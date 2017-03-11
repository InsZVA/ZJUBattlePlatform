// itest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "lib.h"
#include <iostream>
#include <unordered_map>
#include <fstream>
#include <sstream>
#define LISTEN_PORT 6667

// RawIp -> MappedIP
std::unordered_map<DWORD, DWORD> ipMappingTable;
// MappedIP -> RawIP
std::unordered_map<DWORD, DWORD> rIpMappingTable;
// RawIp -> RawMac
std::unordered_map<DWORD, std::vector<BYTE>> macTable;
// common UDP client
SOCKET udpClient;

BYTE myIp[4] = { 0 }, tuntapMac[6] = { 0 };
HANDLE tuntap;
OVERLAPPED wol;

// get a minimum metric ip of route 0.0.0.0
int getZJUIPAddress(BYTE (&ip)[4]) {
	MIB_IPFORWARD_TABLE2* pIpForwardTable = NULL;
	MIB_IPFORWARD_ROW2* pRow = NULL;
	BOOL bOrder = FALSE;
	DWORD dwStatus = 0;
	unsigned int i;
	dwStatus = GetIpForwardTable2(AF_INET, &pIpForwardTable);
	Defer defer([&pIpForwardTable, &pRow](){
		if (pIpForwardTable)
			FreeMibTable(pIpForwardTable);
	});
	if (dwStatus != ERROR_SUCCESS) return dwStatus;
	DWORD prefixLength = 0;
	DWORD minMetric = INFINITE;
	for (i = 0; i < pIpForwardTable->NumEntries; i++) {
		if (pIpForwardTable->Table[i].DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr == 0 &&
			pIpForwardTable->Table[i].DestinationPrefix.PrefixLength == prefixLength) {
			if (pIpForwardTable->Table[i].Metric < minMetric)
				pRow = &pIpForwardTable->Table[i];
		}
	}
	if (pRow == NULL)
		return -1;
	
	// iterator the ip table
	PMIB_IPADDRTABLE pIpAddrTable = NULL;
	ULONG pdwSize = 0;
	if (GetIpAddrTable(pIpAddrTable, &pdwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
		pIpAddrTable = (PMIB_IPADDRTABLE)(malloc(pdwSize));
		if (GetIpAddrTable(pIpAddrTable, &pdwSize, FALSE) != NO_ERROR) {
			return -1;
		}
	}
	else return -1;
	Defer defer2([&pIpAddrTable](){
		free(pIpAddrTable);
	});
	for (int i = 0; i < pIpAddrTable->dwNumEntries; i++) {
		if (pIpAddrTable->table[i].dwIndex == pRow->InterfaceIndex) {
			*(DWORD*)(&ip[0]) = pIpAddrTable->table[i].dwAddr;
			return 0;
		}
	}
	return -1;
}

void receiver(DWORD ip, HANDLE exitEvent) {
	

	SOCKET listener = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
	sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = ip;
	addr.sin_port = htons(LISTEN_PORT);
	if (bind(listener, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
		return;
	sockaddr_in remoteAddr = { 0 };
	WSAOVERLAPPED ol = { 0 };
	ol.hEvent = WSACreateEvent();
	Defer defer([ol, listener](){
		WSACloseEvent(ol.hEvent);
		closesocket(listener);
	});
	int addrLen = sizeof(sockaddr);
	WSABUF buffer;
	char buf[1472];
	buffer.buf = buf;
	buffer.len = 1472;
	DWORD result, nRecv, flags = 0;
	HANDLE handles[2] = { ol.hEvent, exitEvent };
	char addStr[128];
	EthernetIIPacket eth;
	char sendBuffer[1500];
	DWORD rawIp, mappedIp;
	for (;;) {
		result = WSARecvFrom(listener, &buffer, 1, &nRecv, &flags, (sockaddr*)&remoteAddr, &addrLen, &ol, NULL);
		if (result == NO_ERROR) {
			//std::cout << "Receive From " << inet_ntop(AF_INET, &remoteAddr.sin_addr, addStr, 128) << ":" << nRecv << "Bytes." << std::endl;
			rawIp = remoteAddr.sin_addr.S_un.S_addr;
			mappedIp = ipMappingTable[rawIp];
			if (mappedIp != 0) {
				memcpy(&buffer.buf[12], &mappedIp, 4); // not necessaty
				if (*(DWORD*)(&buffer.buf[16]) != 0xffffffff) {
					DWORD myIpMapped = ipMappingTable[*(DWORD*)(&myIp[0])];
					memcpy(&buffer.buf[16], &myIpMapped, 4); // shoule check mac again?
				}
				auto m = macTable[*(DWORD*)(&myIp[0])];
				for (int i = 0; i < 6; i++) sendBuffer[i] = m[i];
				m = macTable[rawIp];
				for (int i = 0; i < 6; i++) sendBuffer[6+i] = m[i];
				*(unsigned short*)(&sendBuffer[12]) = htons(0x0800); // network order
				memcpy(sendBuffer + 14, buffer.buf, nRecv);
				DWORD done = 0;
				writeTuntap(tuntap, wol, &sendBuffer, nRecv + 14, done);
			}
		}
		else if ((result = WSAGetLastError()) == WSA_IO_PENDING) {
			switch (WaitForMultipleObjects(2, handles, FALSE, INFINITE)) {
			case WAIT_OBJECT_0:
				std::cout << "Receive From " << inet_ntop(AF_INET, &remoteAddr.sin_addr, addStr, 128) << ":" << ol.InternalHigh << "Bytes." << std::endl;
				rawIp = remoteAddr.sin_addr.S_un.S_addr;
				mappedIp = ipMappingTable[rawIp];
				nRecv = ol.InternalHigh;
				if (mappedIp != 0 && nRecv > 20) {
					memcpy(&buffer.buf[12], &mappedIp, 4); // not necessaty
					if (*(DWORD*)(&buffer.buf[16]) != 0xffffffff) {
						DWORD myIpMapped = ipMappingTable[*(DWORD*)(&myIp[0])];
						memcpy(&buffer.buf[16], &myIpMapped, 4); // shoule check mac again?
					}
					auto m = macTable[*(DWORD*)(&myIp[0])];
					for (int i = 0; i < 6; i++) sendBuffer[i] = m[i];
					m = macTable[rawIp];
					for (int i = 0; i < 6; i++) sendBuffer[6 + i] = m[i];
					*(unsigned short*)(&sendBuffer[12]) = htons(0x0800); // network order
					memcpy(sendBuffer + 14, buffer.buf, nRecv);
					DWORD done = 0;
					writeTuntap(tuntap, wol, &sendBuffer, nRecv + 14, done);
				}
				break;
			case WAIT_OBJECT_0 + 1:
				return;
			}
		}
	}
}

bool IPPacketAnalyse(std::string data) {
	BYTE b = data[0];
	BYTE version = b >> 4;
	if (version == 6) return true; // ignore IPv6
	BYTE headSize = b & 0xf;
	for (int i = 12; i < 15; i++) {
		std::wcout << (BYTE)data[i] << L".";
	}
	std::wcout << (BYTE)data[15] << L"->";
	for (int i = 16; i < 19; i++) {
		std::wcout << (BYTE)data[i] << L".";
	}
	std::wcout << (BYTE)data[19] << L"   " << (int)(data.size() - headSize) << L"Bytes" << std::endl;
	return true;
}

void sendUdpData(DWORD dstIp, const char* data, int length) {
	BYTE* ip = (BYTE*)&dstIp;
	//printf("send udp to %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
	sockaddr_in remoteAddr = { 0 };
	remoteAddr.sin_addr.S_un.S_addr = dstIp;
	remoteAddr.sin_port = htons(LISTEN_PORT);
	remoteAddr.sin_family = AF_INET;
	sendto(udpClient, data, length, 0, (sockaddr*)(&remoteAddr), sizeof(remoteAddr));
}

bool IPAnalyseFromEthernet(std::string data) {
	// TODO: optimize using mempool
	EthernetIIPacket* eth = new EthernetIIPacket(data);
	IPv4Packet* ip = NULL;
	BYTE* mac = NULL;
	char* buffer = NULL;
	switch (eth->protocol) {
	case EthernetIIPacket::IPv4:
		ip = new IPv4Packet((const char*)(&eth->userData[0]), eth->userDataLen);
		if (ip->dstIp[3] == 0xff) {
			for (auto src : ipMappingTable) {
				if (src.first != *(DWORD*)(&myIp[0]))
					sendUdpData(src.first, (const char*)eth->userData, eth->userDataLen);
			}
		}
		else {
			DWORD rawIp = rIpMappingTable[*(DWORD*)(&ip->dstIp[0])];
			if (rawIp != 0 && rawIp != *(DWORD*)(&myIp[0])) {
				sendUdpData(rawIp, (const char*)eth->userData, eth->userDataLen);
			}
		}
		delete ip;
		break;
	case EthernetIIPacket::ARP:
		IPv4ARPPacket* arp = new IPv4ARPPacket((const char*)(&eth->userData[0]), eth->userDataLen);
		DWORD dstIp = *(DWORD*)arp->targetIpAddress;
		auto&& dstMac = macTable[rIpMappingTable[dstIp]];
		arp->opCode = 2;
		if (dstMac.size() < 6 || *(DWORD*)arp->senderIpAddress == 0) {
			delete arp;
			break;
		}
		mac = new BYTE[6]{ dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5] };
		buffer = new char[28 + 14]{0};
		memcpy(arp->targetMac, arp->senderMac, 6);
		memcpy(arp->senderMac, mac, 6);
		DWORD tempIp = *(DWORD*)&arp->senderIpAddress;
		*(DWORD*)arp->senderIpAddress = *(DWORD*)arp->targetIpAddress;
		*(DWORD*)arp->targetIpAddress = tempIp;
		int length = 28;
		arp->Encode(buffer + 14, &length);
		*(unsigned short*)(&buffer[12]) = htons(0x0806); // network order
		memcpy(buffer, &arp->senderMac, 6);
		memcpy(buffer + 6, &arp->targetMac, 6); 
		DWORD done = 0;
		writeTuntap(tuntap, wol, buffer, (DWORD)28 + 14, done);
		delete mac;
		delete buffer;
		delete arp;
	}
	delete eth; 
	return true;
}

void initIPMapping() {
	// TODO: Get From Server
	std::ifstream inf("./map.txt", std::ios_base::in);
	if (!inf.is_open()) return;
	int n;
	inf >> n;
	int buf[6];
	BYTE rawIp[4] = { 0 }, mappedIp[4] = { 0 }, mac[6] = { 0 };
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < 4; j++) {
			inf >> std::dec >> buf[j];
			rawIp[j] = buf[j] & 0xff;
		}
		for (int j = 0; j < 4; j++) {
			inf >> std::dec >> buf[j];
			mappedIp[j] = buf[j] & 0xff;
		}
		for (int j = 0; j < 6; j++) {
			inf >> std::hex >> buf[j];
			mac[j] = buf[j] & 0xff;
		}
		ipMappingTable[*(DWORD*)(&rawIp[0])] = *(DWORD*)(&mappedIp[0]);
		rIpMappingTable[*(DWORD*)(&mappedIp[0])] = *(DWORD*)(&rawIp[0]);
		std::vector<BYTE> v;
		v.reserve(6);
		v.resize(6);
		for (int j = 0; j < 6; j++)
			v[j] = mac[j];
		macTable[*(DWORD*)(&rawIp[0])] = v;
	}
	udpClient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	inf.close();
}

int _tmain(int argc, _TCHAR* argv[])
{
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) return -1;
	initIPMapping();
	std::wstring s1;
	getTuntapInfo(s1);
	std::wcout << s1 << std::endl;
	DWORD ifIndex = getTuntapIfId(s1);
	std::wcout << ifIndex << std::endl;
	if (getZJUIPAddress(myIp) == 0 && getTuntapMac(ifIndex, tuntapMac) == 0)
		printf("My ip is: %d.%d.%d.%d\n Tuntap mac is: %X:%X:%X:%X:%X:%X\n", myIp[0], myIp[1], myIp[2], myIp[3],
		tuntapMac[0], tuntapMac[1], tuntapMac[2], tuntapMac[3], tuntapMac[4], tuntapMac[5]);
	else {
		printf("Getting my ip failed.\n");
		return -1;
	}
	std::wstring networkName;
	getNetworkName(s1, networkName);
	std::wcout.imbue(std::locale("chs"));
	std::wcout << networkName << std::endl;
	std::wostringstream os;
	BYTE myIpMapped[4] = { 0 };
	*(DWORD*)(&myIpMapped[0]) = ipMappingTable[*(DWORD*)(&myIp[0])];
	os << std::dec << myIpMapped[0] << L"." << std::dec << myIpMapped[1] << L"." << std::dec << myIpMapped[2] << L"." << std::dec << myIpMapped[3];
	setTuntapIp(networkName, os.str(), L"255.255.255.0", L"");
	BYTE addr[4] = { myIp[0], myIp[1], myIp[2], myIp[3] }, network[4] = { 192, 168, 1, 0 }, mask[4] = { 255, 255, 255, 0 };
	tuntap = openTuntap(s1, addr, network, mask, false);
	Sleep(1000); 
	prepareWriteTuntap(wol);
	setIpForwardTable(0xffffffff, 0xffffffff, 0x0000000, 0, ifIndex);
	HANDLE threadExit = CreateEvent(NULL, NULL, NULL, NULL);
	std::thread tProtect([ifIndex, threadExit](){
		protectIpRouteTableThread([ifIndex, threadExit](){
			setIpForwardTable(0xffffffff, 0xffffffff, 0x0000000, 0, ifIndex);
		}, threadExit);
	});
	std::thread tReadTuntap([threadExit](){
		readTuntap(tuntap, threadExit, IPAnalyseFromEthernet);
	});
	std::thread tListener([threadExit](){
		receiver(*(DWORD*)(&myIp[0]), threadExit);
	});
	getchar();
	SetEvent(threadExit);
	SetEvent(threadExit);
	SetEvent(threadExit);
	tProtect.join();
	tReadTuntap.join();
	tListener.join();
	CloseHandle(wol.hEvent);
	CloseHandle(threadExit);
	CloseHandle(tuntap);
	closesocket(udpClient);
	WSACleanup();
	return 0;
}
