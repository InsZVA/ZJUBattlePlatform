#pragma once
#include <string>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <IPHlpApi.h>
#include <functional>
#include <shellapi.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shell32.lib")

class Defer {
private:
	std::function<void()> func;
public:
	Defer(std::function<void()> func) : func(func){}
	~Defer(){ this->func(); }
};

int getTuntapInfo(std::wstring& netCfgInstanceId);
HANDLE openTuntap(std::wstring netCfgInstanceId, BYTE addr[4], BYTE network[4], BYTE mask[4], bool tunmode = true);
DWORD getTuntapIfId(std::wstring& netCfgInstanceId);
int setTuntapIp(std::wstring& networkName, std::wstring ip, std::wstring mask, std::wstring gateway);
int getNetworkName(std::wstring& netCfgInstanceId, std::wstring& networkName);
void readTuntap(HANDLE hFile, HANDLE exitEvent, std::function<bool(std::string data)> readHandler, std::function<void(DWORD)> errorHandler = nullptr);
int prepareWriteTuntap(OVERLAPPED& ol);
int writeTuntap(HANDLE hFile, OVERLAPPED& ol, void* p, int length, DWORD& done);
void tuntapCleanup(HANDLE hFile, OVERLAPPED& ol);
DWORD setIpForwardTable(DWORD network, DWORD mask, DWORD gateway, DWORD metric, DWORD ifIndex);
void protectIpRouteTableThread(std::function<void()> callback, HANDLE exitEvent);
int getTuntapMac(DWORD ifIndex, BYTE(&mac)[6]);

struct EthernetIIPacket {
public:
	enum Protocol{ Unkown = 0x0000, IPv4 = 0x0800, IPX = 0x8137, ARP = 0x0806 };
	EthernetIIPacket();
	EthernetIIPacket(std::string& data);
	EthernetIIPacket(const char* data, int length);
	bool Parse(std::string& data);
	bool Parse(const char* data, int length);
	bool Encode(char* buff, int* buffsize);
	BYTE srcMac[6];
	BYTE dstMac[6];
	Protocol protocol = Unkown;
	BYTE userData[1500];
	int userDataLen = 0;
};

struct IPv4Packet {
public:
	enum Protocol { Unkown = 0x00, UDP = 0x11 };
	IPv4Packet();
	IPv4Packet(std::string& data);
	IPv4Packet(const char* data, int length);
	bool Parse(std::string& data);
	bool Parse(const char* data, int length);
	BYTE srcIp[4], dstIp[4];
	Protocol protocol = Unkown;
	BYTE userData[1480];
	int userDataLen = 0;
};

struct IPv4ARPPacket {
public:
	// 1: request 2: reply
	BYTE opCode = 1;
	BYTE senderIpAddress[4], targetIpAddress[4], senderMac[6], targetMac[6];
	IPv4ARPPacket();
	IPv4ARPPacket(std::string& data);
	IPv4ARPPacket(const char* data, int length);
	bool Parse(std::string& data);
	bool Parse(const char* data, int length);
	bool Encode(char* buff, int* buffsize);
};