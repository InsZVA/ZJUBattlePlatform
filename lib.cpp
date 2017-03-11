#include "stdafx.h"
#include "lib.h"

#define ADAPTER_KEY (L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}")
#define NETWORK_KEY (L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}")
#define TUNTAP_COMPONENT_ID (L"tap0901")
#define CTL_CODE(device_type, function, method, access) ((device_type << 16) | (access << 14) | (function << 2) | method)
#define TAP_CONTROL_CODE(request, method) (CTL_CODE(34, request, method, 0))
#define TAP_IOCTL_CONFIG_TUN TAP_CONTROL_CODE(10, 0)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE(5, 0)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, 0)

/**
* read the device item's "ComponentId" SZ & "DriverDesc" SZ
* @private
*/
static int readKeyInfo(HKEY hKey, LPWSTR subKeyName, std::wstring& netCfgInstanceId) {
	HKEY k;
	if (LONG result = RegOpenKeyEx(hKey, subKeyName, NULL, KEY_READ, &k) != ERROR_SUCCESS) return result;
	DWORD len = 64;
	DWORD type;
	BYTE *data = new BYTE[len];
	Defer defer([&data, &k](){
		delete data;
		RegCloseKey(k);
	});
redo0:
	LONG result = RegQueryValueEx(k, L"ComponentId", NULL, &type, data, &len);
	switch (result) {
	case ERROR_SUCCESS:
		if (!(type == REG_SZ || type == REG_EXPAND_SZ))
			return -1;
		if (lstrcmpW((const wchar_t*)(data), TUNTAP_COMPONENT_ID) != 0)
			return -1;
		break;
	case ERROR_MORE_DATA:
		delete data;
		data = new BYTE[++len];
		goto redo0;
	default:
		return result;
	}
redo1:
	result = RegQueryValueEx(k, L"NetCfgInstanceId", NULL, &type, data, &len);
	switch (result) {
	case ERROR_SUCCESS:
		if (type == REG_SZ || type == REG_EXPAND_SZ)
			netCfgInstanceId = (wchar_t*)data;
		break;
	case ERROR_MORE_DATA:
		delete data;
		data = new BYTE[++len];
		goto redo1;
	default:
		return result;
	}
	return ERROR_SUCCESS;
}

/**
 * get the tuntap device info
 * @public
 * @return ERROR_SUCCESS if ok, -1 else
 */
int getTuntapInfo(std::wstring& netCfgInstanceId) {
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
		return -1;
	DWORD subKeyCount = 0, maxSubKeyLen = 0, valueCount = 0, maxValueNameLen = 0, maxValueLen = 0;
	if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeyCount, &maxSubKeyLen, NULL, &valueCount, &maxValueNameLen, &maxValueLen, NULL, NULL) != ERROR_SUCCESS)
		return -1;

	wchar_t *buf = new wchar_t[maxSubKeyLen + 1];
	Defer defer([&buf, &hKey](){
		delete buf; 
		RegCloseKey(hKey);
	});

	DWORD cName = maxSubKeyLen + 1;
	LONG result;
	for (unsigned int i = 0; i < subKeyCount; i++) {
		result = RegEnumKeyEx(hKey, i, buf, &cName, NULL, NULL, NULL, NULL);
		switch (result) {
		case ERROR_MORE_DATA:
			delete buf;
			buf = new wchar_t[++cName];
			i--;
			continue;
		case ERROR_SUCCESS:
			break;
		case ERROR_NO_MORE_ITEMS:
			break;
		default:
			return result;
		}
		if (readKeyInfo(hKey, buf, netCfgInstanceId) == ERROR_SUCCESS)
			return ERROR_SUCCESS;
	}
	return -1;
}

// return HANDLE if ok, INVALID_HANDLE_VALUE else
HANDLE openTuntap(std::wstring netCfgInstanceId, BYTE addr[4], BYTE network[4], BYTE mask[4], bool tunmode) {
	std::wstring path = L"\\\\.\\Global\\" + netCfgInstanceId + L".tap";
	HANDLE f = CreateFile(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
	if (f == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
	BYTE* config = new BYTE[12];
	Defer defer([&config, &f](){
		delete config;
	});
	memcpy(config, addr, 4);
	memcpy(config + 4, network, 4);
	memcpy(config + 8, mask, 4);
	DWORD returnLen;
	if (tunmode)
		if (DeviceIoControl(f, (tunmode?TAP_IOCTL_CONFIG_TUN:TAP_IOCTL_CONFIG_POINT_TO_POINT), config, (tunmode?12:8), config, (tunmode?12:8), &returnLen, NULL) == 0) {
			if (GetLastError() == ERROR_IO_PENDING) {
				//TODO:
			}
			else {
				return INVALID_HANDLE_VALUE;
			}
		}
	config[0] = 0x01; config[1] = 0x00;	config[2] = 0x00; config[3] = 0x00;
	if (DeviceIoControl(f, TAP_IOCTL_SET_MEDIA_STATUS, config, 4, config, 4, &returnLen, NULL) == 0) {
		if (GetLastError() == ERROR_IO_PENDING) {
			//TODO:
		}
		else {
			return INVALID_HANDLE_VALUE;
		}
	}
	return f;
}

std::string ws2s(std::wstring ws)
{
	const wchar_t* Source = ws.c_str();
	size_t size = 2 * ws.size() + 1;
	char* Dest = new char[size];
	memset(Dest, 0, size);
	size_t len = 0;
	wcstombs_s(&len, Dest, size, Source, size);
	//wcstombs_s(&len, Dest, size, Source, size);  
	std::string result = Dest;
	delete Dest;

	return result;
}

// return id if ok, INFINATE else
DWORD getTuntapIfId(std::wstring& netCfgInstanceId) {
	ULONG ifIndex;
	std::wstring adapterName = L"\\DEVICE\\TCPIP_" + netCfgInstanceId;
	LONG result;
	if ((result = GetAdapterIndex((LPWSTR)adapterName.c_str(), &ifIndex)) == NO_ERROR)
		return ifIndex;
	return INFINITE;
}

// return NO_ERROR if ok, -1 else
int getNetworkName(std::wstring& netCfgInstanceId, std::wstring& networkName) {
	HKEY k;
	std::wstring path = NETWORK_KEY;
	path += L"\\" + netCfgInstanceId + L"\\Connection";
	if (LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), NULL, KEY_READ, &k) != ERROR_SUCCESS) return result;
	DWORD len = 64;
	DWORD type;
	BYTE *data = new BYTE[len];
	Defer defer([data, k](){
		delete data;
		RegCloseKey(k);
	});
redo0:
	LONG result = RegQueryValueEx(k, L"Name", NULL, &type, data, &len);
	switch (result) {
	case ERROR_SUCCESS:
		if (!(type == REG_SZ || type == REG_EXPAND_SZ))
			return -1;
		networkName = (wchar_t*)data;
		break;
	case ERROR_MORE_DATA:
		delete data;
		data = new BYTE[++len];
		goto redo0;
	default:
		return result;
	}
	return -1;
}

// return NO_ERROR if ok
int setTuntapIp(std::wstring& networkName, std::wstring ip, std::wstring mask, std::wstring gateway) {
	std::wstring cmdLine = L" interface ip set address name=\"" + networkName + L"\" source=static addr=" + ip + L" mask=" + mask;
	if (gateway != L"") cmdLine += L" gateway=" + gateway;
	cmdLine += L" gwmetric=0";
	HINSTANCE instance = ShellExecute(NULL, L"runas", L"netsh.exe", cmdLine.c_str(), L"c:\\windows\\system32", SW_HIDE);
	if (instance <= HINSTANCE(32)) return -1;
	WaitForSingleObject(instance, INFINITE);
	return 0;
}

void readTuntap(HANDLE hFile, HANDLE exitEvent, std::function<bool(std::string data)> readHandler, std::function<void(DWORD)> errorHandler) {
	OVERLAPPED ol = { 0 };
	HANDLE hEvent;
	hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent == NULL) {
		if (errorHandler != nullptr) errorHandler(GetLastError());
		return;
	}
	ol.hEvent = hEvent;
	BYTE buff[1500];
	DWORD read;
	DWORD errNo;
	HANDLE handles[2] = { ol.hEvent, exitEvent };
	for (;;) {
		if (ReadFile(hFile, buff, 1500, &read, &ol) != FALSE) {
			if (!readHandler(std::string((char*)buff, read))) break;
		}
		else if ((errNo = GetLastError()) == ERROR_IO_PENDING) {
			switch (WaitForMultipleObjects(2, handles, false, INFINITE)) {
			case WAIT_OBJECT_0:
				if (!readHandler(std::string((char*)buff, ol.InternalHigh))) break;
				break;
			case WAIT_OBJECT_0 + 1:
				return;
			}
		}
		else {
			if (errorHandler != nullptr)
				errorHandler(errNo);
			break;
		}
	}
	CloseHandle(ol.hEvent);
}

int prepareWriteTuntap(OVERLAPPED& ol) {
	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent == NULL) {
		return -1;
	}
	ol.hEvent = hEvent;
	return NO_ERROR;
}

// return NO_ERROR if ok, error code else
int writeTuntap(HANDLE hFile, OVERLAPPED& ol, void* p, int length, DWORD& done) {
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock(mutex);
	DWORD errNo;
	if (WriteFile(hFile, p, length, &done, &ol) != FALSE) {
		ol.Offset += length;
		return NO_ERROR;
	}
	else if ((errNo = GetLastError()) == ERROR_IO_PENDING) {
		WaitForSingleObject(ol.hEvent, INFINITE);
		done = ol.InternalHigh;
		ol.Offset += length;
		return NO_ERROR;
	}
	else return errNo;
}

void tuntapCleanup(HANDLE hFile, OVERLAPPED& ol) {
	CloseHandle(ol.hEvent);
	CloseHandle(hFile);
}

static std::vector<MIB_IPFORWARD_ROW2> backup;

// ipformat: AA.BB.CC.DD: 0xDDCCBBAA
// delete all others
DWORD setIpForwardTable(DWORD network, DWORD mask, DWORD gateway, DWORD metric, DWORD ifIndex) {
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
	DWORD tempMask = mask;
	while (tempMask) {
		tempMask >>= 1;
		prefixLength++;
	}
	for (i = 0; i < pIpForwardTable->NumEntries; i++) {
		if (pIpForwardTable->Table[i].DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr == network && 
			pIpForwardTable->Table[i].DestinationPrefix.PrefixLength == prefixLength && pIpForwardTable->Table[i].InterfaceIndex != ifIndex) {
			backup.push_back(pIpForwardTable->Table[i]); //Backup: TODO avoid repeatly backup
			dwStatus = DeleteIpForwardEntry2(&pIpForwardTable->Table[i]);
			return setIpForwardTable(network, mask, gateway, metric, ifIndex);
		}
	}
	return -1;
}

void protectIpRouteTableThread(std::function<void()> callback, HANDLE exitEvent) {
	OVERLAPPED ol = { 0 };
	HANDLE handle;
	ol.hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	HANDLE waited[2] = { ol.hEvent, exitEvent };
	Defer defer([handle, ol](){
		// Resore ip table route
		for (auto row : backup) {
			CreateIpForwardEntry2(&row);
		}
		CloseHandle(ol.hEvent);
		//CloseHandle(handle);
	});
	for (;;) {
		NotifyRouteChange(&handle, &ol);
		switch (WaitForMultipleObjects(2, waited, false, INFINITE)) {
		case WAIT_OBJECT_0:
			callback();
			break;
		case WAIT_OBJECT_0 + 1:
			return;
		}
	}
}

int getTuntapMac(DWORD ifIndex, BYTE(&mac)[6]) {
	// TODO: optimize by cache the table
	PMIB_IF_TABLE2 pIfTable = NULL;
	if (GetIfTable2(&pIfTable) != NO_ERROR) return -1;
	Defer defer3([&pIfTable](){FreeMibTable(pIfTable); });
	for (int i = 0; i < pIfTable->NumEntries; i++) {
		if (pIfTable->Table[i].InterfaceIndex == ifIndex) {
			memcpy(&mac, pIfTable->Table[i].PhysicalAddress, 6);
			return 0;
		}
	}
	return -1;
}

EthernetIIPacket::EthernetIIPacket() {
	memset(this->dstMac, 0, 6);
	memset(this->srcMac, 0, 6);
}

EthernetIIPacket::EthernetIIPacket(const char* data, int length):EthernetIIPacket() {
	Parse(data, length);
}

EthernetIIPacket::EthernetIIPacket(std::string& data):EthernetIIPacket() {
	Parse(data);
}

bool EthernetIIPacket::Parse(std::string& data) {
	return Parse(data.c_str(), data.size());
}

bool EthernetIIPacket::Parse(const char* raw, int length) {
	if (length < 14) return false;
	memcpy(this->srcMac, raw + 6, 6);
	memcpy(this->dstMac, raw, 6);
	this->protocol = Protocol(ntohs(*(unsigned short*)(&raw[12])));
	this->userDataLen = length < 1514 ? length - 14 : 1500;
	memcpy(this->userData, raw + 14, this->userDataLen);
	return true;
}

bool EthernetIIPacket::Encode(char* buff, int* buffsize) {
	int need = this->userDataLen + 14;
	if (*buffsize < need) { *buffsize = need; return false; }
	memcpy(buff, this->dstMac, 6);
	memcpy(buff + 6, this->srcMac, 6);
	USHORT protocol = htons(*(unsigned short*)(&this->protocol));
	memcpy(buff + 12, &protocol, 2);
	memcpy(buff + 14, this->userData, this->userDataLen);
	return true;
}

IPv4Packet::IPv4Packet() {
	memset(this->srcIp, 0, 4);
	memset(this->dstIp, 0, 4);
}

IPv4Packet::IPv4Packet(std::string& data):IPv4Packet() {
	Parse(data);
}

IPv4Packet::IPv4Packet(const char* raw, int length):IPv4Packet() {
	Parse(raw, length);
}

bool IPv4Packet::Parse(std::string& data) {
	return Parse(data.c_str(), data.size());
}

bool IPv4Packet::Parse(const char* raw, int length) {
	if (length < 20) return false;
	this->protocol = Protocol((BYTE)(raw[9]));
	memcpy(this->srcIp, raw + 12, 4);
	memcpy(this->dstIp, raw + 16, 4);
	this->userDataLen = length < 1500 ? length - 20 : 1480;
	memcpy(this->userData, raw + 20, this->userDataLen);
	return true;
}

IPv4ARPPacket::IPv4ARPPacket() {
	memset(this->senderIpAddress, 0, 4);
	memset(this->senderMac, 0, 6);
	memset(this->targetIpAddress, 0, 4);
	memset(this->targetMac, 0, 6);
}

IPv4ARPPacket::IPv4ARPPacket(std::string& data) :IPv4ARPPacket(){
	Parse(data);
}

IPv4ARPPacket::IPv4ARPPacket(const char* data, int length) : IPv4ARPPacket(){
	Parse(data, length);
}

bool IPv4ARPPacket::Parse(std::string& data) {
	return Parse(data.c_str(), data.size());
}

bool IPv4ARPPacket::Parse(const char* data, int length) {
	if (length < 28) return false;
	this->opCode = data[7];
	memcpy(this->senderMac, data + 8, 6);
	memcpy(this->senderIpAddress, data + 14, 4);
	memcpy(this->targetMac, data + 18, 6);
	memcpy(this->targetIpAddress, data + 24, 4);
	return true;
}

bool IPv4ARPPacket::Encode(char* buff, int* buffsize) {
	BYTE header[] = { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00 };
	if (*buffsize < 28) {
		*buffsize = 28;
		return false;
	}
	memcpy(buff, header, 7);
	buff[7] = this->opCode;
	memcpy(buff + 8, this->senderMac, 6);
	memcpy(buff + 14, this->senderIpAddress, 4);
	memcpy(buff + 18, this->targetMac, 6);
	memcpy(buff + 24, this->targetIpAddress, 4);
	return true;
}