
#include <iostream>
#include "api/Swifty.hpp"
#include "pch.h"
#include "resource.h"
#include <filesystem>
#include "mem.h"
#include <fstream>
#include <Windows.h>
#include <tlhelp32.h>
#include <thread>
#include <filesystem> 
#include "Discord.h"
#include <urlmon.h>
#include"Memx.h"
#include "gui.h"

#include"Settings.h"

#include <thread>
#include "main.h"
#include <Windows.h>"
#include "imgui\imgui.h"
#include "mem.h"


#include <Windows.h>
#include "auth.hpp"
#include <string>
#include "skStr.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;

std::string name = "Mustafa Bypass"; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = "6fT4gDrJi8"; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = "ba0803ca95f691bf2fbf3374281e8c00727ee2a03e083fbcc32cb6d48acba6b0"; // app secret, the blurred text on licenses tab and other tabs
std::string version = "1.0"; // leave alone unless you've changed version on website
std::string url = "https://keyauth.win/api/1.1/"; // change if you're self-hosting
std::string sslPin = "ssl pin key (optional)"; // don't change unless you intend to pin public certificate key. you can get here in the "Pin SHA256" field https://www.ssllabs.com/ssltest/analyze.html?d=keyauth.win&latest. If you do this you need to be aware of when SSL key expires so you can update it


api KeyAuthApp(name, ownerid, secret, version, url, sslPin);




#pragma comment(lib, "urlmon.lib")

Discord* g_Discord;
using namespace std;

int progress_func(void* ptr, double TotalToDownload, double NowDownloaded,
	double TotalToUpload, double NowUploaded)
{
	// ensure that the file to be downloaded is not empty
	// because that would cause a division by zero error later on
	if (TotalToDownload <= 0.0) {
		return 0;
	}

	// how wide you want the progress meter to be
	int totaldotz = 40;
	double fractiondownloaded = NowDownloaded / TotalToDownload;
	// part of the progressmeter that's already "full"
	int dotz = (int)round(fractiondownloaded * totaldotz);

	// create the "meter"
	int ii = 0;
	//printf("%3.0f%% [", fractiondownloaded * 100);
	// part  that's full already
	for (; ii < dotz; ii++) {
		//printf("-");
	}
	for (; ii < totaldotz; ii++) {
		//printf(" ");
	}
	fflush(stdout);
	return 0;
}

class DownloadProgress : public IBindStatusCallback {
public:
	HRESULT __stdcall QueryInterface(const IID&, void**) {
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef(void) {
		return 1;
	}
	ULONG STDMETHODCALLTYPE Release(void) {
		return 1;
	}
	HRESULT STDMETHODCALLTYPE OnStartBinding(DWORD dwReserved, IBinding* pib) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE GetPriority(LONG* pnPriority) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE OnLowResource(DWORD reserved) {
		return S_OK;
	}
	virtual HRESULT STDMETHODCALLTYPE OnStopBinding(HRESULT hresult, LPCWSTR szError) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE GetBindInfo(DWORD* grfBINDF, BINDINFO* pbindinfo) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC* pformatetc, STGMEDIUM* pstgmed) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE OnObjectAvailable(REFIID riid, IUnknown* punk) {
		return E_NOTIMPL;
	}

	virtual HRESULT __stdcall OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText)
	{
		progress_func(0, ulProgressMax, ulProgress, 0, 0);

		wcout << endl;
		return S_OK;
	}
};


std::string tm_to_readable_time(tm ctx) {
	char buffer[25];

	strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

	return std::string(buffer);
}





string readFile(string location)
{
	string myText;
	ifstream MyReadFile(location);
	while (getline(MyReadFile, myText)) {
		cout << myText;
	}
	MyReadFile.close();
	return myText;
}
void writeToFile(string filepath, string credentials)
{
	ofstream MyFile(filepath);
	MyFile << credentials;
	MyFile.close();
}

inline bool FileExist(const std::string& name) {
	if (FILE* file = fopen(name.c_str(), "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

typedef struct _MEMORY_REGION {
	DWORD_PTR dwBaseAddr;
	DWORD_PTR dwMemorySize;
}MEMORY_REGION;

HANDLE ProcessHandle;
DWORD pid;

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);


typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);


void resume(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtResumeProcess");

	pfnNtResumeProcess(processHandle);
	CloseHandle(processHandle);
}

DWORD dGet(DWORD base) {
	DWORD val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
float fGet(DWORD base) {
	float val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
int iGet(DWORD base) {
	int val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
int iwrit(long int addr, float value) {
	int val;
	WriteProcessMemory(ProcessHandle, (void*)(addr), &value, sizeof(value), NULL);
	//pwrite64(handle, &value, 4, addr);
	return val;
}

bool WriteMemory(long addr, SIZE_T siz, DWORD write) {
	WriteProcessMemory(ProcessHandle, (void*)addr, &write, siz, NULL);
	return true;
}

bool replaced(long addr, BYTE write) {
	WriteProcessMemory(ProcessHandle, (void*)addr, &write, 1, NULL);
	return true;
}

bool patcher(long addr, BYTE write[], SIZE_T sizee) {
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (void*)addr, sizee, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (void*)addr, write, sizee, NULL);
	VirtualProtectEx(phandle, (void*)addr, sizee, OldProtect, NULL);
	return true;
}
void suspend(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtSuspendProcess");

	pfnNtSuspendProcess(processHandle);
	CloseHandle(processHandle);
}

HANDLE processHandle;

template <typename T>
T ReadMemoryEx(DWORD BaseAddress, HANDLE phandle)
{
	T Buffer;
	ReadProcessMemory(phandle, (LPCVOID)BaseAddress, &Buffer, sizeof(Buffer), nullptr);

	return Buffer;
}

void WriteUE4Float(DWORD offset, float replace, DWORD pidd, DWORD ue4Header, HANDLE phandle)
{


	DWORD oldprotect;
	VirtualProtectEx(phandle, (LPVOID)(ue4Header + offset), sizeof(float), PAGE_EXECUTE_READWRITE, &oldprotect);
	WriteProcessMemory(phandle, (LPVOID)(ue4Header + offset), &replace, sizeof(float), NULL);
	VirtualProtectEx(phandle, (LPVOID)(ue4Header + offset), sizeof(float), PAGE_READONLY, &oldprotect);
}
//DWORD UE4 = ReadMemoryEx<int>(0xE0C3260);
//DWORD TERSAFE = ReadMemoryEx<int>(0xE0C1220);


template<typename T>
T read(uintptr_t ptrAddress)
{
	T val = T();
	ReadProcessMemory(ProcessHandle, (void*)ptrAddress, &val, sizeof(T), NULL);
	return val;
}


template<typename T>
T read(uintptr_t ptrAddress, T val)
{
	ReadProcessMemory(ProcessHandle, (void*)ptrAddress, &val, sizeof(val), NULL);
	return val;
}


template<typename T>
bool write(uintptr_t ptrAddress, LPVOID value)
{
	return WriteProcessMemory(ProcessHandle, (LPVOID)ptrAddress, &value, sizeof(T), NULL);
}


std::string exec(const char* cmd)
{
	char buffer[128]; std::string result = "";
	FILE* pipe = _popen(cmd, "r");
	if (!pipe)
		throw std::runtime_error("popen() failed!");
	try {
		while (fgets(buffer, sizeof buffer, pipe) != NULL)
		{
			result += buffer;
		}
	}
	catch (...)
	{
		_pclose(pipe);
		throw;
	}
	_pclose(pipe);
	return result;
}


std::string removeSpaces(std::string str)
{
	str.erase(remove(str.begin(), str.end(), ' '), str.end());
	return str;
}




int MemFind(BYTE* buffer, int dwBufferSize, BYTE* bstr, DWORD dwStrLen)
{
	if (dwBufferSize < 0)
	{
		return -1;
	}
	DWORD  i, j;
	for (i = 0; i < dwBufferSize; i++)
	{
		for (j = 0; j < dwStrLen; j++)
		{
			if (buffer[i + j] != bstr[j] && bstr[j] != '?')
				break;
		}
		if (j == dwStrLen)
			return i;
	}
	return -1;
}

int SundaySearch(BYTE* bStartAddr, int dwSize, BYTE* bSearchData, DWORD dwSearchSize)
{
	if (dwSize < 0)
	{
		return -1;
	}
	int iIndex[256] = { 0 };
	int i, j;
	DWORD k;

	for (i = 0; i < 256; i++)
	{
		iIndex[i] = -1;
	}

	j = 0;
	for (i = dwSearchSize - 1; i >= 0; i--)
	{
		if (iIndex[bSearchData[i]] == -1)
		{
			iIndex[bSearchData[i]] = dwSearchSize - i;
			if (++j == 256)
				break;
		}
	}
	i = 0;
	BOOL bFind = FALSE;
	//j=dwSize-dwSearchSize+1;
	j = dwSize - dwSearchSize + 1;
	while (i < j)
	{
		for (k = 0; k < dwSearchSize; k++)
		{
			if (bStartAddr[i + k] != bSearchData[k])
				break;
		}
		if (k == dwSearchSize)
		{
			//ret=bStartAddr+i;
			bFind = TRUE;
			break;
		}
		if (i + dwSearchSize >= dwSize)
		{

			return -1;
		}
		k = iIndex[bStartAddr[i + dwSearchSize]];
		if (k == -1)
			i = i + dwSearchSize + 1;
		else
			i = i + k;
	}
	if (bFind)
	{
		return i;
	}
	else
		return -1;

}


BOOL MemSearch(BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	BYTE* pCurrMemoryData = NULL;
	MEMORY_BASIC_INFORMATION	mbi;
	std::vector<MEMORY_REGION> m_vMemoryRegion;
	mbi.RegionSize = 0x1000;
	DWORD dwAddress = dwStartAddr;



	while (VirtualQueryEx(phandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < dwEndAddr) && ((dwAddress + mbi.RegionSize) > dwAddress))
	{

		if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && (mbi.Protect != PAGE_NOACCESS) && ((mbi.AllocationProtect & PAGE_NOCACHE) != PAGE_NOCACHE))
		{

			MEMORY_REGION mData = { 0 };
			mData.dwBaseAddr = (DWORD_PTR)mbi.BaseAddress;
			mData.dwMemorySize = mbi.RegionSize;
			m_vMemoryRegion.push_back(mData);

		}
		dwAddress = (DWORD)mbi.BaseAddress + mbi.RegionSize;

	}


	std::vector<MEMORY_REGION>::iterator it;
	for (it = m_vMemoryRegion.begin(); it != m_vMemoryRegion.end(); it++)
	{
		MEMORY_REGION mData = *it;


		DWORD_PTR dwNumberOfBytesRead = 0;

		if (bIsCurrProcess)
		{
			pCurrMemoryData = (BYTE*)mData.dwBaseAddr;
			dwNumberOfBytesRead = mData.dwMemorySize;
		}
		else
		{

			pCurrMemoryData = new BYTE[mData.dwMemorySize];
			ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
			ReadProcessMemory(phandle, (LPCVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);

			if ((int)dwNumberOfBytesRead <= 0)
			{
				delete[] pCurrMemoryData;
				continue;
			}
		}
		if (iSearchMode == 0)
		{
			DWORD_PTR dwOffset = 0;
			int iOffset = MemFind(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}
		}
		else if (iSearchMode == 1)
		{

			DWORD_PTR dwOffset = 0;
			int iOffset = SundaySearch(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);

			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}

		}

		if (!bIsCurrProcess && (pCurrMemoryData != NULL))
		{
			delete[] pCurrMemoryData;
			pCurrMemoryData = NULL;
		}

	}
	return TRUE;
}

int SINGLEAOBSCAN6969(BYTE BypaRep[], SIZE_T size)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);
	if (Bypassdo.size() == 1)
	{
		//MessageBoxA(0, "wtf", 0, 0);
	}
	if (Bypassdo.size() == 2)
	{
		//MessageBoxA(0, "ok here we go", 0, 0);
	}
	if (Bypassdo.size() != 0) {
		return Bypassdo[1];
	}
}
//int SINGLEAOBSCAN69691(BYTE BypaRep[], SIZE_T size)
//{
//	DWORD pid = getAowProcId22();
//	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
//	std::vector<DWORD_PTR> Bypassdo;
//	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);
//	if (Bypassdo.size() == 1)
//	{
//		//MessageBoxA(0, "wtf", 0, 0);
//	}
//	if (Bypassdo.size() == 2)
//	{
//		//MessageBoxA(0, "ok here we go", 0, 0);
//	}
//	if (Bypassdo.size() != 0) {
//		return Bypassdo[1];
//	}
//}

int SINGLEAOBSCAN(BYTE BypaRep[], SIZE_T size)
{
	if (Settings::Smartgaga)
	{

		DWORD pid = getProcId2();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		//MemSearch(BypaRep, size, 0x70000000, 0x90000000, false, 0, Bypassdo);
		MemSearch(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}
	}
	else if (Settings::Gameloop)
	{
		DWORD pid = getProcId2();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		//MemSearch(BypaRep, size, 0x40000000, 0x60000000, false, 0, Bypassdo);
		MemSearch(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}

	}
}




int SINGLEAOBSCAN2(BYTE BypaRep[], SIZE_T size)//this is for tersafe
{

	if (Settings::Smartgaga)//For smartgaga
	{
		int pid = getGagaProcId();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		MemSearch(BypaRep, size, 0x04000000, 0x05000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}

	}
	else if (Settings::Gameloop)//change
	{
		DWORD pid = getProcId2();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		MemSearch(BypaRep, size, 0x40000000, 0x41000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}

	}

}
int Keraftonaddr()
{
	int libtersafeheader = 0;
	BYTE tersafehead[] = { 0x4B, 0x00, 0x52, 0x00, 0x41, 0x00, 0x46, 0x00, 0x54, 0x00, 0x4F, 0x00, 0x4E };
	libtersafeheader = SINGLEAOBSCAN6969(tersafehead, sizeof(tersafehead));
	return libtersafeheader;
}

int gettersafeheader()
{
	int libtersafeheader = 0;
	//old //BYTE tersafehead[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x08,0xBD,0x3C };
	BYTE tersafehead[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xC0,0xDA,0x3D,0x00,0x00,0x02,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x1D,0x00,0x1C,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00 };
		libtersafeheader = SINGLEAOBSCAN2(tersafehead, sizeof(tersafehead));
	return libtersafeheader;
}
int getGCloud()
{
	int libtprtheader = 0;
	BYTE GCloud[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xE4,0xA0,0x37,0x00,0x00,0x00,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x18,0x00,0x17,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x34,0x01,0x00,0x00,0x34,0x01,0x00,0x00,0x34,0x01,0x00,0x00,0x13,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	libtprtheader = SINGLEAOBSCAN2(GCloud, sizeof(GCloud));
	return libtprtheader;
}

int getue4header()
{
	unsigned long  libue4header = 0;
	//BYTE ue4head[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x24,0x66,0x67 };
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x26, 0x8A, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 };
	libue4header = SINGLEAOBSCAN(ue4head, sizeof(ue4head));
	return libue4header;
}


int getue4headerVn()
{
	unsigned long  libue4header = 0;
	//BYTE ue4head[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x24,0x66,0x67 };
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x56, 0x8A, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	libue4header = SINGLEAOBSCAN(ue4head, sizeof(ue4head));
	return libue4header;
}

//int gettrptheader()
//{
//	int libtprtheader = 0;
//	BYTE tprt[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xA0,0x50,0x07,0x00,0x00,0x02,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x1B,0x00,0x1A,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70 };
//	libtprtheader = SINGLEAOBSCAN2(tprt, sizeof(tprt));
//	return libtprtheader;
//}
int gettrptheader()
{
	int libtprtheader = 0;
	BYTE tprt[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xA0,0x50,0x07,0x00,0x00,0x02,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x1B,0x00,0x1A,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x07,0x07,0x00,0x70,0x07,0x07,0x00,0x05,0x00,0x00,0x00 };
	libtprtheader = SINGLEAOBSCAN2(tprt, sizeof(tprt));
	return libtprtheader;
}
int getlibTDataMaster()
{
	int libTDataMaste = 0;
	BYTE masterhead[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0xF0, 0x25, 0x00, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x08, 0x00, 0x28, 0x00, 0x1C, 0x00, 0x1B, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00 };
	libTDataMaste = SINGLEAOBSCAN2(masterhead, sizeof(masterhead));
	return libTDataMaste;
}

int getUEend()
{

	unsigned long libue4end = 0;
	BYTE ue4end[] = { 0xB0, 0xAF, 0x00, 0x80, 0xFF, 0x00, 0xE3, 0x80, 0x00, 0x03, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0xA8, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x48, 0x02, 0x00 };
	libue4end = SINGLEAOBSCAN(ue4end, sizeof(ue4end));
	return libue4end;

}

int getTERSend()
{
	int libuTERSend = 0;
	BYTE TERSend[] = { 0xFF, 0x00, 0xBC, 0x00, 0x03, 0x34, 0x30, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x01, 0x5C, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
	libuTERSend = SINGLEAOBSCAN2(TERSend, sizeof(TERSend));
	return libuTERSend;
}


void offsetsearch2(int offset, BYTE write[], SIZE_T size, int header)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	int addr = header + offset;
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (BYTE*)addr, write, size, NULL);
	VirtualProtectEx(phandle, (BYTE*)addr, size, OldProtect, NULL);

}


void AOBREP(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}
	}
	else
	{

	}
}
DWORD MyGetProcessId(LPCTSTR ProcessName) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) { // must call this first
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap); // close handle on failure
	return 0;
}
void AOBREP2(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers)
{
	DWORD pid = MyGetProcessId("AndroidEmulatorEx.exe");
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}
	}
	else
	{

	}
}

void findAndReplaceAll(std::string& data, std::string toSearch, std::string replaceStr)
{
	size_t pos = data.find(toSearch);
	while (pos != std::string::npos)
	{
		data.replace(pos, toSearch.size(), replaceStr);
		pos = data.find(toSearch, pos + replaceStr.size());
	}
}

void cmdd(string text)
{
	string prim = "/c " + text;
	const char* primm = prim.c_str();
	ShellExecute(0, "open", "cmd.exe", (LPCSTR)primm, 0, SW_HIDE);
}

void startEmulator(int choices)
{
	if (choices == 1)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\Tencent\\MobileGamePC\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname + "UI";
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallPath", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\AndroidEmulatorEx.exe";
					//findAndReplaceAll(aedir, "C:", "\"C:");
					aedir.insert(0, 1, '"');
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					string aedirx = aedir + " -vm 100";
					//std::cout << aedirx << std::endl;
					cmdd(aedirx.c_str());
				}
				RegCloseKey(key1);
			}
		}
		else
		{
			cout << "Your Choice Of Emulator Isn't Installed" << endl;
		}
		RegCloseKey(key);
	}
	if (choices == 2)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\Tencent\\MobileGamePC\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname + "UI";
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallPath", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\AndroidEmulatorEn.exe";//AndroidEmulatorEn
					aedir.insert(0, 1, '"');
					string aedirx = aedir + " x";
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					//std::cout << aedir << std::endl;
					cmdd(aedir.c_str());
				}
				RegCloseKey(key1);
			}

		}
		else
		{
			cout << "Your Choice Of Emulator Isn't Installed" << endl;
		}
		RegCloseKey(key);
	}
	if (choices == 3)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\SmartGaGa\\ProjectTitan\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname;
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallDir", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\Engine\\ProjectTitan.exe";
					aedir.insert(0, 1, '"');
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					//std::cout << aedir << std::endl;
					cmdd(aedir.c_str());
				}
				RegCloseKey(key1);
			}

		}
		else
		{
			cout << "Your Choice Of Emulator Isn't Installed" << endl;
		}
		RegCloseKey(key);
	}

}




string  gen_random(int len) {
	string s;
	static const char alphanum[] =
		"0123456789";
	for (int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return s;
}

string  gen_random2(int len) {
	string s;
	static const char alphanum[] =
		"0123456789"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return s;
}
std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}
void fixemuid()
{
	std::ofstream outfile("C:\\device_id.txt");
	outfile << " <?xml version='1.0' encoding='utf-8' standalone='yes' ?> \n<map>\n    <string name=\"install\">dc33f8d6-a036-45d3-ae00-d13eb6cb46b9</string>\n    <string name=\"uuid\">" + gen_random2(32) + "</string>\n    <string name = \"random\"></string>\n</map>" << std::endl;
	outfile.close();
	string did = "adb shell settings put secure android_id " + gen_random(31);

}

int Bypass(std::string command)
{
	command.insert(0, "/C ");

	SHELLEXECUTEINFOA ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = "cmd.exe";
	ShExecInfo.lpParameters = command.c_str();
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;

	if (ShellExecuteExA(&ShExecInfo) == FALSE)
		return -1;

	WaitForSingleObject(ShExecInfo.hProcess, INFINITE);

	DWORD rv;
	GetExitCodeProcess(ShExecInfo.hProcess, &rv);
	CloseHandle(ShExecInfo.hProcess);

	return rv;
}
void writememx()
{
	DWORD pid = getProcId2();




	Memory memory;
	if (!memory.AttachProcess(pid))
	{
		MessageBoxA(0, "error attache proccess.", "Error", MB_ICONERROR);
		return;
	}

entrypoint:

	std::string dri = "sc create BUSHIDO binPath= \"C:\\hookdrv.sys\" start=demand type=filesys > nul 2> nul";
	Bypass(dri.c_str());
	Bypass("sc start BUSHIDO > nul 2> nul");
	//DWORD pid = getGagaProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

	short c = 10;
	DWORD libtersafeheader = gettersafeheader();
	DWORD GCloud = getGCloud();
	DWORD Tprt = gettrptheader();

	DWORD trptheader = gettrptheader();
	unsigned long libue4header = getue4header();

	if (libtersafeheader == 0 || libue4header == 0)
	{


		std::cout << "try again" << std::endl;


		goto entrypoint;
	}

	else
	{
		
		int UE4Base,  ANOGSBase; 
		int PTRBase;
		int TDMBase;
		int GCLBase;
		int UE4Base1;
		int IGBase;
		int GCLOUDCORE;
		int ANORTBase;
		int CSBase;
		UE4Base = ReadMemoryEx<int>(0xE0C3868, phandle);
		ANOGSBase = ReadMemoryEx<int>(0xE0C1228,phandle);
		PTRBase = ReadMemoryEx<int>(0xE0C0928,phandle);
		TDMBase = ReadMemoryEx<int>(0xE0C0F28,phandle);
		GCLBase = ReadMemoryEx<int>(0xE0C10A8,phandle);
		IGBase = ReadMemoryEx <int>(0xE0C1828,phandle);
		GCLOUDCORE = ReadMemoryEx<int>(0xE0C0DA8, phandle);
		ANORTBase = ReadMemoryEx<int>(0xE0C07A8, phandle);
		CSBase = ReadMemoryEx<int>(0xE0C3268, phandle);


		//CString str1;// to print header agous
		//str1.Format(_T("%d"), ANOGSBase);
		//string s = to_string(ANOGSBase);
		//MessageBoxA(0, "fuck ANOGSBase ", s.c_str(), 0);
		//SAFE 2.0 O


//suspend(pid);
Sleep(3000);

		
		//put your offest here 
//memory.WriteBytes(ANOGSBase + 0x443536, new BYTE[]{ 0x00, 0x00, 0x00, 0x00 }, true);


	//resume(pid);

		CloseHandle(memory.ProcessHandle);


		

		Settings::bypassDone = true;

		



	}

}
void writememx2()
{
	DWORD pid = getProcId2();




	Memory memory;
	if (!memory.AttachProcess(pid))
	{
		MessageBoxA(0, "error attache proccess.", "Error", MB_ICONERROR);
		return;
	}

entrypoint:

	std::string dri = "sc create BUSHIDO binPath= \"C:\\hookdrv.sys\" start=demand type=filesys > nul 2> nul";
	Bypass(dri.c_str());
	Bypass("sc start BUSHIDO > nul 2> nul");
	//DWORD pid = getGagaProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

	short c = 10;
	DWORD libtersafeheader = gettersafeheader();
	DWORD trptheader = gettrptheader();
	unsigned long libue4header = getue4header();
	unsigned long libue4header2 = getue4headerVn();

	if (libtersafeheader == 0 || libue4header == 0)
	{


		std::cout << "try again" << std::endl;


		goto entrypoint;
	}

	else
	{



		memory.WriteBytes(libtersafeheader + 0x342C0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libtersafeheader + 0x371FA, new BYTE[]{ 0x59 }, true);
		memory.WriteBytes(libtersafeheader + 0x37214, new BYTE[]{ 0x59,0x00 }, true);
		memory.WriteBytes(libtersafeheader + 0x3722A, new BYTE[]{ 0x59,0x00,0x59,0x00,0x59,0x00 }, true);
		memory.WriteBytes(libtersafeheader + 0x39665D, new BYTE[]{ 0x30,0x0A,0x06 }, true);
		memory.WriteBytes(libtersafeheader + 0x396791, new BYTE[]{ 0x05,0x0A,0x06 }, true);

		memory.WriteBytes(libtersafeheader + 0x342C0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libtersafeheader + 0x37214, new BYTE[]{ 0x59,0x00 }, true);
		memory.WriteBytes(libtersafeheader + 0x3722A, new BYTE[]{ 0x59,0x00 }, true);
		memory.WriteBytes(libtersafeheader + 0x37EC4, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libtersafeheader + 0x846A0, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libtersafeheader + 0x85088, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libtersafeheader + 0xEC7F8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libtersafeheader + 0x289070, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libtersafeheader + 0x2890A8, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libtersafeheader + 0x29A138, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libtersafeheader + 0x29BD78, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libtersafeheader + 0x29BDCC, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		//memory.WriteBytes(libtersafeheader + 0x39665D, new BYTE[]{ 0xC0,0x44,0x05 }, true);
		//memory.WriteBytes(libtersafeheader + 0x396791, new BYTE[]{ 0x95,0x44,0x05 }, true);
		//memory.WriteBytes(libtersafeheader + 0x3B6D04, new BYTE[]{ 0x00 }, true);
		//


		Sleep(4000);


		memory.WriteBytes(libue4header2 + 0x342C0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x371EB, new BYTE[]{ 0x00,0x59,0x00,0x59,0x00,0x59,0x00,0x59,0x00,0x59,0x00,0x59 }, true);
		memory.WriteBytes(libue4header2 + 0x371F8, new BYTE[]{ 0x59 }, true);
		memory.WriteBytes(libue4header2 + 0x37204, new BYTE[]{ 0x59,0x00,0x59,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x3720A, new BYTE[]{ 0x59,0x00,0x59,0x00,0x59,0x00,0x59,0x00,0x59 }, true);
		memory.WriteBytes(libue4header2 + 0x37214, new BYTE[]{ 0x59,0x00,0x59,0x00,0x59 }, true);
		memory.WriteBytes(libue4header2 + 0x3721A, new BYTE[]{ 0x59,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x37224, new BYTE[]{ 0x59,0x00,0x59,0x00,0x59,0x00,0x59,0x00,0x59,0x00,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x37238, new BYTE[]{ 0x59 }, true);
		memory.WriteBytes(libue4header2 + 0x37244, new BYTE[]{ 0x59,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x37EC4, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x5EBAE, new BYTE[]{ 0x78,0x47,0xC0 }, true);
		memory.WriteBytes(libue4header2 + 0x5EBB2, new BYTE[]{ 0xAE,0xEB,0xA5,0x40,0x00,0x00,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x5EBCC, new BYTE[]{ 0x78,0x47,0xC0 }, true);
		memory.WriteBytes(libue4header2 + 0x5EBD0, new BYTE[]{ 0xCC,0xEB,0xA5,0x40,0x00,0x00,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x5EDBE, new BYTE[]{ 0xA8,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x5EDC1, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x5FB0A, new BYTE[]{ 0xA8,0x00,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x696C0, new BYTE[]{ 0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x846A0, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x85088, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0xA0018, new BYTE[]{ 0xF8,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0024, new BYTE[]{ 0xF7,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA02E8, new BYTE[]{ 0x48,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA034C, new BYTE[]{ 0x31,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA039C, new BYTE[]{ 0x1F,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA03B4, new BYTE[]{ 0x1B,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA03C4, new BYTE[]{ 0x19,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA03D8, new BYTE[]{ 0x16,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA03EC, new BYTE[]{ 0x13,0xBB,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA051C, new BYTE[]{ 0xC9,0xBA,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0524, new BYTE[]{ 0xC9,0xBA,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0664, new BYTE[]{ 0x7B,0xBA,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0754, new BYTE[]{ 0x41,0xBA,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0904, new BYTE[]{ 0xD7,0xB9,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA09BC, new BYTE[]{ 0xAB,0xB9,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0B58, new BYTE[]{ 0x46,0xB9,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0BB8, new BYTE[]{ 0x30,0xB9,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0C40, new BYTE[]{ 0x10,0xB9,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0CB0, new BYTE[]{ 0xF6,0xB8,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0E60, new BYTE[]{ 0x8C,0xB8,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0EAC, new BYTE[]{ 0x7B,0xB8,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA0FE8, new BYTE[]{ 0x2E,0xB8,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1034, new BYTE[]{ 0x1D,0xB8,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1170, new BYTE[]{ 0xD0,0xB7,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA11BC, new BYTE[]{ 0xBF,0xB7,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1350, new BYTE[]{ 0x5C,0xB7,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA14AC, new BYTE[]{ 0x07,0xB7,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA14D4, new BYTE[]{ 0xFF,0xB6,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1544, new BYTE[]{ 0xE5,0xB6,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA158C, new BYTE[]{ 0xD5,0xB6,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA15D4, new BYTE[]{ 0xC5,0xB6,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA15DC, new BYTE[]{ 0xC5,0xB6,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1660, new BYTE[]{ 0xA6,0xB6,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA191C, new BYTE[]{ 0xF9,0xB5,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1944, new BYTE[]{ 0xF1,0xB5,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA19B4, new BYTE[]{ 0xD7,0xB5,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA19FC, new BYTE[]{ 0xC7,0xB5,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1A44, new BYTE[]{ 0xB7,0xB5,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1A4C, new BYTE[]{ 0xB7,0xB5,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1AD0, new BYTE[]{ 0x98,0xB5,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1D7C, new BYTE[]{ 0xEF,0xB4,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1DA4, new BYTE[]{ 0xE7,0xB4,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1E14, new BYTE[]{ 0xCD,0xB4,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1E5C, new BYTE[]{ 0xBD,0xB4,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xA1EA4, new BYTE[]{ 0xAD,0xB4,0x0D,0xEA }, true);
		memory.WriteBytes(libue4header2 + 0xDF204, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x04,0xF2,0xAD,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xDF238, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x38,0xF2,0xAD,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xDF26C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x6C,0xF2,0xAD,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xDF4FD, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0xFD,0xF4,0xAD,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xE041D, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1D,0x04,0xAE,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xE414D, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x4D,0x41,0xAE,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xE431D, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1D,0x43,0xAE,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xE6BD5, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0xD5,0x6B,0xAE,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xE836D, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x6D,0x83,0xAE,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0xEC7F8, new BYTE[]{ 0x78,0x78,0x47,0xC0,0x46,0x04,0xF0,0xF9,0xC7,0xAE,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x17756D, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x6D,0x75,0xB7,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x177689, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x89,0x76,0xB7,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x17796C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0x6C,0x79,0xB7,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x17CA9D, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x9D,0xCA,0xB7,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x17DB14, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x14,0xDB,0xB7,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x289070, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x2890A8, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x29A138, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x29BD78, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x29BDCC, new BYTE[]{ 0x00,0x20,0x70,0x47 }, true);
		memory.WriteBytes(libue4header2 + 0x2A54F4, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2A54FC, new BYTE[]{ 0xF4,0x54,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A566C, new BYTE[]{ 0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2A5670, new BYTE[]{ 0x1E }, true);
		memory.WriteBytes(libue4header2 + 0x2A5672, new BYTE[]{ 0x2F,0xE1,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2A5676, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x76,0x56,0xCA,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2A5738, new BYTE[]{ 0x78,0x47,0xC0,0x46 }, true);
		memory.WriteBytes(libue4header2 + 0x2A573D, new BYTE[]{ 0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2A5740, new BYTE[]{ 0x38,0x57,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A5794, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0x94,0x57,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A6670, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2A6678, new BYTE[]{ 0x70,0x66,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A6780, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2A6788, new BYTE[]{ 0x80,0x67,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A70CC, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xCC,0x70,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A71B4, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xB4,0x71,0xCA,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2A75E0, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xE0,0x75,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A8008, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0x08,0x80,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2A8154, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2A8156, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x56,0x81,0xCA,0x40,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2A94EC, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2A94F4, new BYTE[]{ 0xEC,0x94,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AA8D0, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xD0,0xA8,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AA9C8, new BYTE[]{ 0x78 }, true);
		memory.WriteBytes(libue4header2 + 0x2AA9CA, new BYTE[]{ 0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xC8,0xA9,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AABEC, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2AABF4, new BYTE[]{ 0xEC,0xAB,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AAC40, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2AAC48, new BYTE[]{ 0x40,0xAC,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AAC9C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2AACA4, new BYTE[]{ 0x9C,0xAC,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AACC1, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2ABA50, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2ABA58, new BYTE[]{ 0x50,0xBA,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2ABB04, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2ABB08, new BYTE[]{ 0x1E }, true);
		memory.WriteBytes(libue4header2 + 0x2ABB0A, new BYTE[]{ 0x2F,0xE1,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2ABB10, new BYTE[]{ 0x1E }, true);
		memory.WriteBytes(libue4header2 + 0x2ABB12, new BYTE[]{ 0x2F,0xE1,0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2AE484, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2AE48C, new BYTE[]{ 0x84,0xE4,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AE8F4, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xF4,0xE8,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AF1AC, new BYTE[]{ 0x78 }, true);
		memory.WriteBytes(libue4header2 + 0x2AF1AE, new BYTE[]{ 0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xAC,0xF1,0xCA,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2AF384, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x84,0xF3,0xCA,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2AF50C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x0C,0xF5,0xCA,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2B7AA0, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2B7AA8, new BYTE[]{ 0xA0,0x7A,0xCB,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2B80A8, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2B80B0, new BYTE[]{ 0xA8,0x80,0xCB,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2B9AB0, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2B9AB8, new BYTE[]{ 0xB0,0x9A,0xCB,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2B9C94, new BYTE[]{ 0x78,0x47,0xC0,0x46 }, true);
		memory.WriteBytes(libue4header2 + 0x2B9C99, new BYTE[]{ 0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2B9C9C, new BYTE[]{ 0x94,0x9C,0xCB,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2BDD9C, new BYTE[]{ 0x78,0x47,0xC0,0x46 }, true);
		memory.WriteBytes(libue4header2 + 0x2BDDA1, new BYTE[]{ 0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2BDDA4, new BYTE[]{ 0x9C,0xDD,0xCB,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2C137C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0x7C,0x13,0xCC,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2C3F9C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x9C,0x3F,0xCC,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2C4CC0, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2C4CC8, new BYTE[]{ 0xC0,0x4C,0xCC,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2C4F1C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2C4F24, new BYTE[]{ 0x1C,0x4F,0xCC,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2C8144, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0x44,0x81,0xCC,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2C8268, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2C8270, new BYTE[]{ 0x68,0x82,0xCC,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2C8278, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0x78,0x82,0xCC,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2CBA88, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0x88,0xBA,0xCC,0x40,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2CEC20, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2CEC22, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x22,0xEC,0xCC,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2CEC2D, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x2D09D4, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xD4,0x09,0xCD,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2D0FA4, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F,0xE5,0xA4,0x0F,0xCD,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2D1B4C, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2D1B54, new BYTE[]{ 0x4C,0x1B,0xCD,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2D6840, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2D6848, new BYTE[]{ 0x40,0x68,0xCD,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2D7200, new BYTE[]{ 0x78 }, true);
		memory.WriteBytes(libue4header2 + 0x2D7202, new BYTE[]{ 0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2D7208, new BYTE[]{ 0x00,0x72,0xCD,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x2D7BA8, new BYTE[]{ 0x78,0x47,0xC0,0x46,0x04,0xF0,0x1F }, true);
		memory.WriteBytes(libue4header2 + 0x2D7BB0, new BYTE[]{ 0xA8,0x7B,0xCD,0x40 }, true);
		memory.WriteBytes(libue4header2 + 0x39665D, new BYTE[]{ 0x60,0x28,0x05 }, true);
		memory.WriteBytes(libue4header2 + 0x396791, new BYTE[]{ 0x35,0x28,0x05 }, true);






		memory.WriteBytes(libue4header2 + 0xEDE950, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF3C22C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF3F149, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0xF3F1E0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF47C48, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF4961C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF4A4BC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF4EEF0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF51AF0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF59E22, new BYTE[]{ 0x31 }, true);
		memory.WriteBytes(libue4header2 + 0xF59E26, new BYTE[]{ 0x35 }, true);
		memory.WriteBytes(libue4header2 + 0xF59E28, new BYTE[]{ 0x32 }, true);
		memory.WriteBytes(libue4header2 + 0xF59E2E, new BYTE[]{ 0x30 }, true);
		memory.WriteBytes(libue4header2 + 0xF6AAE4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xF9B330, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xFB3F30, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xFB4D68, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xFB5CC4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0xFD00B4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x100AD40, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x106BF1C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x106C874, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x10FE4DC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1174C28, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11B9230, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11B93D0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11B9D24, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11B9E30, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11B9F88, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BA314, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BA420, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BA780, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BAA84, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BAE30, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BB014, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BB608, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11BB9D4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11DA3BC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11E08B0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11E2F24, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11ED324, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11EDAFC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11EDE3C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11EE07C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11EECD4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11EF124, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11EFA9C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F0160, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F102C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F1778, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F6DE0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F6FF0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F7880, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F8A50, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F8F90, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F9130, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F92B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F9478, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F949C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F9674, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11F9D14, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11FA1D0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11FA704, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11FA90C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11FACF8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11FADBC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11FAE6C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x11FB300, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x120197E, new BYTE[]{ 0xE0 }, true);
		memory.WriteBytes(libue4header2 + 0x1201980, new BYTE[]{ 0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1201990, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1201B7C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1201C10, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1201D80, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1201DC4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1201F14, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x120288C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x12029AC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1203148, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1203228, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1203C20, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1203DB0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1204220, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x120D920, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1228EA0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1279094, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x127916C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x127D4F0, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x12FBF8C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x12FD874, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x13304A4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1341CA8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1349B18, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x134ACA4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x134B37C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1412434, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x14DBB54, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x14DBE2C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x14DE9F0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x14DEAE0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x14DEBB8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153372C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153471C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153492C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1534AA8, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1534EA0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153503C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1535430, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15357D8, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1535C80, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1536BEC, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1536FC8, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15373B8, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1537AF4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153A398, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153A9F0, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153AD54, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153B3C8, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153BD24, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153BEC0, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153C038, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153CE04, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153D5AC, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153D6D0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153E024, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153EFC4, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153F3A4, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153F648, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153F8C0, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153FB10, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153FCE8, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x153FDF4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1541894, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1541D70, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1542CFC, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x155E50C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x155F404, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x155F6A8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x155FC44, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x155FDE4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1560550, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x156076C, new BYTE[]{ 0x00,0x00,0x00,0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x1561BAC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15621C8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15622E4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1562748, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15632C0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x156348C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1564498, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x156468C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1564B9C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1565140, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x156541C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15657B4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1565CAC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1565F88, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1566228, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15663B0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1580BE8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1580EE0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15B2518, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15B2EB8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x15BAF9C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x161AC6C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x161B4C8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16223D0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1625140, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16259E4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1625AB4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1625E3C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x162E16C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x162F470, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16309A0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1630DE4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1642578, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x164762C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1647E6C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x164806C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1648C28, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x164C020, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x164C3FC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x164D014, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x165A72C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16687A8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x166DF70, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1676F2C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16B53FC, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16B7610, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16BB38C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16C2720, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16C75F0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16C79EC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16C8074, new BYTE[]{ 0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16C8618, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16C8AC4, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16D1578, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16D23A8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16EABE0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16F7C80, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16F9C28, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16F9C40, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16F9E78, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16F9EEC, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16FB0D4, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x16FE900, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1704098, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x170E654, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1723840, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1723E41, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1728FF4, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x174A5B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x174AA2C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x174AEC8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x174B54C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x174B858, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x174BB38, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x174C0A8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1809E0C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x18376E4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1838590, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x183959C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x183A0E4, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x183A254, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x183A2B0, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1843754, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x18439FC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1848F0C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x18490B0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x184A9C4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x184B6F0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x18D7524, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x18F1F98, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x195C2D4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19B4F60, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19B96C4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19B98B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19B9C74, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19DA6E8, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19DC100, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19DFC00, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19E9DB0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19ED2C0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x19F3280, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A07EC0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A08430, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A09638, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A09C60, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A0B1B0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A0B568, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A0BEC8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1198C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A12980, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A12EE0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A13500, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1374C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A13DF4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A140F8, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x1A140FA, new BYTE[]{ 0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A149C1, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1A14C0C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A15B10, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A17F58, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1838C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A18960, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A19144, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A192A8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A19918, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1998C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A19B68, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A19BB0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1A18C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1A260, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1A858, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1A930, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1AA50, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1B118, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1B358, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1B52C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1B6D4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1B78C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A1B844, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A204B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A205DC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A20754, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A20FE8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21264, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21494, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A216D4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A219B0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21AD4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21B60, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21BCC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21D68, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21DD0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A21ED8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A220CC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A22601, new BYTE[]{ 0x00,0xE0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1A22634, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A22880, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A22B14, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A22C50, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A22D90, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A22EE0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A231D8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2343C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A23760, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A23860, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A238B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2396C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A23C04, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A23D0C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A23E00, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A24528, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A24550, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A247EC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A248D8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A24B00, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2569C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A257B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A25864, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A25B24, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A25E64, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A25F74, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2E6B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2F2BC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2F768, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2FF58, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A2FF8C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A30070, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A30538, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A308F0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A30B68, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A31110, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A311CC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A312BC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A31465, new BYTE[]{ 0x00,0xE0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1A315C8, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x1A315CA, new BYTE[]{ 0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A3168C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A31794, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A31C94, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A31DDC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A31EF8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A320D4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A32170, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A323F0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A330C4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A33618, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A33AAC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A33C34, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A33E1C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A33FD0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A3435C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A34535, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1A3458C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A34808, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A34C3C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A34DB4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A34F2C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A350D0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A35390, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A35678, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A35C98, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A35D30, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A369D8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A36A80, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A36AE4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A36B64, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A36C1C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A36F38, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A374D8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A37BE0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A37DE4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A3B5B8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A3D1F8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A3D33D, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1A3D3F4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1A3D4F1, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1AFC701, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1AFC82C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1AFC988, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1AFCB28, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1AFCFB0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1AFD0DC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1AFDEC8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1AFE234, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B003C0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B00998, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B00CCC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B01124, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B014C4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B01A24, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B01DB4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B01E9C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B0213C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B021C1, new BYTE[]{ 0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libue4header2 + 0x1B02214, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B024D0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B0259C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B02938, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B02E4C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B03160, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B03570, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B03C24, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B0402C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B0483C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B05A1C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B060E8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B06E68, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B072A4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B082D0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B08818, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B089E0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1B19760, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1C1EE48, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D62828, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D62BFC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D62CB8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D63410, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D636CC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D641A0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D64C0C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D65BB8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D65CA8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1D99D70, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1DE0780, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1DE09F0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1DE107C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1DE17CC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1DF5B40, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1E420E0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1E44891, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x1E44894, new BYTE[]{ 0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1E4CC08, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1E4D4A0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1E4DAF0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0A298, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0A544, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0AA98, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0AB44, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0AF6C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0B578, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0BA9C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x1F0CF7C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x208F8DC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x20B6948, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x20F7A78, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x213A66C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2178E5C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2179CC4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2179DF0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2179EA0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x22BC26C, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x255A1E4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x25E4BD0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x261D1E2, new BYTE[]{ 0xA0 }, true);
		memory.WriteBytes(libue4header2 + 0x261D1E4, new BYTE[]{ 0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x261D4DC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26374B0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2661E34, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2663AB4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2663B2C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2663C3C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2678B10, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x269CDC4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26D9334, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26D9484, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26D95F0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26D982C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26D989C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26D99E4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26DB560, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26DCE80, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26DD264, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26EA924, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26EB340, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26EB758, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26EB948, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x26F6478, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2708EF4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x27096F8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2709E70, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x270A8B0, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x276A2E8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x277F84C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x27903B8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x28132A4, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2813474, new BYTE[]{ 0x64,0x09,0xA0,0x00,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2896018, new BYTE[]{ 0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x2898848, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x289884B, new BYTE[]{ 0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x28CBAF4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x28CBC2C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x28CD22C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x28D513C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x295138C, new BYTE[]{ 0x00 }, true);
		memory.WriteBytes(libue4header2 + 0x295138E, new BYTE[]{ 0xE0 }, true);
		memory.WriteBytes(libue4header2 + 0x2F5B124, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x30D1D20, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3741CE0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8AE0C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8B658, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8B7A8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8B8F8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8BA48, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8BCBC, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8BF6C, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8C308, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8CCA4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8D010, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3A8DA14, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3B0DD48, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3C148B8, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3C14D78, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3C15070, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3D19D70, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3D1A318, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E464B4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E46B90, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E76FE8, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		//memory.WriteBytes(libue4header2 + 0x3E826D6, new BYTE[]{ 0x82 }, true);
		memory.WriteBytes(libue4header2 + 0x3E903B4, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E90DFC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E91010, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E91820, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E91A6C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E922A4, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E92A20, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E92E70, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E931FC, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E9359C, new BYTE[]{ 0x00,0x00,0xE0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		memory.WriteBytes(libue4header2 + 0x3E93D94, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F,0xE1 }, true);
		CloseHandle(memory.ProcessHandle);




		Settings::bypassDone = true;

		//}



	}

}

int nsystem(std::string command)
{
	command.insert(0, "/C ");

	SHELLEXECUTEINFOA ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = "cmd.exe";
	ShExecInfo.lpParameters = command.c_str();
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;

	if (ShellExecuteExA(&ShExecInfo) == FALSE)
		return -1;

	WaitForSingleObject(ShExecInfo.hProcess, INFINITE);

	DWORD rv;
	GetExitCodeProcess(ShExecInfo.hProcess, &rv);
	CloseHandle(ShExecInfo.hProcess);

	return rv;
}
void Stealth()
{
	HWND Stealth;
	AllocConsole();
	Stealth = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(Stealth, 0);
}
void DownloadFile22(string DownloadLink, string SaveLocation)
{
	string initialargument = "curl.exe --url " + DownloadLink + " --output " + SaveLocation;
	const char* argument = initialargument.c_str();
	system("@echo off");
	system(argument);
}
void PatchGameloopAntiCheat2()
{

	//Sleep(8000);
	//Memory memory;
	//DWORD pid = MyGetProcessId("AndroidEmulatorEx.exe");

	//if (!memory.AttachProcess(pid))
	//{
	//	MessageBoxA(0, "error attache proccess.", "Error", MB_ICONERROR);
	//	return;
	//}

	//memory.ReplacePattern(0x00000000, 0x7fffffff, new BYTE[]{ 0xE9,0xE7,0x2D,0x2B,0x00,0x8D,0x64 }, new BYTE[]{ 0xC2,0x08,0x00,0x2B,0x00,0x8D,0x64 }, true);
	Stealth();
	if (std::filesystem::exists("C:\Windows\ConsoleApplication2.exe"))
	{

	}
	else
	{
		DownloadFile22("https://cdn.discordapp.com/attachments/740652161435959327/977937598444093530/ConsoleApplication2.exe", "C:\\Windows\\ConsoleApplication2.exe");
	}
	system("C:\\Windows\\ConsoleApplication2.exe");
}

std::string executee(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}
int isSubstring(string s1, string s2)
{
	int M = s1.length();
	int N = s2.length();
	for (int i = 0; i <= N - M; i++) {
		int j;
		for (j = 0; j < M; j++)
			if (s2[i + j] != s1[j])
				break;

		if (j == M)
			return i;
	}

	return -1;
}
void startGame(int choice, int mode)
{

	DownloadFile22("https://cdn.discordapp.com/attachments/740652161435959327/987118550416240730/libanogs.so", "C:\libanogs.so");


	//fixemuid();
	if (mode == 1)
	{
		if (Settings::Smartgaga) {
			startEmulator(3);
		}
		if (Settings::Gameloop = true) {

			startEmulator(1);
		}
		Stealth();

	gamepointer:
		bool gg = false;
		system("adb kill-server");
		string output = executee("adb devices");
		string substring = "emulator";
		int checks = isSubstring(substring, output);

		if (checks != -1)
		{
			gg = true;

			system("TASKKILL /F /IM cmd.exe 2>NULL");
			//print(c_xor("\nEmulator Has Already Been Loaded"), 9);

		}
		if (!gg) {
			goto gamepointer;
		}
		//Sleep(3000);
		if (Settings::Gameloop) {
			//PatchGameloopAntiCheat2();
			//Sleep(4000);
			Settings::Gameloopkill = true;
		}
		if (Settings::Smartgaga || Settings::Gameloop && Settings::Gameloopkill) {
			if (choice == 1)
			{



				Settings::choices = 1;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.tencent.ig");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.tencent.ig-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.tencent.ig-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.tencent.ig-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.tencent.ig-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");
				nsystem("adb -s emulator-5554 shell am start com.tencent.ig/com.epicgames.ue4.SplashActivity filter");
				//Sleep(3000);
				//nsystem("adb push C:\libanogs.so /data/user/0/com.tencent.ig/lib/libanogs.so");
				//nsystem("adb rm /data/user/0/com.tencent.ig/lib/libanogs.so");


				//	Sleep(6000);
			gamepointer3:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer3;
				}

				Sleep(5000);

				std::thread sex(writememx);
				sex.detach();
				/*writememx();*/



			}
			if (choice == 2)
			{

				Settings::choices = 2;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.pubg.krmobile");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.pubg.krmobile-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.pubg.krmobile-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.pubg.krmobile-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.pubg.krmobile-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.pubg.krmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");

				nsystem("adb -s emulator-5554 shell am start com.pubg.krmobile/com.epicgames.ue4.SplashActivity filter");
				//	Sleep(6000);
			gamepointer5:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer5;
				}

				Sleep(5000);

				std::thread sex(writememx);
				sex.detach();
				/*writememx();*/

			}



			if (choice == 3)
			{


				Settings::choices = 3;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.rekoo.pubgm");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.rekoo.pubgm-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.rekoo.pubgm-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.rekoo.pubgm-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.rekoo.pubgm-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.rekoo.pubgm/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");

				nsystem("adb -s emulator-5554 shell am start com.rekoo.pubgm/com.epicgames.ue4.SplashActivity filter");
				//	Sleep(6000);
			gamepointer7:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer7;
				}

				Sleep(5000);

				std::thread sex(writememx);
				sex.detach();
				/*writememx();*/
			}
			if (choice == 4)
			{

				Settings::choices = 4;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.vng.pubgmobile");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.vng.pubgmobile-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.vng.pubgmobile-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.vng.pubgmobile-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.vng.pubgmobile-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.vng.pubgmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");

				nsystem("adb -s emulator-5554 shell am start com.vng.pubgmobile/com.epicgames.ue4.SplashActivity filter");
				//	Sleep(6000);
			gamepointer6:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer6;
				}

				Sleep(5000);

				std::thread sex(writememx2);
				sex.detach();
				/*writememx();*/
			}
			if (choice == 5)
			{

			}
			Settings::Gameloopkill = false;
		}
	}

}


//
//int isSubstring(string s1, string s2)
//{
//	int M = s1.length();
//	int N = s2.length();
//	for (int i = 0; i <= N - M; i++) {
//		int j;
//		for (j = 0; j < M; j++)
//			if (s2[i + j] != s1[j])
//				break;
//
//		if (j == M)
//			return i;
//	}
//
//	return -1;
//}


void WriteResToDisk(std::string PathFile, LPCSTR File_WITHARG)
{
	HRSRC myResource = ::FindResource(NULL, (LPCSTR)File_WITHARG, RT_RCDATA);
	unsigned int myResourceSize = ::SizeofResource(NULL, myResource);
	HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
	void* pMyExecutable = ::LockResource(myResourceData);
	std::ofstream f(PathFile, std::ios::out | std::ios::binary);
	f.write((char*)pMyExecutable, myResourceSize);
	f.close();
}

void mainmenu(int emu, int game)
{

	cmdd(("sc create xander binPath=\"C:\\hookdrv.sys\" type=filesys"));
	cmdd(("sc start xander"));
	if (!FileExist("C:\\hookdrv.sys"))
	{
		WriteResToDisk("C:\\hookdrv.sys", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA1));
	}
	if (!FileExist("C:\\Windows\\adb.exe"))
	{
		WriteResToDisk("C:\\Windows\\adb.exe", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA2));
	}
	if (!FileExist("C:\\Windows\\AdbWinApi.dll"))
	{
		WriteResToDisk("C:\\Windows\\AdbWinApi.dll", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA3));
	}


	int mode;
	int timer;


	//startEmulator(emu);
	//Sleep(6000);
	startGame(Settings::choices, 1);

	//gamepointer3:

	nsystem(("sc stop xander"));
	nsystem(("sc delete xander"));
	nsystem(("sc stop hookdrv"));
	nsystem(("sc delete hookdrv"));
	nsystem(("sc stop Xtreme"));
	nsystem(("sc delete Xtreme"));
	Sleep(-1);
}

void mainmenuaur1()
{

	if (Settings::Smartgaga)
		startEmulator(3);
	if (Settings::Gameloop)
		startEmulator(1);


}
void mainmenuaur()
{

	if (Settings::Smartgaga)
		mainmenu(3, Settings::choices);
	if (Settings::Gameloop)
		mainmenu(1, Settings::choices);

}
void safeExit()
{

	exit(0);

}
auto GetExpiry = [=]()
{
	time_t time = strtol(KeyAuthApp.data.expiry.c_str(), NULL, 10);
	std::tm expiry;
	localtime_s(&expiry, &time);

	time_t ExpiryTime = mktime(&expiry) - std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	int Days = (ExpiryTime) / (24 * 3600); int Hours = (ExpiryTime % (24 * 3600)) / (3600);
	int Minutes = (ExpiryTime % (3600)) / 60; int Seconds = (ExpiryTime) % 60;

	return
		std::to_string(Days) + " Days, " + std::to_string(Hours) + " Hours, " +
		std::to_string(Minutes) + " Minutes, " + std::to_string(Seconds) + " Seconds";
};
std::string GetClipboardText()
{
	if (!OpenClipboard(nullptr))
		exit(0);
	HANDLE hData = GetClipboardData(CF_TEXT);
	if (hData == nullptr)
		exit(0);

	char* pszText = static_cast<char*>(GlobalLock(hData));
	if (pszText == nullptr)
		exit(0);

	std::string text(pszText);
	GlobalUnlock(hData);
	CloseClipboard();

	return text;
}
int __stdcall wWinMain(
	HINSTANCE instance,
	HINSTANCE previousInstance,
	PWSTR arguments,
	int commandShow)
{
	// create gui

	Stealth();

	if (std::filesystem::exists("C:\Windows\Ruda-Bold.ttf"))
	{

	}
	else
	{

		DownloadFile22("https://cdn.discordapp.com/attachments/848989184550502451/981529714441203782/Ruda-Bold.ttf", "C:\Windows\Ruda-Bold.ttf");

	}
	KeyAuthApp.init();


	int option;
	std::string username;
	std::string password;
	std::string key;


	

	//std::string user, email, pass, token;
	//if (FileExist(c_xor("C:\\GG.lic")))
	//{
	//	token = readFile("C:\\GG.lic");
	//	KeyAuthApp.license(token);

	//	if (!KeyAuthApp.data.success) {
	//		token = GetClipboardText();
	//		KeyAuthApp.license(token);
	//		writeToFile(c_xor("C:\\GG.lic"), token);
	//	}
	//
	//}

	//else {
	//	token = GetClipboardText();
	//	writeToFile(c_xor("C:\\GG.lic"), token);
	//	KeyAuthApp.license(token);
	//}
	//writeToFile(c_xor("C:\\GG22.lic"), GetExpiry());

	//
	//KeyAuthApp.license(token);
	//if (!KeyAuthApp.data.success)
	//{
	//	std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
	//	MessageBoxA(0, "Invalid Key", 0, 0);
	//	Sleep(1500);
	//	exit(0);
	//}
	if (!FileExist("C:\hookdrv.sys"))
	{
		WriteResToDisk("C:\hookdrv.sys", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA1));
	}
	if (!FileExist("C:\Windows\adb.exe"))
	{
		WriteResToDisk("C:\Windows\adb.exe", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA2));
	}
	if (!FileExist("C:\Windows\AdbWinApi.dll"))
	{
		WriteResToDisk("C:\Windows\AdbWinApi.dll", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA3));
	}
	g_Discord->Initialize();
	g_Discord->Update();
	gui::CreateHWindow("SNAKE BYPASS");
	gui::CreateDevice();
	gui::CreateImGui();

	while (gui::exit)
	{
		gui::BeginRender();
		gui::Render();
		gui::EndRender();

		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}

	// destroy gui
	gui::DestroyImGui();
	gui::DestroyDevice();
	gui::DestroyHWindow();

	return EXIT_SUCCESS;
}
