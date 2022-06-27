#include "gui.h"

#include "../imgui/imgui.h"
#include "../imgui/imgui_impl_dx9.h"
#include "../imgui/imgui_impl_win32.h"
#include <Settings.h>
#include <main.h>
#include <thread>



#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>
#include <thread>
#include <iterator>
#include <math.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <atlbase.h>
#include <atlstr.h>
#include <memory.h>
#include <iostream>


#include <filesystem>

#include <fstream>
#include <Windows.h>
#include <tlhelp32.h>
#include <thread>
#include <filesystem> 
#include "main.h"
#include <urlmon.h>
#include"Memx.h"
#include "Settings.h"
using namespace std;
string STATUS = "Welcome to SNAKE PRIVATE BYPASS.";

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
	HWND window,
	UINT message,
	WPARAM wideParameter,
	LPARAM longParameter
);
typedef struct _MEMORY_REGION {
	DWORD_PTR dwBaseAddr;
	DWORD_PTR dwMemorySize;
}MEMORY_REGION;

long __stdcall WindowProcess(
	HWND window,
	UINT message,
	WPARAM wideParameter,
	LPARAM longParameter)
{
	if (ImGui_ImplWin32_WndProcHandler(window, message, wideParameter, longParameter))
		return true;

	switch (message)
	{
	case WM_SIZE: {
		if (gui::device && wideParameter != SIZE_MINIMIZED)
		{
			gui::presentParameters.BackBufferWidth = LOWORD(longParameter);
			gui::presentParameters.BackBufferHeight = HIWORD(longParameter);
			gui::ResetDevice();
		}
	}return 0;

	case WM_SYSCOMMAND: {
		if ((wideParameter & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
			return 0;
	}break;

	case WM_DESTROY: {
		PostQuitMessage(0);
	}return 0;

	case WM_LBUTTONDOWN: {
		gui::position = MAKEPOINTS(longParameter); // set click points
	}return 0;

	case WM_MOUSEMOVE: {
		if (wideParameter == MK_LBUTTON)
		{
			const auto points = MAKEPOINTS(longParameter);
			auto rect = ::RECT{ };

			GetWindowRect(gui::window, &rect);

			rect.left += points.x - gui::position.x;
			rect.top += points.y - gui::position.y;

			if (gui::position.x >= 0 &&
				gui::position.x <= gui::WIDTH &&
				gui::position.y >= 0 && gui::position.y <= 19)
				SetWindowPos(
					gui::window,
					HWND_TOPMOST,
					rect.left,
					rect.top,
					0, 0,
					SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOZORDER
				);
		}

	}return 0;

	}

	return DefWindowProc(window, message, wideParameter, longParameter);
}

void gui::CreateHWindow(const char* windowName) noexcept
{
	windowClass.cbSize = sizeof(WNDCLASSEX);
	windowClass.style = CS_CLASSDC;
	windowClass.lpfnWndProc = WindowProcess;
	windowClass.cbClsExtra = 0;
	windowClass.cbWndExtra = 0;
	windowClass.hInstance = GetModuleHandleA(0);
	windowClass.hIcon = 0;
	windowClass.hCursor = 0;
	windowClass.hbrBackground = 0;
	windowClass.lpszMenuName = 0;
	windowClass.lpszClassName = "class001";
	windowClass.hIconSm = 0;

	RegisterClassEx(&windowClass);

	window = CreateWindowEx(
		0,
		"class001",
		windowName,
		WS_POPUP,
		100,
		100,
		WIDTH,
		HEIGHT,
		0,
		0,
		windowClass.hInstance,
		0
	);

	ShowWindow(window, SW_SHOWDEFAULT);
	UpdateWindow(window);
}

void gui::DestroyHWindow() noexcept
{
	DestroyWindow(window);
	UnregisterClass(windowClass.lpszClassName, windowClass.hInstance);
}

bool gui::CreateDevice() noexcept
{
	d3d = Direct3DCreate9(D3D_SDK_VERSION);

	if (!d3d)
		return false;

	ZeroMemory(&presentParameters, sizeof(presentParameters));

	presentParameters.Windowed = TRUE;
	presentParameters.SwapEffect = D3DSWAPEFFECT_DISCARD;
	presentParameters.BackBufferFormat = D3DFMT_UNKNOWN;
	presentParameters.EnableAutoDepthStencil = TRUE;
	presentParameters.AutoDepthStencilFormat = D3DFMT_D16;
	presentParameters.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

	if (d3d->CreateDevice(
		D3DADAPTER_DEFAULT,
		D3DDEVTYPE_HAL,
		window,
		D3DCREATE_HARDWARE_VERTEXPROCESSING,
		&presentParameters,
		&device) < 0)
		return false;

	return true;
}

void gui::ResetDevice() noexcept
{
	ImGui_ImplDX9_InvalidateDeviceObjects();

	const auto result = device->Reset(&presentParameters);

	if (result == D3DERR_INVALIDCALL)
		IM_ASSERT(0);

	ImGui_ImplDX9_CreateDeviceObjects();

}

void gui::DestroyDevice() noexcept
{
	if (device)
	{
		device->Release();
		device = nullptr;
	}

	if (d3d)
	{
		d3d->Release();
		d3d = nullptr;
	}
}

int Bypassx(std::string command)
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
}int getAowProcId22x()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "AndroidEmulatorEx.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getAowProcIdx()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "aow_exe.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getGagaProcIdx()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "AndroidProcess.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}
void StealthX()
{
	HWND Stealth;
	AllocConsole();
	Stealth = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(Stealth, 0);
}
void DownloadFile(string DownloadLink, string SaveLocation)
{
	string initialargument = "curl.exe --url " + DownloadLink + " --output " + SaveLocation;
	const char* argument = initialargument.c_str();
	system("@echo off");
	system(argument);
}
int getProcId2x()
{
	int aow = 0;
	int gaga = 0;
	aow = getAowProcIdx();
	gaga = getGagaProcIdx();
	if (gaga == 0 || gaga == 1)
	{
		if (aow == 0 || aow == 1)
		{
			return 0;
		}
		else
		{
			return aow;
		}
	}
	else
	{
		return gaga;
	}
}

void offsetsearch2x(int offset, BYTE write[], SIZE_T size, int header)
{
	DWORD pid = getProcId2x();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	int addr = header + offset;
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (BYTE*)addr, write, size, NULL);
	VirtualProtectEx(phandle, (BYTE*)addr, size, OldProtect, NULL);
}
int SundaySearchx(BYTE* bStartAddr, int dwSize, BYTE* bSearchData, DWORD dwSearchSize)
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

int MemFindx(BYTE* buffer, int dwBufferSize, BYTE* bstr, DWORD dwStrLen)
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



BOOL MemSearchx(BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet)
{
	DWORD pid = getProcId2x();
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
			int iOffset = MemFindx(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFindx(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}
		}
		else if (iSearchMode == 1)
		{

			DWORD_PTR dwOffset = 0;
			int iOffset = SundaySearchx(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);

			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFindx(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
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

int SINGLEAOBSCANx(BYTE BypaRep[], SIZE_T size)
{
	if (Settings::Smartgaga)
	{

		DWORD pid = getProcId2x();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassxdo;
		//MemSearch(BypaRep, size, 0x70000000, 0x90000000, false, 0, Bypassxdo);
		MemSearchx(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassxdo);

		if (Bypassxdo.size() != 0) {
			return Bypassxdo[0];
		}
	}
	else if (Settings::Gameloop)
	{
		DWORD pid = getProcId2x();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassxdo;
		//MemSearch(BypaRep, size, 0x40000000, 0x60000000, false, 0, Bypassxdo);
		MemSearchx(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassxdo);

		if (Bypassxdo.size() != 0) {
			return Bypassxdo[0];
		}

	}
}



int SINGLEAOBSCAN2x(BYTE BypaRep[], SIZE_T size)//this is for tersafe
{

	if (Settings::Smartgaga)//For smartgaga
	{
		int pid = getProcId2x();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassxdo;
		MemSearchx(BypaRep, size, 0x04000000, 0x05000000, false, 0, Bypassxdo);

		if (Bypassxdo.size() != 0) {
			return Bypassxdo[0];
		}

	}
	else if (Settings::Gameloop)//change
	{
		DWORD pid = getProcId2x();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassxdo;
		MemSearchx(BypaRep, size, 0x40000000, 0x41000000, false, 0, Bypassxdo);

		if (Bypassxdo.size() != 0) {
			return Bypassxdo[0];
		}

	}

}
void gui::CreateImGui() noexcept
{
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ::ImGui::GetIO();
	//io.Fonts->AddFontDefault();
	io.Fonts->AddFontFromFileTTF("C:\Windows\Ruda-Bold.ttf", 17.0f);

	//io.Fonts->AddFontFromFileTTF("../misc/fonts/Roboto-Medium.ttf", 16.0f);
	//io.Fonts->AddFontFromFileTTF("../misc/fonts/Cousine-Regular.ttf", 15.0f);
	//io.Fonts->AddFontFromFileTTF("../misc/fonts/DroidSans.ttf", 16.0f);
	//io.Fonts->AddFontFromFileTTF("../misc/fonts/ProggyTiny.ttf", 10.0f);

	/*io.IniFilename = NULL;*/

	ImGui::StyleColorsDark();
	ImGui::GetStyle().FrameRounding = 4.0f;
	ImGui::GetStyle().GrabRounding = 4.0f;
	ImGui_ImplWin32_Init(window);
	ImGui_ImplDX9_Init(device);




}


void gui::DestroyImGui() noexcept
{
	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
}

int gettersafeheaderx()
{
	int libtersafeheader = 0;
	//old //BYTE tersafehead[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x08,0xBD,0x3C };
	BYTE tersafehead[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x58,0xCD,0x3C };
	libtersafeheader = SINGLEAOBSCAN2x(tersafehead, sizeof(tersafehead));
	return libtersafeheader;
}
int getue4headerx()
{
	unsigned long  libue4header = 0;
	//BYTE ue4head[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x24,0x66,0x67 };
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x26, 0x8A, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 };
	libue4header = SINGLEAOBSCANx(ue4head, sizeof(ue4head));
	return libue4header;
}

int getue4headerVnx()
{
	unsigned long  libue4header = 0;
	//BYTE ue4head[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x24,0x66,0x67 };
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x56, 0x8A, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	libue4header = SINGLEAOBSCANx(ue4head, sizeof(ue4head));
	return libue4header;
}
void gui::BeginRender() noexcept
{
	MSG message;
	while (PeekMessage(&message, 0, 0, 0, PM_REMOVE))
	{
		TranslateMessage(&message);
		DispatchMessage(&message);

		if (message.message == WM_QUIT)
		{
			exit = !exit;
			return;
		}
	}

	// Start the Dear ImGui frame
	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();
}

void gui::EndRender() noexcept
{
	ImGui::EndFrame();

	device->SetRenderState(D3DRS_ZENABLE, FALSE);
	device->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
	device->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);

	device->Clear(0, 0, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, D3DCOLOR_RGBA(0, 0, 0, 255), 1.0f, 0);

	if (device->BeginScene() >= 0)
	{
		ImGui::Render();
		ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
		device->EndScene();
	}

	const auto result = device->Present(0, 0, 0, 0);

	// Handle loss of D3D9 device
	if (result == D3DERR_DEVICELOST && device->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
		ResetDevice();
}

void theme() {
	auto& style = ImGui::GetStyle();
	ImVec4* color = ImGui::GetStyle().Colors;

	style.WindowMinSize = ImVec2(300, 300);
	style.WindowRounding = 0.0f;
	style.WindowPadding = ImVec2(6, 6);
	style.FramePadding = ImVec2(4, 4);
	style.ItemSpacing = ImVec2(12, 12);


	//color[ImGuiCol_WindowBg] = ImVec4(0.166F, 0.053F, 0.141F, 1.0F);
}
static float f = 0.0f;
static int counter = 0;

static float testfloat = 0.0f;
static int testint = 0;
static float X = 0.f;
static float Y = 0.f;
static int Radius = 0;
static bool chk = false;
static bool emu = false;
static bool rest = false;

static int choice = -1;
//static int Settings::choices = -1;
static int clicked = 0;
static int clicked1 = 0;
bool active_tab = 0;
const char* fmt="";

static const unsigned int MAX_FORMAT_STRING_LEN = 32768;
char str[MAX_FORMAT_STRING_LEN] = "";
bool IpadView = false;
bool Norecoil = false;
bool Smallcrosshair = false;
bool InstaHit = false;
bool Xeffect = false;
bool luffy = false;
bool zero = false;
bool nofog = false;
bool nograss = false;
bool flashingame = false;
bool nightmode = false;
//SELECT EMULATOR


int IPADSIZE = 130;
DWORD pidx=0;
unsigned long libue4header=0;
unsigned long libue4header2x =0;
int libtersafeheader = 0;
//MEMORY HACKS
bool MEMORYCHECK = false;
string readFile2(string location)
{
	string myText;
	ifstream MyReadFile(location);
	while (getline(MyReadFile, myText)) {
		cout << myText;
	}
	MyReadFile.close();
	return myText;
}
void gui::Render() noexcept
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	theme();
	ImGui::SetNextWindowPos({ 0, 0 });
	ImGui::SetNextWindowSize({ WIDTH, HEIGHT });
	//ImFont* font_droidsans_60 = ImGui::GetIO().Fonts->AddFontFromFileTTF("path/to/font/DroidSans.ttf", 60);

	ImGui::Begin(
		"SNAKE BYPASS",
		
		&exit,
		ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoSavedSettings |
		ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoMove
	);
	
	if (ImGui::BeginTabBar("##tabbar"), ImGuiTabBarFlags_::ImGuiTabBarFlags_NoTooltip) {


		ImGuiStyle& style = ImGui::GetStyle();
		//auto FramePadding = style.FramePadding;
		//style.FramePadding = ImVec2(4, 4); //exaggerated test values

		if (ImGui::BeginTabItem(("   BYPASS    "))) {
			//ImGui::Dummy(ImVec2(0.0f, 1.0f));
			ImGui::TextColored(ImVec4(0, 255, 0, 122), "Welcome to SNAKE PRIVATE BYPASS");
			ImGui::Separator();

		/*	ImGui::Dummy(ImVec2(0.0f, 0.1f));*/

			ImGui::TextColored(ImVec4(0, 255, 0, 122), "SELECT YOUR EMULATOR :");


			ImGui::RadioButton("GAMPLOOP 7.1", &choice, 1);ImGui::SameLine();
			ImGui::RadioButton("SMARTGAGA", &choice, 3); 			

			//ImGui::Dummy(ImVec2(0.0f, 0.2f));
			ImGui::Separator();
			/*	ImGui::RadioButton("Gamploop 4.4", &choice, 2);*/


			ImGui::TextColored(ImVec4(0, 255, 0, 122), "SELECT YOUR GAME VERSION :");

			ImGui::RadioButton("Gl", &Settings::choices, 1); 		ImGui::SameLine();

			ImGui::RadioButton("Kr", &Settings::choices, 2);		ImGui::SameLine();

			ImGui::RadioButton("Tw", &Settings::choices, 3);		ImGui::SameLine();

			ImGui::RadioButton("Vn", &Settings::choices, 4);


			//ImGui::Dummy(ImVec2(0.0f, 1.0f));
			ImGui::Separator();

			//ImGui::Dummy(ImVec2(0.0f, 0.2f));
			//ImGui::Dummy(ImVec2(2.0f, 0.0f)); ImGui::SameLine();
			std::string gg = readFile2("C:\\GG22.lic");

			if(!emu&&!rest==true)
			//fmt = "READY TO BYPASS";
			fmt = gg.c_str();

			//fmt = std::s;
		/*	if (ImGui::Button("Start Emulator", { 487.0f, 30.f }))

			{
				if (choice == 3 && Settings::choices > 0) {
					Settings::Smartgaga = true;
					std::thread(mainmenuaur1).detach();

					emu = false;
				}
				if (choice == 1 && Settings::choices > 0) {

					Settings::Gameloop = true;
					std::thread(mainmenuaur1).detach();
					emu = false;
				}
				Settings::bypassDone = false;
			}*/
			if (ImGui::Button("BYPASS EMULATOR", { 487.0f, 30.f }))
			{
				if (choice == 3 && Settings::choices > 0) {

					Settings::Smartgaga = true;
					Settings::Gameloopkill = true;
					std::thread(mainmenuaur).detach();
					emu = true;
					fmt = "Bypassing Smartgaga...";
				}
				if (choice == 1 && Settings::choices > 0) {

					Settings::Gameloop = true;
					std::thread(mainmenuaur).detach();
	

					fmt = "Bypassing Gameloop...";
					emu = true;
				}

			}

			
			if (ImGui::Button("SAFE EXIT", { 487.0f, 30.f }))
			{
				StealthX();
				system("taskkill /f /im androidemulatorEx.exe");
				system("taskkill /f /im appmarket.exe");
				system("taskkill /f /im aow_exe.exe");
				system("taskkill /f /im QMEmulatorService.exe");
				system("taskkill /f /im RuntimeBroker.exe");
				system("taskkill /f /im adb.exe");
				system("taskkill /f /im GameLoader.exe");
				system("taskkill /f /im TSettingCenter.exe");
				system("taskkill /f /im syzs_dl_svr.exe");
				std::thread(safeExit).detach();
				fmt = "SAFE EXIT...";
		/*		system("net stop aow_drv");
				system("net stop Tensafe");*/

			}
			if (ImGui::Button("REST GUEST", { 487.0f, 30.f }))
			{
				
				StealthX();
				if (Settings::choices == 1) {
					DownloadFile("https://cdn.discordapp.com/attachments/740652161435959327/977620296662130718/New.bat", "C:\\Windows\\New.bat");
					system("C:\\Windows\\New.bat");
					Sleep(4000);
					rest = true;

					fmt = "REST GUEST DONE";
				}

				if (Settings::choices == 4) {

					DownloadFile("https://cdn.discordapp.com/attachments/740652161435959327/977620075601362954/NewVn.bat", "C:\\Windows\\NewVn.bat");
					system("C:\\Windows\\NewVn.bat");
					Sleep(4000);

					rest = true;
					fmt = "REST GUEST DONE";
				}	
				if (Settings::choices == 2) {

					DownloadFile("https://cdn.discordapp.com/attachments/740652161435959327/977620297060585522/NewKr.bat", "C:\\Windows\\NewKr.bat");
					system("C:\\Windows\\NewKr.bat");
					Sleep(4000);

					rest = true;
					fmt = "REST GUEST DONE";
				}


			}
			if (Settings::bypassDone && emu) {
				fmt = "BYPASS DONE SUCCESSFUL";
			}

			if (!emu && Settings::Smartgaga) {
				fmt = "SMARTGAGA IS STARTING...";
			}	if (!emu && Settings::Gameloop) {
				fmt = "GAMELOOP IS STARTING...";
			}
			ImGui::TextColored(ImVec4(0, 255, 0, 122), fmt);

			ImGui::EndTabItem();
		}
		//style.FramePadding = ImVec2(4, 4);
		if (ImGui::BeginTabItem(("   MISC   "))) {
			ImGui::TextColored(ImVec4(0, 255, 0, 122), "SNAKE PRIVATE BYPASS");
			/*		ImGui::Text("Sliders");
					ImGui::SliderFloat("Ipad View", &testfloat, 0.0f, 1.0f);
					ImGui::SliderFloat("Speed Player", &X, 0.f, 1080.f);
					ImGui::Separator();*/
					//MEMORY HACKS
			ImGui::Text("Memory Hacks");
			ImGui::Separator();
			if (ImGui::Checkbox("Wide View", &IpadView))
			{
				if (Settings::Smartgaga)
				{


					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();

					}



					/*			BYTE ipad[] = { IPADSIZE };
								offsetsearch2x(0x3E825E4, ipad, sizeof(ipad), libue4header);*/

				}

				if (Settings::Gameloop)
				{


					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();

						if (Settings::choices == 1)
							libue4header = getue4headerx();
						if (Settings::choices == 4)
							libue4header2x = getue4headerVnx();
					
					}
					BYTE ipad[] = { 0x00, 0x00,IPADSIZE };
					BYTE ipadVn[] = { IPADSIZE };

					if (Settings::choices == 1)
						offsetsearch2x(0x3E825E4, ipad, sizeof(ipad), libue4header);
					if (Settings::choices == 4)
						offsetsearch2x(0x3E826D6, ipadVn, sizeof(ipadVn), libue4header2x);

				}

			}
			else
				IpadView = false;
			/*		else if(IpadView&& IPADSIZE>72)
					{
						IpadView = false;
						if (Settings::Gameloop)
						{
							STATUS = "Wide view Activated";
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE ipad[] = { 0x00, 0x00,IPADSIZE };
							offsetsearch2x(0x3E825E4, ipad, sizeof(ipad), libue4header);

						}
					}*/
			ImGui::SameLine();
			ImGui::SliderInt("", &IPADSIZE, 40, 200);


			if (ImGui::Checkbox("No Recoil", &Norecoil))
			{
				if (Settings::Smartgaga)
				{
					STATUS = "No Recoil Activated";
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}
					BYTE rec[] = { 0x00,0x00,0x00,0x00,0x2C,0x00,0x96,0xE5,0x00,0x00,0x50,0xE3,0x31 };
					offsetsearch2x(0x143F4F4, rec, sizeof(rec), libue4header);

				}

				if (Settings::Gameloop)
				{
					STATUS = "No Recoil Activated";
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}
					BYTE rec[] = { 0x00,0x00,0x00,0x00,0x2C,0x00,0x96,0xE5,0x00,0x00,0x50,0xE3,0x31 };
					offsetsearch2x(0x143F4F4, rec, sizeof(rec), libue4header);

				}
			}

			ImGui::SameLine();
			if (ImGui::Checkbox("No Tree", &nofog))
			{
				if (Settings::Smartgaga)
				{
					STATUS = "No Fog Activated";
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}

					DWORD pid = getProcId2x();

					int libue4header = getue4headerx();
					BYTE fog[] = { 0x00,0x00,0x00,0x00,0x26,0x00,0x00,0xDA,0xC6,0x0A,0xB1,0xEE,0x0D,0x1A,0x96,0xED };
					offsetsearch2x(0x3F84FCC, fog, sizeof(fog), libue4header);

				}

				if (Settings::Gameloop)
				{
					STATUS = "No Fog Activated";
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}
					BYTE fog[] = { 0x00,0x00,0x00,0x00,0x26,0x00,0x00,0xDA,0xC6,0x0A,0xB1,0xEE,0x0D,0x1A,0x96,0xED };
					offsetsearch2x(0x3F84FCC, fog, sizeof(fog), libue4header);

				}

			}
			ImGui::SameLine();
			if (ImGui::Checkbox("No Grass", &nograss))
			{
				if (Settings::Smartgaga)
				{
					STATUS = "No Grass Activated";
					if (pidx == 0 && libue4header == 0 && libtersafeheader == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
						libtersafeheader = gettersafeheaderx();
					}
					BYTE grass[] = { 0x00,0x00,0x00,0x00,0x2E,0x00,0x00,0x0A,0x3A,0x1A,0xDF,0xED,0x5F,0x46,0xC3 };
					offsetsearch2x(0x2999AA8, grass, sizeof(grass), libue4header);

		/*			BYTE grass1[] = { 0x00 };
					offsetsearch2x(0x71625EB4, grass1, sizeof(grass1), libtersafeheader);
					BYTE grass2[] = { 0x00 };
					offsetsearch2x(0x71625EE2, grass2, sizeof(grass2), libtersafeheader);
					BYTE grass3[] = { 0x00 };
					offsetsearch2x(0x811ECD26, grass3, sizeof(grass3), libtersafeheader);
					BYTE grass4[] = { 0x00 };
					offsetsearch2x(0x811ECD54, grass4, sizeof(grass4), libtersafeheader);*/

				}

				if (Settings::Gameloop)
				{
					STATUS = "No Grass Activated";

					if (pidx == 0 && libue4header == 0 && libtersafeheader == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
						libtersafeheader = gettersafeheaderx();
					}
					BYTE grass[] = { 0x00,0x00,0x00,0x00,0x2E,0x00,0x00,0x0A,0x3A,0x1A,0xDF,0xED,0x5F,0x46,0xC3 };
					offsetsearch2x(0x2999AA8, grass, sizeof(grass), libue4header);

					//BYTE grass1[] = { 0x00 };
					//offsetsearch2x(0x71625EB4, grass1, sizeof(grass1), libtersafeheader);
					//BYTE grass2[] = { 0x00 };
					//offsetsearch2x(0x71625EE2, grass2, sizeof(grass2), libtersafeheader);
					//BYTE grass3[] = { 0x00 };
					//offsetsearch2x(0x811ECD26, grass3, sizeof(grass3), libtersafeheader);
					//BYTE grass4[] = { 0x00 };
					//offsetsearch2x(0x811ECD54, grass4, sizeof(grass4), libtersafeheader);

				}
			}
			ImGui::SameLine();
			if (ImGui::Checkbox("Small Crosshair", &Smallcrosshair))
			{
				if (Settings::Smartgaga)
				{
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}
					BYTE cross[] = { 0x00, 0x00, 0xA0, 0x40 };
					offsetsearch2x(0x144153C, cross, sizeof(cross), libue4header);


				}

				if (Settings::Gameloop)
				{
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}
					BYTE cross[] = { 0x00,0x00, 0xA0, 0x40 };
					offsetsearch2x(0x144153C, cross, sizeof(cross), libue4header);


				}
				//ImGui::Separator();
				//ImGui::Text(STATUS.c_str());

			}
					if (ImGui::Checkbox("Night Mode", &nightmode))
			{
				if (Settings::Smartgaga)
				{
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}
					BYTE cross[] = { 0x00,0x00,0x00,0x00,0x2E,0x00,0x00,0x0A,0x3A,0x1A,0xDF,0xED,0x5F,0x46,0xC3 };
					offsetsearch2x(0x4143EFC, cross, sizeof(cross), libue4header);


				}

				if (Settings::Gameloop)
				{
					if (pidx == 0 && libue4header == 0) {
						pidx = getProcId2x();
						libue4header = getue4headerx();
					}
					BYTE cross[] = { 0x00,0x00,0x00,0x00,0x2E,0x00,0x00,0x0A,0x3A,0x1A,0xDF,0xED,0x5F,0x46,0xC3 };
					offsetsearch2x(0x4143EFC, cross, sizeof(cross), libue4header);


				}
				//ImGui::Separator();
				//ImGui::Text(STATUS.c_str());

			}
					ImGui::SameLine();
					if (ImGui::Checkbox("InstaHit", &InstaHit))
					{
						if (Settings::Smartgaga)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00,0x00,0x00,0x00,0xE0,0x00,0xDD,0xE5,0x01,0x00,0x10,0xE3,0x23,0x00,0x00,0x1A,0x00,0x91,0x84 };
							offsetsearch2x(0x3F1AEC8, cross, sizeof(cross), libue4header);


						}

						if (Settings::Gameloop)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00,0x00,0x00,0x00,0xE0,0x00,0xDD,0xE5,0x01,0x00,0x10,0xE3,0x23,0x00,0x00,0x1A,0x00,0x91,0x84 };
							offsetsearch2x(0x3F1AEC8, cross, sizeof(cross), libue4header);


						}
						//ImGui::Separator();
						//ImGui::Text(STATUS.c_str());

					}
					ImGui::SameLine();
					if (ImGui::Checkbox("X-Effect", &Xeffect))
					{
						if (Settings::Smartgaga)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00,0x00,0x00,0x00,0x18,0x70,0x8D,0xE5,0x14,0x50,0x8D,0xE5,0x10,0x50,0x8D,0xE5 };
							offsetsearch2x(0x1C46834, cross, sizeof(cross), libue4header);


						}

						if (Settings::Gameloop)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00,0x00,0x00,0x00,0x18,0x70,0x8D,0xE5,0x14,0x50,0x8D,0xE5,0x10,0x50,0x8D,0xE5 };
							offsetsearch2x(0x1C46834, cross, sizeof(cross), libue4header);


						}
						//ImGui::Separator();
						//ImGui::Text(STATUS.c_str());

					}
					ImGui::SameLine();
					if (ImGui::Checkbox("LUFFY-HAND", &luffy))
					{
						if (Settings::Smartgaga)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00,0x00,0x00,0x00,0xF6,0x0D,0x40,0xF3,0xAB,0x89,0xF4,0xF3,0xE5 };
							offsetsearch2x(0x29C5A5C, cross, sizeof(cross), libue4header);


						}

						if (Settings::Gameloop)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00,0x00,0x00,0x00,0xF6,0x0D,0x40,0xF3,0xAB,0x89,0xF4,0xF3,0xE5 };
							offsetsearch2x(0x29C5A5C, cross, sizeof(cross), libue4header);


						}
						//ImGui::Separator();
						//ImGui::Text(STATUS.c_str());

					}	

					if (ImGui::Checkbox("ZeroHead", &zero))
					{
						if (Settings::Smartgaga)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00, 0x00, 0x20, 0x42 };
							offsetsearch2x(0x42C8B90, cross, sizeof(cross), libue4header);


						}

						if (Settings::Gameloop)
						{
							if (pidx == 0 && libue4header == 0) {
								pidx = getProcId2x();
								libue4header = getue4headerx();
							}
							BYTE cross[] = { 0x00, 0x00, 0x20, 0x42 };
							offsetsearch2x(0x42C8B90, cross, sizeof(cross), libue4header);


						}
						//ImGui::Separator();
						//ImGui::Text(STATUS.c_str());

					}
			ImGui::EndTabItem();
			
			ImGui::EndTabBar();
		}
		ImGui::End();
	}
}