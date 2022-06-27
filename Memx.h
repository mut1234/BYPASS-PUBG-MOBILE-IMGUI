#pragma once
#include <Windows.h>
#include <vector>

class Memory
{

public:
	DWORD ProcessId = 0;
	HANDLE ProcessHandle;

	typedef struct _MEMORY_REGION {
		DWORD_PTR dwBaseAddr;
		DWORD_PTR dwMemorySize;
	}MEMORY_REGION;

	BOOL AttachProcess(DWORD ProcId)
	{
		if (ProcId == 0)
			return false;
		ProcessId = ProcId;
		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
		return ProcessHandle != nullptr;
	}

	bool ChangeProtection(ULONG Address, size_t size, DWORD NewProtect, DWORD& OldProtect)
	{
		return VirtualProtectEx(ProcessHandle, (LPVOID)Address, size, NewProtect, &OldProtect);;
	}

	bool ReplacePattern(DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* SearchAob, BYTE* ReplaceAob, bool ForceWrite = false)
	{

		int RepByteSize = _msize(ReplaceAob);
		if (RepByteSize <= 0) return false;
		std::vector<DWORD_PTR> foundedAddress;
		FindPattern(dwStartRange, dwEndRange, SearchAob, foundedAddress);
		if (foundedAddress.empty())
			return false;
		for (int i = 0; i < foundedAddress.size(); i++)
		{
			BOOL WriteStat = WriteBytes(foundedAddress[i], ReplaceAob, ForceWrite);
			if (!WriteStat)
				return false;
		}
		return true;
	}

	template <typename T>
	T ReadMemory(ULONG WriteAddress)
	{
		T pBuffer;
		ReadProcessMemory(ProcessHandle, (LPCVOID)WriteAddress, &pBuffer, sizeof(pBuffer), nullptr);
		return pBuffer;
	}
	template <typename T>
	bool WriteMemory(ULONG WriteAddress, T WriteValue, bool ForceWrite = false)
	{
		DWORD OldProtect;
		bool PStatus = false;
		if (ForceWrite)
		{
			PStatus = ChangeProtection(WriteAddress, sizeof(WriteValue), PAGE_EXECUTE_READWRITE, OldProtect);
		}
		bool status = WriteProcessMemory(ProcessHandle, (LPVOID)WriteAddress, &WriteValue, sizeof(WriteValue), nullptr);
		if (OldProtect != 0 && ForceWrite)
		{
			PStatus = ChangeProtection(WriteAddress, sizeof(WriteValue), PAGE_EXECUTE_READWRITE, OldProtect);
		}
		return PStatus && status;
	}

	bool WriteBytes(ULONG WriteAddress, BYTE* RepByte, bool ForceWrite = false) {

		DWORD OldProtect;
		int RepByteSize = _msize(RepByte);
		if (RepByteSize <= 0) return false;
		if (ForceWrite)
		{
			ChangeProtection(WriteAddress, RepByteSize, PAGE_EXECUTE_READWRITE, OldProtect);
		}
		bool status = WriteProcessMemory(ProcessHandle, (LPVOID)WriteAddress, RepByte, RepByteSize, 0);
		if (ForceWrite && OldProtect != 0)
		{
			ChangeProtection(WriteAddress, RepByteSize, PAGE_EXECUTE_READ, OldProtect);
		}
		delete[] RepByte;
		return status;
	}

	bool FindPattern(DWORD_PTR StartRange, DWORD_PTR EndRange, BYTE* SearchBytes, std::vector<DWORD_PTR>& AddressRet)
	{

		BYTE* pCurrMemoryData = NULL;
		MEMORY_BASIC_INFORMATION	mbi;
		std::vector<MEMORY_REGION> m_vMemoryRegion;
		mbi.RegionSize = 0x1000;
		DWORD dwAddress = StartRange;
		DWORD nSearchSize = _msize(SearchBytes);


		while (VirtualQueryEx(ProcessHandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < EndRange) && ((dwAddress + mbi.RegionSize) > dwAddress))
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
			pCurrMemoryData = new BYTE[mData.dwMemorySize];
			ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
			ReadProcessMemory(ProcessHandle, (LPCVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);
			if ((int)dwNumberOfBytesRead <= 0)
			{
				delete[] pCurrMemoryData;
				continue;
			}
			DWORD_PTR dwOffset = 0;
			int iOffset = Memfind(pCurrMemoryData, dwNumberOfBytesRead, SearchBytes, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				AddressRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = Memfind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, SearchBytes, nSearchSize);
			}

			if (pCurrMemoryData != NULL)
			{
				delete[] pCurrMemoryData;
				pCurrMemoryData = NULL;
			}

		}
		return TRUE;
	}

	int Memfind(BYTE* buffer, DWORD dwBufferSize, BYTE* bstr, DWORD dwStrLen) {
		if (dwBufferSize < 0) {
			return -1;
		}
		DWORD  i, j;
		for (i = 0; i < dwBufferSize; i++) {
			for (j = 0; j < dwStrLen; j++) {
				if (buffer[i + j] != bstr[j] && bstr[j] != '?')
					break;

			}
			if (j == dwStrLen)
				return i;
		}
		return -1;
	}
};