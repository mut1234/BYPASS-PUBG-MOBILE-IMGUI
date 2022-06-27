////
//// memory.h
////
////      Copyright (c) Microsoft Corporation. All rights reserved.
////
//// The buffer (memory) manipulation library.
////
//#pragma once
//#ifndef _INC_MEMORY // include guard for 3rd party interop
//#define _INC_MEMORY
//
//#include <corecrt_memory.h>
//#endif // _INC_MEMORY
//#pragma once
//#include <Windows.h>
//#include <vector>
//
//class Memory
//{
//	/*
//	--Author: 0xPrince
//	 --UPDATE- 1.1
//	*/
//public:
//	DWORD ProcessId = 0;
//	HANDLE ProcessHandle;
//
//	typedef struct _MEMORY_REGION {
//		DWORD_PTR dwBaseAddr;
//		DWORD_PTR dwMemorySize;
//	}MEMORY_REGION;
//
//	BOOL AttachProcess(DWORD ProcId)
//	{
//		if (ProcId == 0)
//			return false;
//		ProcessId = ProcId;
//		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
//		return ProcessHandle != nullptr;
//	}
//
//	bool ChangeProtection(ULONG Address, size_t size, DWORD NewProtect, DWORD& OldProtect)
//	{
//		return VirtualProtectEx(ProcessHandle, (LPVOID)Address, size, NewProtect, &OldProtect);;
//	}
//
//	bool ReplacePattern(DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* SearchAob, BYTE* ReplaceAob, bool ForceWrite = false)
//	{
//		//Author: 0xPrince
//		int RepByteSize = _msize(ReplaceAob);
//		if (RepByteSize <= 0) return false;
//		std::vector<DWORD_PTR> foundedAddress;
//		FindPattern(dwStartRange, dwEndRange, SearchAob, foundedAddress);
//		if (foundedAddress.empty())
//			return false;
//		for (int i = 0; i < foundedAddress.size(); i++)
//		{
//			BOOL WriteStat = WriteBytes(foundedAddress[i], ReplaceAob, ForceWrite);
//			if (!WriteStat)
//				return false;
//		}
//		return true;
//	}
//
//	template <typename T>
//	T ReadMemory(ULONG WriteAddress)
//	{
//		T pBuffer;
//		ReadProcessMemory(ProcessHandle, (LPCVOID)WriteAddress, &pBuffer, sizeof(pBuffer), nullptr);
//		return pBuffer;
//	}
//	template <typename T>
//	bool WriteMemory(ULONG WriteAddress, T WriteValue, bool ForceWrite = false)//he tell me use this beter
//		//this method is not correct. The address range is incorrect.
//		//Ok first check the addresses in your console, after that I fix this for you easy Compile now and cheeck
//	{
//		DWORD OldProtect;
//		bool PStatus = false;
//		if (ForceWrite)
//		{
//			PStatus = ChangeProtection(WriteAddress, sizeof(WriteValue), PAGE_EXECUTE_READWRITE, OldProtect);
//		}
//		bool status = WriteProcessMemory(ProcessHandle, (LPVOID)WriteAddress, &WriteValue, sizeof(WriteValue), nullptr);
//		if (OldProtect != 0 && ForceWrite)
//		{
//			PStatus = ChangeProtection(WriteAddress, sizeof(WriteValue), PAGE_EXECUTE_READWRITE, OldProtect);
//		}
//		return PStatus && status;
//	}
//
//	bool WriteBytes(ULONG WriteAddress, BYTE* RepByte, bool ForceWrite = false) {
//
//		DWORD OldProtect;
//		int RepByteSize = _msize(RepByte);
//		if (RepByteSize <= 0) return false;
//		if (ForceWrite)
//		{
//			ChangeProtection(WriteAddress, RepByteSize, PAGE_EXECUTE_READWRITE, OldProtect);
//		}
//		bool status = WriteProcessMemory(ProcessHandle, (LPVOID)WriteAddress, RepByte, RepByteSize, 0);
//		if (ForceWrite && OldProtect != 0)
//		{
//			ChangeProtection(WriteAddress, RepByteSize, PAGE_EXECUTE_READ, OldProtect);
//		}
//		delete[] RepByte;
//		return status;
//	}
//
//	int Memfind(BYTE* buffer, DWORD dwBufferSize, BYTE* bstr, DWORD dwStrLen) {
//		if (dwBufferSize < 0) {
//			return -1;
//		}
//		DWORD  i, j;
//		for (i = 0; i < dwBufferSize; i++) {
//			for (j = 0; j < dwStrLen; j++) {
//				if (buffer[i + j] != bstr[j] && bstr[j] != '?')
//					break;
//
//			}
//			if (j == dwStrLen)
//				return i;
//		}
//		return -1;
//	}
//};
