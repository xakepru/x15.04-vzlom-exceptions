#include <windows.h>
#include "VEHtoSEH.h"
#include "_Hooks_mod\Hooks_mod.h"

void RelocateImage(PVOID Image, UINT_PTR addrDelta, BOOL isRawFile);

UINT_PTR g_dwImageBase = 0;

typedef NTSTATUS (NTAPI*__NtQueryVirtualMemory)(HANDLE, PVOID , INT, PVOID, ULONG, PULONG);
__NtQueryVirtualMemory org_NtQueryVirtualMemory;

NTSTATUS NTAPI xNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, INT MemoryInformationClass, OUT PMEMORY_BASIC_INFORMATION MemInformation, ULONG Length, OUT PULONG ResultLength OPTIONAL)
{
	NTSTATUS Status = org_NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemInformation, Length, ResultLength);
	if (!Status && !MemoryInformationClass) // MemoryBasicInformation
	{
		if((UINT_PTR)MemInformation->AllocationBase == g_dwImageBase) MemInformation->Type =  MEM_IMAGE;
	}
	return Status;
}

typedef NTSTATUS (__stdcall *_NtQueryInformationProcess)(HANDLE, INT, PVOID, ULONG, PULONG);
_NtQueryInformationProcess org_NtQueryInformationProcess;

NTSTATUS __stdcall xNtQueryInformationProcess(__in HANDLE ProcessHandle, __in INT ProcessInformationClass, PVOID ProcessInformation, __in ULONG ProcessInformationLength, PULONG ReturnLength)
{
	NTSTATUS Status = org_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	
	if (!Status && ProcessInformationClass == 0x22) // ProcessExecuteFlags
        *(PDWORD)ProcessInformation |= 0x20; // ImageDispatchEnable
	return Status;
}

void exceptions_test()
{
	__try 
	{
		int *i  =0;
		*i = 0;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		MessageBoxA(0, "Исключение перехвачено", "", 0);
	}
	ExitProcess(0);
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	/*	3 варианта обхода RtlIsValidHandler в том же порядке, что и в статье 
		раскоментируй нужную строчку чтобы активировать тот или иной способ
	*/

	/* Вариант с хуком NtQueryInformationProcess */
	//org_NtQueryInformationProcess = (_NtQueryInformationProcess) HookProc("ntdll.dll", "NtQueryInformationProcess", (DWORD)&xNtQueryInformationProcess);
	
	/* Вариант с хуком NtQueryVirtualMemory */
	org_NtQueryVirtualMemory = (__NtQueryVirtualMemory) HookProc("ntdll.dll", "NtQueryVirtualMemory", (DWORD)&xNtQueryVirtualMemory);
	
	/* Вариант с реализацией SEH через VEH */
	//EnableSEHoverVEH();

	/* Копируем текущий имейдж в новое место */
	DWORD dwImageBase = (DWORD) GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER *) dwImageBase;
	IMAGE_NT_HEADERS* pe = (IMAGE_NT_HEADERS *) ((DWORD) dos->e_lfanew + (DWORD) dos);
	DWORD SizeOfImage = pe->OptionalHeader.SizeOfImage;
	PVOID NewImage = VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD ret;
	VirtualProtect(NewImage, SizeOfImage, SEC_IMAGE|PAGE_EXECUTE_READWRITE, &ret);
	DWORD dwDeltaRemote = (DWORD) NewImage - dwImageBase;
	// Copy image
	memcpy(NewImage, (PVOID)dwImageBase, SizeOfImage);
	// Fix offsets (with relocs)
	RelocateImage(NewImage, dwDeltaRemote, 0);
	DWORD dwRemoteProcAddr = ((DWORD) &exceptions_test + dwDeltaRemote);
	g_dwImageBase = (UINT_PTR) NewImage;
	// exceptions_test в новой области
	__asm jmp dwRemoteProcAddr;
	return 0;
}