#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable : 4005 ) 
#include <windows.h>
#include <WinNT.h>

void RelocateImage(PVOID Image, UINT_PTR addrDelta, BOOL isRawFile);

extern "C"NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData (PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size);

PRUNTIME_FUNCTION xRuntimeFunctionCallback ( _In_ DWORD64 ControlPc, _In_opt_ PVOID ImageBase /* here could be pointer to the any Context */)
{
	ULONG Size, Length;
	PRUNTIME_FUNCTION Table = (PRUNTIME_FUNCTION) RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &Size);
	Length = Size/sizeof(PRUNTIME_FUNCTION);
	// process table
	ControlPc -= (UINT_PTR)ImageBase;
	for (ULONG i=0; i<Length; i++) {
		if (ControlPc >= Table[i].BeginAddress && ControlPc < Table[i].EndAddress)
		{
			return &Table[i];
		}
	}
	return 0;
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

void __stdcall main()
{
	/* Копируем текущий имейдж в новое место */
	PVOID ImageBase = GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER *) ImageBase;
	IMAGE_NT_HEADERS* pe = (IMAGE_NT_HEADERS *) ((UINT_PTR) dos->e_lfanew + (INT_PTR) dos);
	DWORD SizeOfImage = pe->OptionalHeader.SizeOfImage;
	PVOID NewImage = VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	UINT_PTR dwDeltaRemote = (UINT_PTR) NewImage - (UINT_PTR)ImageBase;
	// Copy image
	memcpy(NewImage, ImageBase, SizeOfImage);
	// Fix relocable offsets
	RelocateImage(NewImage, dwDeltaRemote, false);
	
	/* Вариант с добавлением таблицы в DynamicFunctionTable */
	//ULONG Size, Length;
	//PRUNTIME_FUNCTION Table = (PRUNTIME_FUNCTION) RtlImageDirectoryEntryToData(NewImage, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &Size);
	//Length = Size/sizeof(PRUNTIME_FUNCTION);
	//RtlAddFunctionTable(Table, Length, (UINT_PTR)NewImage);
	
	/* Вариант с установкой коллбека */
	RtlInstallFunctionTableCallback((UINT_PTR)NewImage |0x3, (UINT_PTR)NewImage, SizeOfImage, &xRuntimeFunctionCallback, NewImage, 0);

	/* Прыгаем на копию exceptions_test */
	((void (*)()) ((UINT_PTR) &exceptions_test + dwDeltaRemote)) ();
}

