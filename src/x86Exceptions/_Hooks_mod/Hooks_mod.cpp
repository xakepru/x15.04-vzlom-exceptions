#pragma warning( disable : 4005 ) 
#include <Windows.h>
#include <Ntsecapi.h>

#include "../_Dasm_mod/Dasm_mod.h"
#include "Hooks_mod.h" 

// ------------------------------------------------------

BYTE bSplicingCode[] = {0xE9, 0x00, 0x00, 0x00, 0x00}; // jmp rel32

// ------------------------------------------------------

DWORD	HookProc(HMODULE hModule, PCHAR szProc, DWORD dwHookAddr)
{
	DWORD pProcAddr = (DWORD) GetProcAddress(hModule, szProc);
	if (pProcAddr == NULL) return NULL;	// function doesn't exists in current process

	return HookProc (pProcAddr, dwHookAddr);
}
// ------------------------------------------------------

DWORD	HookProc(PCHAR szModule, PCHAR szProc, DWORD dwHookAddr)
{
	HMODULE module = GetModuleHandle(szModule);
	return HookProc (module, szProc, dwHookAddr);
}
// ------------------------------------------------------

/// RETURN VALUES: addr of org code thunk, 0 if mem err, -1 if func_size < code_size
DWORD	HookProc(DWORD dwProcAddr, DWORD dwHookAddr)
{	
	// sizes
	DWORD dwCodeSize = sizeof(bSplicingCode);
	DWORD dwFuncSize = GetFuncSize( (PBYTE) dwProcAddr);
	DWORD dwCodeSizeAligned = GetMinSize((PBYTE) dwProcAddr, dwCodeSize);
	if (dwCodeSizeAligned > dwFuncSize) return (DWORD)-1;	// no enough space

	PBYTE pBuffOriginal = (PBYTE) VirtualAlloc(NULL, dwCodeSizeAligned + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // +5 (JMP to continuation)
	if (pBuffOriginal)
	{
		// initialize original code thunk
		memcpy(pBuffOriginal, (PVOID)dwProcAddr, dwCodeSizeAligned);
		*(pBuffOriginal+dwCodeSizeAligned) = 0xE9;
		*(PDWORD)(pBuffOriginal+dwCodeSizeAligned+1) = dwProcAddr - (DWORD)pBuffOriginal - 5;

		// hook
		DWORD dwOldAccess;
		BOOL changed = VirtualProtect( (PVOID)dwProcAddr, dwCodeSizeAligned, PAGE_EXECUTE_READWRITE, &dwOldAccess);
		
		if (changed)
		{
			*(PDWORD) (bSplicingCode + 1) = dwHookAddr - (dwProcAddr + 5);
			memcpy((PVOID)dwProcAddr, bSplicingCode, sizeof(bSplicingCode));
		}
		else
		{
			VirtualFree(pBuffOriginal, 0, MEM_RELEASE);
			pBuffOriginal = NULL;
		}
	}

	return (DWORD)pBuffOriginal;
}
// ------------------------------------------------------




