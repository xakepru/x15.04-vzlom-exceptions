#ifndef HOOK_MOD
#define HOOK_MOD

DWORD	HookProc(HMODULE hModule, PCHAR szProc, DWORD dwHookAddr);
DWORD	HookProc(PCHAR szModule, PCHAR szProc, DWORD dwHookAddr);
DWORD	HookProc(DWORD dwProcAddr, DWORD dwHookAddr);

#endif