#ifndef DASM_MOD
#define DASM_MOD

int Disasm (void * pCode);

int GetFuncSize (unsigned char* pCode);

int GetMinSize (unsigned char* pCode, unsigned long dwRequestedSize);

#endif