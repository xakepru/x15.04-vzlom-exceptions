#include <Windows.h>
#include <winnt.h>

UINT_PTR RvaToOffset(UINT_PTR RVA, UINT_PTR pFileMap)
{
	PIMAGE_NT_HEADERS pe = (IMAGE_NT_HEADERS *) ( ((IMAGE_DOS_HEADER *)pFileMap)->e_lfanew + (UINT_PTR)pFileMap);
	PIMAGE_SECTION_HEADER section = (IMAGE_SECTION_HEADER *) ((UINT_PTR)pe + sizeof (IMAGE_NT_HEADERS));

	WORD NumOfSections = pe->FileHeader.NumberOfSections;

	for (int i = 0; i < NumOfSections; i++)
	{
		if ((RVA >= section->VirtualAddress) && (RVA < section->VirtualAddress + section->SizeOfRawData))    
		//	return (DWORD)pFileMap + section->PointerToRawData + RVA - section->VirtualAddress;
			return section->PointerToRawData + RVA - section->VirtualAddress + pFileMap;
		section++;
	}
	return 0;
}
// ------------------------------------------------------

IMAGE_BASE_RELOCATION * LdrProcessRelocationBlock( void *page, UINT count, USHORT *relocs, UINT_PTR delta )
{
    while (count--)
    {
        USHORT offset = *relocs & 0xfff;
        int type = *relocs >> 12;
        switch(type)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(PWORD)((UINT_PTR)page + offset) += HIWORD(delta);
            break;
        case IMAGE_REL_BASED_LOW:
            *(PWORD)((UINT_PTR)page + offset) += LOWORD(delta);
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(PDWORD)((UINT_PTR)page + offset) += (DWORD)delta;
            break;
#ifdef _WIN64
        case IMAGE_REL_BASED_DIR64:
            *(INT_PTR *)((UINT_PTR)page + offset) += delta;
            break;
#endif
        default:
            //FIXME("Unknown/unsupported fixup type %x.\n", type);
            return NULL;
        }
        relocs++;
    }
    return (IMAGE_BASE_RELOCATION *)relocs;  /* return address of next block */
}
// ------------------------------------------------------

void RelocateImage(PVOID Image, UINT_PTR addrDelta, BOOL isRawFile) // suports x86 and x64
{
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER *) Image;
	IMAGE_NT_HEADERS* pe = (IMAGE_NT_HEADERS *) ((DWORD) dos->e_lfanew + (DWORD) dos);
	PIMAGE_BASE_RELOCATION pRelocs	= (PIMAGE_BASE_RELOCATION)((UINT_PTR)pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (UINT_PTR)Image);
	DWORD dwDirSize	= (DWORD)pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if ( isRawFile ) pRelocs = (PIMAGE_BASE_RELOCATION) RvaToOffset( (UINT_PTR)pRelocs - (UINT_PTR)Image, (UINT_PTR)Image);

	UINT_PTR pRelocationOffset;

	while ( dwDirSize && pRelocs->SizeOfBlock)
	{
		if ( pRelocs->VirtualAddress )
		{
			if ( isRawFile ) 
				pRelocationOffset = RvaToOffset( pRelocs->VirtualAddress, (UINT_PTR)Image);
			else
				pRelocationOffset = pRelocs->VirtualAddress + (UINT_PTR)Image;
			UINT dwCount = (pRelocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			pRelocs = LdrProcessRelocationBlock( (void*)pRelocationOffset, dwCount, (USHORT *)(pRelocs + 1), addrDelta );
			if (!pRelocs) return;
		}

		dwDirSize -= pRelocs->SizeOfBlock;
		//pRelocs = (PIMAGE_BASE_RELOCATION) (pRelocs->SizeOfBlock + (UINT_PTR)pRelocs);
	}
}