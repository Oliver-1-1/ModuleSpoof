#include "manual_map.hpp"

bool manual_map_reloc(uint64_t base) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint64_t)base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(nt->OptionalHeader.DataDirectory[0x5].VirtualAddress + base);
	while (reloc->SizeOfBlock && reloc->VirtualAddress) {
		if (reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
			uint16_t* info = (uint16_t*)((uint64_t)reloc + sizeof(IMAGE_BASE_RELOCATION));
			if (info == NULL) return false;

			for (uint32_t i = 0; i < (reloc->SizeOfBlock - 0x4); i++) {
				if (info[i]) {
					*(uint64_t*)((uint64_t)base + (reloc->VirtualAddress + (info[i] & 0xFFF))) += (base - nt->OptionalHeader.ImageBase);
				}
			}
		}
		reloc = (PIMAGE_BASE_RELOCATION)((uint64_t)reloc + reloc->SizeOfBlock);
	}

	return true;
}

bool manual_map_import(uint64_t base) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint64_t)base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(nt->OptionalHeader.DataDirectory[1].VirtualAddress + base);
	while (import->Name) {
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(base + import->OriginalFirstThunk);
		PIMAGE_THUNK_DATA fthunk = (PIMAGE_THUNK_DATA)(base + import->FirstThunk);

		HMODULE hmodule = LoadLibraryA((LPCSTR)(base + import->Name));
		if (hmodule == NULL) return false;

		while (thunk->u1.AddressOfData) {
			LPCSTR name = (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) ? (LPCSTR)(thunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)(base + thunk->u1.AddressOfData))->Name;
			*(PVOID*)fthunk = GetProcAddress(hmodule, name);
			thunk++, fthunk++;
		}
		import++;
	}

	return true;
}

uint64_t manual_map_populate(uint64_t file_buffer) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)file_buffer;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint64_t)file_buffer + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
	PVOID mapped_base = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // TODO set page protection

	memcpy(mapped_base, (PVOID)file_buffer, nt->OptionalHeader.SizeOfHeaders);
	PIMAGE_SECTION_HEADER section_ptr = IMAGE_FIRST_SECTION(nt);
	for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		IMAGE_SECTION_HEADER section = (IMAGE_SECTION_HEADER)*section_ptr++;
		memcpy((PVOID)((uint64_t)mapped_base + section.VirtualAddress), (PVOID)((uint64_t)file_buffer + section.PointerToRawData), section.SizeOfRawData);
	}

	return (uint64_t)mapped_base;
}

PVOID manual_map(PVOID file) {
	PVOID file_buffer = file;

	uint64_t mapped_base = manual_map_populate((uint64_t)file_buffer);
	manual_map_reloc(mapped_base);
	manual_map_import(mapped_base);

	return (PVOID)mapped_base;
}