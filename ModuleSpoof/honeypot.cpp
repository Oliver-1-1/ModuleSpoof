#include "honeypot.hpp"
uint64_t module_base;
bool is_va_loaded(PVOID virtualAddress) {
	PSAPI_WORKING_SET_EX_INFORMATION w = { 0 };
	w.VirtualAddress = virtualAddress;
	K32QueryWorkingSetEx(GetCurrentProcess(), &w, sizeof(w));

	return w.VirtualAttributes.Valid;
}

void honeypot(){

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)module_base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return;
	uint32_t pages = SIZE_TO_PAGES(nt->OptionalHeader.SizeOfImage);
	K32EmptyWorkingSet(GetCurrentProcess());

	while (1) {
		for (uint32_t i = 0; i < pages; i++) {
			if (is_va_loaded((PVOID)(module_base + i * PAGE_SIZE))) {
				printf("Someone accessed the non spoofed module!\n");
				K32EmptyWorkingSet(GetCurrentProcess());
			}
		}
	}
}

void run_honeypot(uint64_t base) {
	module_base = base;
	std::thread s(honeypot);
	s.detach();
}