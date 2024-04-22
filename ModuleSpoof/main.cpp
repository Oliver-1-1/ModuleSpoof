#include "spoof_module.hpp"
#include "honeypot.hpp"

void main() {
	uint64_t org = spoof("Protected.dll");
	run_honeypot(org);
	while (1) {
		Sleep(100);
	}
}

BOOL start = FALSE;
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID Reserved){
	if (dwReason == DLL_PROCESS_ATTACH){
		if(start == FALSE){
			start = TRUE;
			AllocConsole();
			freopen("CONOUT$", "w", stdout);
			main();
		}
	}
	return 1;
}

