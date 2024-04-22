#include "spoof_module.hpp"

HMODULE remapped_location = 0;
HMODULE original_location = 0;

BOOL is_spoofed = FALSE;

z_hook* load_lib = nullptr;
z_hook* get_modulew = nullptr;
z_hook* get_module_exw = nullptr;
z_hook* get_proc_address_for_caller = nullptr;
z_hook* get_proc_address = nullptr;
z_hook* free_lib = nullptr;
z_hook* main_info = nullptr;

std::wstring wspoofed_name;
std::string spoofed_name;

EntryPoint_t spoofed_main;

BOOL free_library_hook(HMODULE module) {
	log("free_library_hook called!\n");
	if (module == remapped_location) {
		log("free_library_hook remapped called!\n");
		return TRUE;
	}
	FreeLibrary_t lib = (FreeLibrary_t)(free_lib->gateway_bytes);
	BOOL ret = lib(module);

	return ret;
}

FARPROC __stdcall get_proc_address_hook(HMODULE module, LPCSTR name) {
	log("get_proc_address_hook called!\n");

	GetProcAddress_t orginal = (GetProcAddress_t)(get_proc_address->gateway_bytes);

	if (module == original_location) {
		log("get_proc_address_hook original location called!\n");
	}

	if (module == remapped_location) {
		//Sleep(5000);
		log("get_proc_address_hook remapped called!\n");

		return (FARPROC)z_get_proc_address((uint64_t)remapped_location, name);
	}

	return orginal(module, name);
}

__int64 __fastcall get_proc_address_for_caller_hook(void* a1, const char* a2, __int64 a3) {
	log("get_proc_address_for_caller_hook called!\n");

	GetProcAddressForCaller_t orginal = (GetProcAddressForCaller_t)(get_proc_address_for_caller->gateway_bytes);
	if (a1 == original_location) {
		log("get_proc_address_for_caller_hook original location called!\n");

	}
	if (a1 == remapped_location) {
		//Sleep(5000);
		log("get_proc_address_for_caller_hook remapped called!\n");
		return (__int64)z_get_proc_address((uint64_t)remapped_location, a2);
	}

	return orginal(a1, a2, a3);
}

HMODULE __stdcall get_module_handleW_hook(LPCWSTR name) {
	logw(L"get_module_handleW_hook called: %s\n", name);

	GetModuleHandleW_t original = (GetModuleHandleW_t)(get_modulew->gateway_bytes);

	if (name == NULL) {
		return (HMODULE)NtCurrentPeb()->ImageBaseAddress;
	}

	if (wcscmp(name, wspoofed_name.c_str())) {
		auto ret = original(name);
		return ret;
	}

	log("get_module_handleW_hook remapped called!\n");

	return remapped_location;

}

BOOL __stdcall get_module_handle_exW_hook(DWORD flags, LPCWSTR name, HMODULE* module) {
	log("get_module_handle_exW_hook called: %s\n", name);

	GetModuleHandleExW_t original = (GetModuleHandleExW_t)(get_module_exw->gateway_bytes);

	if (name == NULL) {
		*module = (HMODULE)NtCurrentPeb()->ImageBaseAddress;
		return TRUE;
	}

	if (wcscmp(name, wspoofed_name.c_str())) {
		return original(flags, name, module);
	}

	log("get_module_handle_exW_hook remapped called!\n");

	*module = remapped_location;
	return TRUE;
}

HMODULE load_lib_hook(LPCWSTR name, HANDLE file, DWORD flags) {
	LoadLibraryExW_t original = (LoadLibraryExW_t)load_lib->gateway_bytes;
	log("load_lib_hook called!\n");

	if (!wcsstr(name, wspoofed_name.c_str())) {
		HMODULE modT = original(name, file, flags);
		return modT;
	}

	if (is_spoofed == TRUE) {
		return remapped_location;
	}

	HMODULE ret = original(name, file, flags);
	if (ret == 0) {
		log("load_lib_hook error: %x\n", GetLastError());
		return 0;
	}

	original_location = ret;
	is_spoofed = TRUE;

	log("load_lib_hook original location: 0x%x\n", ret);
	log("load_lib_hook spoofed location: 0x%x\n", remapped_location);

	return remapped_location;
}

BOOL WINAPI main_hook(HINSTANCE dll, DWORD reason, LPVOID reserved) {
	log("Spoofed entry hook was called! Base 0x%x Reason %d\n", dll, reason);

	auto ret = spoofed_main(remapped_location, reason, reserved);
	log("Spoofed entry was executed! return value %d\n", (int)ret);

	//Sleep(5000);
	return TRUE;
}

PVOID load_file(LPCWSTR path) {
	HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD file_size = GetFileSize(file, NULL);
	PVOID file_base = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_READWRITE);
	ReadFile(file, file_base, file_size, 0, 0);

	return file_base;
}

void WINAPI dll_callback(ULONG reason, PCLDR_DLL_NOTIFICATION_DATA data, PVOID context) {
	UNREFERENCED_PARAMETER(context);
	if (reason == LDR_DLL_NOTIFICATION_REASON_LOADED) {
		if (data == NULL || data->Loaded.FullDllName == NULL) return;
		if (wcscmp(data->Loaded.BaseDllName->Buffer, wspoofed_name.c_str()) || is_spoofed == TRUE) return;

		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data->Loaded.DllBase;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
		PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS((uint64_t)dos + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return;

		logw(L"Module load callback was called: %s\n", data->Loaded.FullDllName->Buffer);

		//Hook real entry.
		(main_info = new z_hook((void*)((uint64_t)dos + nt->OptionalHeader.AddressOfEntryPoint), main_hook))->activate();

		//Now when entry is looked we manual map in spoofed module
		PVOID file = load_file(data->Loaded.FullDllName->Buffer);

		if (file == NULL) {
			log("Module load callback! Could not find file!\n");
			while (1) {}
		}

		remapped_location = (HMODULE)manual_map(file);

		if (remapped_location == NULL) {
			log("Module load callback! Could not map module\n");
			while (1) {}
		}

		dos = (PIMAGE_DOS_HEADER)remapped_location;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
		nt = (PIMAGE_NT_HEADERS)((uint64_t)remapped_location + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return;
		spoofed_main = (EntryPoint_t)(nt->OptionalHeader.AddressOfEntryPoint + (ULONGLONG)remapped_location);

		//Sleep(5000);
	}
}

NTSTATUS(NTAPI* LdrRegisterDllNotification)(
	ULONG                          flags,
	PLDR_DLL_NOTIFICATION_FUNCTION function,
	PVOID                          context,
	PVOID* cookie
	);

uint64_t spoof(std::string name) {
	spoofed_name = name;
	wspoofed_name = std::wstring(name.begin(), name.end());

	log("spoofing %s!\n", name);

	VOID* dll_callback_handle = 0;
	*(void**)&LdrRegisterDllNotification = (void*)GetProcAddress(LoadLibraryA("ntdll.dll"), "LdrRegisterDllNotification");
	LdrRegisterDllNotification(0, dll_callback, 0, &dll_callback_handle);
	log("Module load callback set!\n");

	(load_lib = new z_hook((void*)GetProcAddress(LoadLibraryA("kernelbase.dll"), "LoadLibraryExW"), &load_lib_hook))->activate();
	(get_modulew = new z_hook((void*)GetProcAddress(LoadLibraryA("kernelbase.dll"), "GetModuleHandleW"), &get_module_handleW_hook))->activate();
	(get_module_exw = new z_hook((void*)GetProcAddress(LoadLibraryA("kernelbase.dll"), "GetModuleHandleExW"), &get_module_handle_exW_hook))->activate();
	(free_lib = new z_hook((void*)GetProcAddress(LoadLibraryA("kernelbase.dll"), "FreeLibrary"), &free_library_hook))->activate();
	(get_proc_address = new z_hook((void*)GetProcAddress(LoadLibraryA("kernelbase.dll"), "GetProcAddress"), &get_proc_address_hook))->activate();
	(get_proc_address_for_caller = new z_hook((void*)GetProcAddress(LoadLibraryA("kernelbase.dll"), "GetProcAddressForCaller"), &get_proc_address_for_caller_hook))->activate();
	log("Hooks activated!\n");

	//----------Test----------\\

	log("Loading protected dll!\n");


	HMODULE dll = LoadLibraryA(name.c_str());

	FARPROC address = GetProcAddress(dll, "export_test");
	typedef int(__stdcall* export_test_t)(long bar);
	export_test_t export_test = (export_test_t)address;

	log("export_test: %d\n", export_test(5));
	log("Test LoadLibraryA 0x%x\n ", LoadLibraryA(name.c_str()));
	log("Test GetModuleHandleA 0x%x\n ", GetModuleHandleA(name.c_str()));

	return (uint64_t)original_location;
}
