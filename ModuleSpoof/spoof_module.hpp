#pragma once
#include "z_hook.hpp"
#include "manual_map.hpp"
#include "util.hpp"

#define log(msg, ...) printf("[Zepta-ModuleSpoof] "); printf(msg, __VA_ARGS__);fflush(stdout);
#define logw(msg, ...) wprintf(L"[Zepta-ModuleSpoof] "); wprintf(msg, __VA_ARGS__);fflush(stdout);

typedef BOOL(WINAPI* EntryPoint_t)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef HMODULE(WINAPI* LoadLibraryExW_t)(LPCWSTR name, HANDLE file, DWORD flags);
typedef BOOL(WINAPI* FreeLibrary_t)(HMODULE module);
typedef BOOL(WINAPI* GetModuleHandleExW_t)(DWORD flags, LPCWSTR name, HMODULE* module);
typedef HMODULE(WINAPI* GetModuleHandleW_t)(LPCWSTR name);
typedef __int64 (WINAPI* LdrGetProcedureAddressForCaller_t)(unsigned __int64 a1, const void** a2, int a3, ULONGLONG* a4, char a5, unsigned __int64 a6);
typedef __int64(WINAPI* GetProcAddressForCaller_t)(void* a1, const char* a2, __int64 a3);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE module, LPCSTR name);

BOOL free_library_hook(HMODULE module);
FARPROC __stdcall get_proc_address_hook(HMODULE module, LPCSTR name);
__int64 __fastcall get_proc_address_for_caller_hook(void* a1, const char* a2, __int64 a3);
HMODULE __stdcall get_module_handleW_hook(LPCWSTR name);
BOOL __stdcall get_module_handle_exW_hook(DWORD flags, LPCWSTR name, HMODULE* module);
HMODULE load_lib_hook(LPCWSTR name, HANDLE file, DWORD flags);
void WINAPI dll_callback(ULONG reason, PCLDR_DLL_NOTIFICATION_DATA data, PVOID context);
uint64_t spoof(std::string name);
