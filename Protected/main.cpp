#include <Windows.h>
#include <iostream>
#include <map>
#include <thread>

#define log(msg, ...) printf("[Zepta-Protected.dll] "); printf(msg, __VA_ARGS__);fflush(stdout);
#define logw(msg, ...) wprintf(L"[Zepta-Protected.dll] "); wprintf(msg, __VA_ARGS__);fflush(stdout);
int* bb = nullptr;
void main();
extern "C" __declspec(dllexport)
int __stdcall export_test(long bar) {
	log("export_test called\n");

	int* nn = new int;
	*nn = 55;
	return *bb + 1 + *nn;
}
int m = 0;
int func(void) {
	return 3;
}

class test_classes {
public:

	test_classes() {
		log("test_classes called\n");
	}

	void test() {
		log("test_classes test called\n");
	}

	~test_classes() {
		log("test_classes deloc called \n");
	}
};

void normal_test() {
	log("Normal test...\n");
	log("Main fuction address: 0x%x\n", &main);
	log("export fuction address: 0x%x\n", &export_test);
}

//crt
test_classes test;
int gi = func();
void crt_test() {
	test_classes test2;
	test2.test();

	test_classes* test3 = new test_classes;
	test3->test();

	log("crt test gi %x\n", gi);
	_onexit(func);

}

void import_test() {
	log("ntdll: 0x%x\n", GetModuleHandleA("ntdll.dll"));
	log("kernelbase: 0x%x\n", GetModuleHandleA("kernelbase.dll"));
	log("Protected: 0x%x\n", GetModuleHandleA("Protected.dll"));

}

void main() {
	normal_test();
	crt_test();
	import_test();

	bb = new int;
	*bb = 5;

	int u = 6;
	memcpy(bb, &u, sizeof(int));

	log("... %d\n", *bb);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		main();
	}
	return 1;
}

