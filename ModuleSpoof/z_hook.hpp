#pragma once

#include <Windows.h>
#include <fstream>
#include <Ntsecapi.h>
#include <iostream>

class z_hook{
public:
    z_hook(void* original_function, void* target_function);
	bool activate();
	bool deactivate();
	uint8_t* gateway_bytes;

private:
	bool active;
    uint16_t size;

	unsigned char original_bytes[32];

	void* original_function;
	void* target_function;

	int get_instruction_size(const void* address);
};

