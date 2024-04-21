#pragma once
#include <Windows.h>
#include <fstream>
#include <Ntsecapi.h>
#include <iostream>

bool manual_map_reloc(uint64_t base);
bool manual_map_import(uint64_t base);
uint64_t manual_map_populate(uint64_t file_buffer);
PVOID manual_map(PVOID file);