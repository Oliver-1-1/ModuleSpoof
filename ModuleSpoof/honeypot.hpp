#pragma once
#include <Windows.h>
#include <iostream>
#include <thread>	
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#include <libloaderapi.h>

#define PAGE_SIZE  0x1000
#define PAGE_MASK  0xFFF
#define PAGE_SHIFT 12
#define SIZE_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + (((Size) & PAGE_MASK) ? 1 : 0))
#define PAGES_TO_SIZE(Pages) ((Pages) << PAGE_SIZE)

bool is_va_loaded(PVOID virtualAddress);
void honeypot();
void run_honeypot(uint64_t base);