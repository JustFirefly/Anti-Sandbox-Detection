#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/*
 * POF-CONCEPT: HARDWARE SPOOFING (T01 & T06) via VEH
 * Scans process memory for CPUID/RDTSC opcodes, patches them with INT3 breakpoints,
 * and handles the exceptions to manipulate CPU registers dynamically.
 */

// Arrays to store the memory addresses where we found the instructions
void* cpuid_addrs[100];
int cpuid_count = 0;

void* rdtsc_addrs[100];
int rdtsc_count = 0;

// The Exception Handler that catches our INT3 (0xCC) breakpoints
LONG WINAPI VehHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        void* faultAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;

        // 1. Check if the breakpoint happened at a CPUID instruction
        for (int i = 0; i < cpuid_count; i++) {
            if (faultAddr == cpuid_addrs[i]) {
                // Get the requested CPUID leaf from the RAX register
                uint32_t leaf = (uint32_t)ExceptionInfo->ContextRecord->Rax;
                uint32_t eax, ebx, ecx, edx;

                // Execute the REAL cpuid instruction inside our handler
                __asm__ volatile ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(leaf));

                // If checking features (Leaf 1), tamper with the results!
                if (leaf == 1) {
                    ecx &= ~(1 << 31); // Clear the 31st bit (Hypervisor Present)
                    printf("[VEH] T01: Trapped CPUID. Cleared Hypervisor bit.\n");
                }

                // Write the spoofed results back directly into the thread's CPU registers
                ExceptionInfo->ContextRecord->Rax = eax;
                ExceptionInfo->ContextRecord->Rbx = ebx;
                ExceptionInfo->ContextRecord->Rcx = ecx;
                ExceptionInfo->ContextRecord->Rdx = edx;

                // Advance the Instruction Pointer (RIP) by 2 bytes to skip the patched instruction
                ExceptionInfo->ContextRecord->Rip += 2; 
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // 2. Check if the breakpoint happened at an RDTSC instruction
        for (int i = 0; i < rdtsc_count; i++) {
            if (faultAddr == rdtsc_addrs[i]) {
                static uint64_t fake_ticks = 1000;
                fake_ticks += 50; // Increment slightly to simulate normal execution time

                // RDTSC stores results in EDX (High 32 bits) and EAX (Low 32 bits)
                ExceptionInfo->ContextRecord->Rax = (fake_ticks & 0xFFFFFFFF);
                ExceptionInfo->ContextRecord->Rdx = (fake_ticks >> 32);

                printf("[VEH] T06: Trapped RDTSC. Spoofed low-latency tick.\n");

                ExceptionInfo->ContextRecord->Rip += 2; 
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Function to scan memory and install the breakpoints
void InstallVehHooks() {
    // Register our exception handler
    AddVectoredExceptionHandler(1, VehHandler);

    // Get the base memory address of main.exe
    HMODULE hModule = GetModuleHandleA(NULL); 
    if (!hModule) return;

    // Parse the PE (Portable Executable) headers to find the executable .text section
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Look for the .text section containing the program's assembly code
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            uint8_t* textStart = (uint8_t*)hModule + section[i].VirtualAddress;
            DWORD textSize = section[i].Misc.VirtualSize;

            // Make the memory writable
            DWORD oldProtect;
            VirtualProtect(textStart, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            // Scan every byte for the opcodes
            for (DWORD j = 0; j < textSize - 1; j++) {
                if (textStart[j] == 0x0F && textStart[j+1] == 0xA2) { // 0F A2 = CPUID
                    cpuid_addrs[cpuid_count++] = &textStart[j];
                    textStart[j] = 0xCC; // Overwrite with INT 3 (Breakpoint)
                }
                else if (textStart[j] == 0x0F && textStart[j+1] == 0x31) { // 0F 31 = RDTSC
                    rdtsc_addrs[rdtsc_count++] = &textStart[j];
                    textStart[j] = 0xCC; // Overwrite with INT 3
                }
            }

            // Restore memory protection
            VirtualProtect(textStart, textSize, oldProtect, &oldProtect);
            break;
        }
    }
    printf("[PoC] VEH Hooks Active. Patched %d CPUID and %d RDTSC instructions.\n", cpuid_count, rdtsc_count);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InstallVehHooks();
    }
    return TRUE;
}
