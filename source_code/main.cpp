#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <tchar.h>
#include <mmsystem.h> 
#include <intrin.h>   
#include <iphlpapi.h> 

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "user32.lib")

// -----------------------------------------------------------------------------------------
// T01: Hardware Artifacts - CPUID (Hypervisor Bit)
// Source: Adapted from a0rtega/pafish/pafish/cpu.c (Converted to MSVC Intrinsics)
// -----------------------------------------------------------------------------------------
int cpu_hv() {
    // __cpuid intrinsic stores results in an array of 4 integers (EAX, EBX, ECX, EDX)
    int cpuInfo[4] = { -1 };

    // Check CPUID with EAX=1
    __cpuid(cpuInfo, 1);

    // The hypervisor bit is bit 31 of ECX (index 2 in cpuInfo array)
    return (cpuInfo[2] >> 31) & 1;
}

// -----------------------------------------------------------------------------------------
// T02: Hardware Artifacts - MAC Address Validation
// Source: Adapted from ayoubfaouzi/al-khaser/al-khaser/AntiVM/VirtualBox.cpp
// -----------------------------------------------------------------------------------------
void t02_mac_check() {
    printf("[T02] MAC Address Check: Initiated\n");

    // MAC Prefixes to check (OUI - Organizationally Unique Identifier)
    // Sources: VMWare.cpp , VirtualBox.cpp 
    struct MacPrefix {
        const unsigned char bytes[3];
        const char* vendor;
    };

    std::vector<MacPrefix> blacklist = {
        { {0x00, 0x05, 0x69}, "VMware" },
        { {0x00, 0x0C, 0x29}, "VMware" },
        { {0x00, 0x1C, 0x14}, "VMware" },
        { {0x00, 0x50, 0x56}, "VMware" },
        { {0x08, 0x00, 0x27}, "VirtualBox" }
    };

    // Buffer for GetAdaptersInfo
    ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);

    // First call to check buffer size
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }

    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        bool found = false;

        // Iterate through linked list of adapters
        while (pAdapter) {
            printf("  [-] Checking Adapter: %s\n", pAdapter->Description);
            printf("      MAC: %02X-%02X-%02X-%02X-%02X-%02X\n",
                pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);

            // Check against blacklist
            for (const auto& entry : blacklist) {
                if (pAdapter->AddressLength >= 3 &&
                    pAdapter->Address[0] == entry.bytes[0] &&
                    pAdapter->Address[1] == entry.bytes[1] &&
                    pAdapter->Address[2] == entry.bytes[2]) {

                    printf("  [!] DETECTED: Known Virtualization Vendor MAC (%s)\n", entry.vendor);
                    found = true;
                }
            }
            pAdapter = pAdapter->Next;
        }

        if (!found) {
            printf("  [+] No blacklisted MAC addresses found.\n");
        }
    }
    else {
        printf("  [!] Error: Failed to get adapter info.\n");
    }

    if (pAdapterInfo) free(pAdapterInfo);
}

// -----------------------------------------------------------------------------------------
// T03: System Artifacts - Driver Files 
// Source: ayoubfaouzi/al-khaser/al-khaser/AntiVM/VirtualBox.cpp
// -----------------------------------------------------------------------------------------
BOOL is_FileExists(LPCTSTR szPath) {
    DWORD dwAttrib = GetFileAttributes(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void t03_driver_files() {
    const TCHAR* szPaths[] = {
        _T("C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmnet.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmmouse.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmci.sys")
    };

    printf("[T03] Driver File Check: Initiated\n");

    bool foundAny = false;

    // Iterate and print status for EVERY file
    for (int i = 0; i < 5; i++) {
        printf("  [-] Checking: %ls... ", szPaths[i]);

        if (is_FileExists(szPaths[i])) {
            printf("\n      [!] DETECTED: File exists!\n");
            foundAny = true;
        }
        else {
            printf("File not found (Clean)\n");
        }
    }

    if (!foundAny) {
        printf("  [+] Result: No blacklisted drivers found.\n");
    }
    else {
        printf("  [!] Result: Virtualization drivers detected.\n");
    }
}

// -----------------------------------------------------------------------------------------
// T04: System Artifacts - Analysis Processes 
// Source: ayoubfaouzi/al-khaser/al-khaser/AntiAnalysis/process.cpp
// -----------------------------------------------------------------------------------------
DWORD GetProcessIdFromName(LPCTSTR szProcessName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD dwProcessId = 0;

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_tcsicmp(pe32.szExeFile, szProcessName) == 0) {
                    dwProcessId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return dwProcessId;
}

void t04_process_scan() {
    const TCHAR* szProcesses[] = {
        _T("vboxservice.exe"),
        _T("vboxtray.exe"),
        _T("vmtoolsd.exe"),
        _T("wireshark.exe"),
        _T("procmon.exe")
    };

    printf("[T04] Analysis Process Scan: Initiated\n");

    bool foundAny = false;

    for (int i = 0; i < 5; i++) {
        printf("  [-] Scanning for: %ls... ", szProcesses[i]);

        DWORD pid = GetProcessIdFromName(szProcesses[i]);

        if (pid != 0) {
            printf("\n      [!] DETECTED: Running at PID %lu\n", pid);
            foundAny = true;
        }
        else {
            printf("Not running\n");
        }
    }

    if (!foundAny) {
        printf("  [+] Result: No analysis processes found.\n");
    }
    else {
        printf("  [!] Result: Analysis tools detected.\n");
    }
}

// -----------------------------------------------------------------------------------------
// T05: System State - Process Count Check (< 15)
// Source: Generated (Missing from repos)
// -----------------------------------------------------------------------------------------
void t05_process_count_check() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    int count = 0;
    PROCESSENTRY32 pe32;

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                count++;
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    printf("[T05] Total Process Count: %d\n", count);
    if (count < 15) {
        printf("  [!] DETECTED: Suspiciously low process count (Sandbox)\n");
    }
    else {
        printf("  [+] Process count normal.\n");
    }
}

// -----------------------------------------------------------------------------------------
// T06: Timing - RDTSC Ratio Checks
// Source: Adapted from a0rtega/pafish/pafish/cpu.c (Converted to MSVC Intrinsics)
// -----------------------------------------------------------------------------------------
unsigned long long rdtsc_diff() {
    unsigned long long tsc1, tsc2;
    // __rdtsc() is the intrinsic for the RDTSC instruction
    int cpuInfo[4] = { -1 };
    tsc1 = __rdtsc();
    // A small operation could go here to measure latency, but pafish measures back-to-back overhead
    __cpuid(cpuInfo, 1);
    tsc2 = __rdtsc();
    return tsc2 - tsc1;
}

void t06_rdtsc_check() {
    unsigned long long avg = 0;
    for (int i = 0; i < 10; i++) {
        avg += rdtsc_diff();
        Sleep(10); // Standard Sleep to prevent strict racing
    }
    avg = avg / 10;

    printf("[T06] Average CPU Cycles for RDTSC: %llu\n", avg);

    // If the average cycle count is abnormally high (e.g. > 750 or 1000), it implies 
    // a hypervisor exit occurred during the instruction execution.
    // Note: Thresholds vary by CPU, but > 1000 is usually suspicious for bare RDTSC.
    if (avg > 750) {
        printf("  [!] DETECTED: High RDTSC latency indicates virtualization.\n");
    }
    else {
        printf("  [+] RDTSC latency normal.\n");
    }
}

// -----------------------------------------------------------------------------------------
// T07: Hardware Artifacts - Audio Device Check 
// Source: Generated (Missing from repos)
// -----------------------------------------------------------------------------------------
void t07_audio_device_check() {
    printf("[T07] Audio Device Check: Initiated\n");

    // Get the number of audio output devices
    UINT numDevs = waveOutGetNumDevs();
    printf("  [-] Total WaveOut Devices: %d\n", numDevs);

    if (numDevs == 0) {
        printf("  [!] DETECTED: No audio devices found (typical of sandboxes)\n");
    }
    else {
        // Iterate through devices to get their names (Capabilities)
        WAVEOUTCAPS caps;
        for (UINT i = 0; i < numDevs; i++) {
            if (waveOutGetDevCaps(i, &caps, sizeof(caps)) == MMSYSERR_NOERROR) {
                printf("      [+] Device %d: %ls\n", i, caps.szPname);
            }
            else {
                printf("      [?] Device %d: Unknown (Error retrieving caps)\n", i);
            }
        }
        printf("  [+] Result: Audio hardware is present.\n");
    }
}

// -----------------------------------------------------------------------------------------
// T08: System State - Screen Resolution Check
// Source: Generated (Missing from repos)
// -----------------------------------------------------------------------------------------
void t08_resolution_check() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    printf("[T08] Screen Resolution: %dx%d\n", width, height);

    // Common sandbox defaults: 800x600, 1024x768. 
    // Bare metal usually has higher resolutions (e.g. 1920x1080).
    if (width <= 1024 || height <= 768) {
        printf("  [!] DETECTED: Low screen resolution indicates VM/Sandbox\n");
    }
    else {
        printf("  [+] Screen resolution normal.\n");
    }
}

int main() {
    printf("=== Sandbox Detection Proof of Concept ===\n");
    printf("Target Platform: Windows 11\n\n");

    // T01
    if (cpu_hv()) {
        printf("[T01] CPUID Check: [!] Hypervisor Detected\n");
    }
    else {
        printf("[T01] CPUID Check: Clean\n");
    }

    // Run other checks
    t02_mac_check();
    t03_driver_files();
    t04_process_scan();
    t05_process_count_check();
    t06_rdtsc_check();
    t07_audio_device_check();
    t08_resolution_check();

    printf("\n=== Analysis Complete ===\n");
    printf("Press Enter to exit...");
    getchar();
    return 0;
}