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
#pragma comment(lib, "Advapi32.lib")

// --- Color Helper ---
enum ConsoleColor {
    GREEN = 10,
    RED = 12,
    CYAN = 11,
    WHITE = 15,
    YELLOW = 14
};

void set_color(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

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
    set_color(CYAN);
    printf("[T02] MAC Address Check: Initiated\n");
    set_color(WHITE);

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
        { {0x08, 0x00, 0x27}, "VirtualBox" },
        { {0x52, 0x54, 0x00}, "QEMU/KVM" }
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

                    set_color(RED);
                    printf("  [!] DETECTED: Known Virtualization Vendor MAC (%s)\n", entry.vendor);
                    set_color(WHITE);
                    found = true;
                }
            }
            pAdapter = pAdapter->Next;
        }

        if (!found) {
            set_color(GREEN);
            printf("  [+] No blacklisted MAC addresses found.\n");
            set_color(WHITE);
        }
    }
    else {
        set_color(RED);
        printf("  [!] Error: Failed to get adapter info.\n");
        set_color(WHITE);
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
        _T("C:\\WINDOWS\\system32\\drivers\\vmci.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\viostar.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\netktvm.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\balloon.sys")
    };

    set_color(CYAN);
    printf("[T03] Driver File Check: Initiated\n");
    set_color(WHITE);

    bool foundAny = false;

    // Iterate and print status for EVERY file
    for (int i = 0; i < 8; i++) { // Fixed loop count to match array size
        printf("  [-] Checking: %ls... ", szPaths[i]);

        if (is_FileExists(szPaths[i])) {
            set_color(RED);
            printf("\n      [!] DETECTED: File exists!\n");
            set_color(WHITE);
            foundAny = true;
        }
        else {
            printf("File not found (Clean)\n");
        }
    }

    if (!foundAny) {
        set_color(GREEN);
        printf("  [+] Result: No blacklisted drivers found.\n");
    }
    else {
        set_color(RED);
        printf("  [!] Result: Virtualization drivers detected.\n");
    }
    set_color(WHITE);
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
        _T("procmon.exe"),
        _T("qemu-ga.exe"),
        _T("spice-vdagent.exe")
    };

    set_color(CYAN);
    printf("[T04] Analysis Process Scan: Initiated\n");
    set_color(WHITE);

    bool foundAny = false;

    for (int i = 0; i < 7; i++) { // Fixed loop count to match array size
        printf("  [-] Scanning for: %ls... ", szProcesses[i]);

        DWORD pid = GetProcessIdFromName(szProcesses[i]);

        if (pid != 0) {
            set_color(RED);
            printf("\n      [!] DETECTED: Running at PID %lu\n", pid);
            set_color(WHITE);
            foundAny = true;
        }
        else {
            printf("Not running\n");
        }
    }

    if (!foundAny) {
        set_color(GREEN);
        printf("  [+] Result: No analysis processes found.\n");
    }
    else {
        set_color(RED);
        printf("  [!] Result: Analysis tools detected.\n");
    }
    set_color(WHITE);
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

    set_color(CYAN);
    printf("[T05] Total Process Count: %d\n", count);
    if (count < 15) {
        set_color(RED);
        printf("  [!] DETECTED: Suspiciously low process count (Sandbox)\n");
    }
    else {
        set_color(GREEN);
        printf("  [+] Process count normal.\n");
    }
    set_color(WHITE);
}

// -----------------------------------------------------------------------------------------
// T06: Timing - RDTSC Ratio Checks
// Source: Adapted from a0rtega/pafish/pafish/cpu.c (Converted to MSVC Intrinsics)
// -----------------------------------------------------------------------------------------
unsigned long long rdtsc_diff() {
    unsigned long long tsc1, tsc2;
    int cpuInfo[4] = { -1 };
    tsc1 = __rdtsc();
    __cpuid(cpuInfo, 1);
    tsc2 = __rdtsc();
    return tsc2 - tsc1;
}

void t06_rdtsc_check() {
    unsigned long long avg = 0;
    for (int i = 0; i < 10; i++) {
        avg += rdtsc_diff();
        Sleep(10); 
    }
    avg = avg / 10;

    set_color(CYAN);
    printf("[T06] Average CPU Cycles for RDTSC: %llu\n", avg);

    if (avg > 750) {
        set_color(RED);
        printf("  [!] DETECTED: High RDTSC latency indicates virtualization.\n");
    }
    else {
        set_color(GREEN);
        printf("  [+] RDTSC latency normal.\n");
    }
    set_color(WHITE);
}

// -----------------------------------------------------------------------------------------
// T07: Hardware Artifacts - Audio Device Check 
// Source: Generated (Missing from repos)
// -----------------------------------------------------------------------------------------
void t07_audio_device_check() {
    set_color(CYAN);
    printf("[T07] Audio Device Check: Initiated\n");
    set_color(WHITE);

    UINT numDevs = waveOutGetNumDevs();
    printf("  [-] Total WaveOut Devices: %d\n", numDevs);

    if (numDevs == 0) {
        set_color(RED);
        printf("  [!] DETECTED: No audio devices found (typical of sandboxes)\n");
    }
    else {
        WAVEOUTCAPS caps;
        for (UINT i = 0; i < numDevs; i++) {
            if (waveOutGetDevCaps(i, &caps, sizeof(caps)) == MMSYSERR_NOERROR) {
                printf("      [+] Device %d: %ls\n", i, caps.szPname);
            }
            else {
                printf("      [?] Device %d: Unknown (Error retrieving caps)\n", i);
            }
        }
        set_color(GREEN);
        printf("  [+] Result: Audio hardware is present.\n");
    }
    set_color(WHITE);
}

// -----------------------------------------------------------------------------------------
// T08: System State - Screen Resolution Check
// Source: Generated (Missing from repos)
// -----------------------------------------------------------------------------------------
void t08_resolution_check() {
printf("[T08] Active Hardware Signal Check: Initiated\n");

    UINT32 numPathArrayElements = 0;
    UINT32 numModeInfoArrayElements = 0;

    // 1. Ask Windows how much memory we need to store the current display paths
    LONG result = GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, 
                                              &numPathArrayElements, 
                                              &numModeInfoArrayElements);
    
    if (result != ERROR_SUCCESS) {
        printf("  [-] Error: Could not get display config buffer sizes.\n");
        return;
    }

    // 2. Allocate the memory
    DISPLAYCONFIG_PATH_INFO* pathInfoArray = new DISPLAYCONFIG_PATH_INFO[numPathArrayElements];
    DISPLAYCONFIG_MODE_INFO* modeInfoArray = new DISPLAYCONFIG_MODE_INFO[numModeInfoArrayElements];

    // 3. Query the actual display configuration mapped to the hardware
    result = QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS,
                                &numPathArrayElements, pathInfoArray,
                                &numModeInfoArrayElements, modeInfoArray,
                                NULL);

    if (result == ERROR_SUCCESS) {
        bool signalFound = false;

        // Iterate through the modes to find the hardware target
        for (UINT32 i = 0; i < numModeInfoArrayElements; i++) {
            
            // We ONLY want the TARGET mode (the hardware signal leaving the port).
            // SOURCE mode is the logical Windows desktop.
            if (modeInfoArray[i].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_TARGET) {
                signalFound = true;
                DISPLAYCONFIG_VIDEO_SIGNAL_INFO signalInfo = modeInfoArray[i].targetMode.targetVideoSignalInfo;

                printf("  [-] Active Signal Resolution: %u x %u\n", 
                       signalInfo.activeSize.cx, 
                       signalInfo.activeSize.cy);

                // Hardware refresh rates are stored as a fraction (Numerator / Denominator)
                // e.g., 60000 / 1000 = 60Hz. Or 59940 / 1000 = 59.94Hz.
                if (signalInfo.vSyncFreq.Denominator != 0) {
                    double refreshRate = (double)signalInfo.vSyncFreq.Numerator / signalInfo.vSyncFreq.Denominator;
                    printf("  [-] Hardware Refresh Rate:  %.2f Hz\n", refreshRate);

                    // --- Sandbox Detection Logic ---
                    // VirtualBox and QEMU often default to weird flat refresh rates 
                    // or low active signals regardless of what the Windows desktop is set to.
                    if (refreshRate == 0.0 || refreshRate < 50.0) {
                         set_color(RED);
			    printf("      [!] DETECTED: Suspicious hardware refresh rate (Virtual Display).\n");
                    }
                }
            }
        }
        
        if (!signalFound) {
            set_color(YELLOW);
		printf("  [!] DETECTED: No hardware target mode found (Headless/Virtual).\n");
        }
    } else {
        printf("  [-] Error: QueryDisplayConfig failed.\n");
    }

    // Clean up
    delete[] pathInfoArray;
    delete[] modeInfoArray;
    set_color(WHITE);
}

int main() {
    set_color(YELLOW);
    printf("=== Sandbox Detection Proof of Concept ===\n");
    printf("Target Platform: Windows 11\n\n");
    set_color(WHITE);

    // T01
    set_color(CYAN);
    printf("[T01] CPUID Check: ");
    if (cpu_hv()) {
        set_color(RED);
        printf("[!] Hypervisor Detected\n");
    }
    else {
        set_color(GREEN);
        printf("Clean\n");
    }
    set_color(WHITE);

    // Run other checks
    t02_mac_check();
    t03_driver_files();
    t04_process_scan();
    t05_process_count_check();
    t06_rdtsc_check();
    t07_audio_device_check();
    t08_resolution_check();

    set_color(YELLOW);
    printf("\n=== Analysis Complete ===\n");
    set_color(WHITE);
    printf("Press Enter to exit...");
    getchar();
    return 0;
}
