#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <tchar.h>
#include <mmsystem.h> 
#include <intrin.h>   
#include <iphlpapi.h> 
#include <wininet.h>
#include <shlobj.h> 
#include <mmdeviceapi.h>
#include <functiondiscoverykeys_devpkey.h>
#include <initguid.h>
#include <propsys.h>

#pragma comment(lib, "ole32.lib") 
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")

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
    // Array of full absolute paths using TCHAR macros
    const TCHAR* szPaths[] = {
        // --- QEMU / KVM / VirtIO ---
        _T("C:\\WINDOWS\\system32\\drivers\\viostar.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\netktvm.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\balloon.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\qxl.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\qxlk.sys"),

        // --- Hyper-V ---
        _T("C:\\WINDOWS\\system32\\drivers\\vmbus.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\winhv.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmicvss.sys"),

        // --- VMware ---
        _T("C:\\WINDOWS\\system32\\drivers\\vmmouse.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmnet.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmci.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vm3dmp.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmxnet3.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\vmmemctl.sys"),

        // --- VirtualBox ---
        _T("C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\VBoxVideo.sys"),
        _T("C:\\WINDOWS\\system32\\drivers\\VBoxDrv.sys")
    };

    // Dynamically calculate the array size
    int numPaths = sizeof(szPaths) / sizeof(szPaths[0]);

    set_color(CYAN);
    printf("[T03] Driver File Check: Initiated\n");
    set_color(WHITE);

    bool foundAny = false;

    // Iterate and print status
    for (int i = 0; i < numPaths; i++) { 
        _tprintf(_T("  [-] Checking: %s... "), szPaths[i]);

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
}// -----------------------------------------------------------------------------------------
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

    for (int i = 0; i < 7; i++) {
        _tprintf("  [-] Scanning for: %s... ", szProcesses[i]);

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
// Source: (Missing from repos)
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
    if (count < 170) {
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
// Source: (Missing from repos)
// -----------------------------------------------------------------------------------------
EXTERN_C const PROPERTYKEY PKEY_Device_FriendlyName = { 
    { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } }, 
    14 
};
void t07_audio_device_check() {
    set_color(CYAN);
    printf("[T07] Audio Device Check: Initiated\n");
    set_color(WHITE);

    // Initialize the COM library
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr);

    IMMDeviceEnumerator *pEnum = NULL;
    hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pEnum);

    if (SUCCEEDED(hr)) {
        IMMDeviceCollection *pDevices = NULL;
        
        // eRender = Playback devices (Speakers/Headphones)
        // DEVICE_STATE_ACTIVE = Only devices that are actually plugged in and working
        hr = pEnum->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE, &pDevices);

        if (SUCCEEDED(hr)) {
            UINT count = 0;
            pDevices->GetCount(&count);
            printf("  [-] Total Active Audio Endpoints: %u\n", count);

            if (count == 0) {
                set_color(RED);
                printf("  [!] DETECTED: No active audio devices found (Sandbox)\n");
            } else {
                for (UINT i = 0; i < count; i++) {
                    IMMDevice *pDevice = NULL;
                    if (SUCCEEDED(pDevices->Item(i, &pDevice))) {
                        IPropertyStore *pStore = NULL;
                        if (SUCCEEDED(pDevice->OpenPropertyStore(STGM_READ, &pStore))) {
                            PROPVARIANT prop;
                            PropVariantInit(&prop);
                            
                            // Retrieve the full, untruncated Friendly Name
                            if (SUCCEEDED(pStore->GetValue(PKEY_Device_FriendlyName, &prop))) {
                                printf("      [+] Device %u: %ls\n", i, prop.pwszVal);
                                PropVariantClear(&prop);
                            }
                            pStore->Release();
                        }
                        pDevice->Release();
                    }
                }
                set_color(GREEN);
                printf("  [+] Result: Audio hardware is present.\n");
            }
            pDevices->Release();
        }
        pEnum->Release();
    } else {
        printf("  [-] Error: Failed to initialize MMDevice API.\n");
    }

    if (coInit) CoUninitialize();
    set_color(WHITE);
}// -----------------------------------------------------------------------------------------
// T08: System State - Screen Resolution Check
// Source: (Missing from repos)
// -----------------------------------------------------------------------------------------
void t08_resolution_check() {
    set_color(CYAN);
    printf("[T08] Active Hardware Signal Check: Initiated\n");
    set_color(WHITE);

    UINT32 numPathArrayElements = 0;
    UINT32 numModeInfoArrayElements = 0;

    // Get buffer sizes for active paths
    LONG result = GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS,
        &numPathArrayElements,
        &numModeInfoArrayElements);

    if (result != ERROR_SUCCESS) {
        printf("  [-] Error: Could not get display config buffer sizes.\n");
        return;
    }

    // Allocate the memory
    DISPLAYCONFIG_PATH_INFO* pathInfoArray = new DISPLAYCONFIG_PATH_INFO[numPathArrayElements];
    DISPLAYCONFIG_MODE_INFO* modeInfoArray = new DISPLAYCONFIG_MODE_INFO[numModeInfoArrayElements];

    // Query the actual display configuration mapped to the hardware
    result = QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS,
        &numPathArrayElements, pathInfoArray,
        &numModeInfoArrayElements, modeInfoArray,
        NULL);

    if (result == ERROR_SUCCESS) {
        bool signalFound = false;

        // Iterate through the modes to find the hardware target
        for (UINT32 i = 0; i < numModeInfoArrayElements; i++) {

            // We ONLY want the TARGET mode
            if (modeInfoArray[i].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_TARGET) {
                signalFound = true;
                DISPLAYCONFIG_VIDEO_SIGNAL_INFO signalInfo = modeInfoArray[i].targetMode.targetVideoSignalInfo;

                printf("  [-] Active Signal Resolution: %u x %u\n",
                    signalInfo.activeSize.cx,
                    signalInfo.activeSize.cy);

                if (signalInfo.vSyncFreq.Denominator != 0) {
                    double refreshRate = (double)signalInfo.vSyncFreq.Numerator / signalInfo.vSyncFreq.Denominator;
                    printf("  [-] Hardware Refresh Rate:  %.2f Hz\n", refreshRate);

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
    }
    else {
        printf("  [-] Error: QueryDisplayConfig failed.\n");
    }

    delete[] pathInfoArray;
    delete[] modeInfoArray;
    set_color(WHITE);
}

// -----------------------------------------------------------------------------------------
// T09: Network Artifacts - External IP / ISP Check
// Source: Adapted from Al-Khaser and MITRE T1497.001
// -----------------------------------------------------------------------------------------
void t09_network_check() {
    set_color(CYAN);
    printf("[T09] External Network Check: Initiated\n");
    set_color(WHITE);

    HINTERNET hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        set_color(RED);
        printf("  [!] Failed to open internet handle. Assuming isolated sandbox.\n");
        set_color(WHITE);
        return;
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, "http://ip-api.com/line/?fields=isp,org,as", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        set_color(RED);
        printf("  [!] Failed to connect to internet. Assuming isolated sandbox.\n");
        set_color(WHITE);
        InternetCloseHandle(hInternet);
        return;
    }

    char buffer[1024];
    DWORD bytesRead;
    std::string response = "";

    while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (response.empty()) {
        set_color(RED);
        printf("  [!] Empty response from network check. Assuming sandboxed connection.\n");
        set_color(WHITE);
        return;
    }

    // Convert to lowercase for checking
    std::string lowerResponse = response;
    for (auto& c : lowerResponse) c = tolower(c);

    const char* blocklist[] = {
        "amazon", "aws", "microsoft", "azure", "google", "gcp",
        "digitalocean", "ovh", "choopa", "linode", "university",
        "cisco", "fireeye", "fortinet", "palo alto", "hetzner"
    };

    bool detected = false;
    for (const char* blocked : blocklist) {
        if (lowerResponse.find(blocked) != std::string::npos) {
            set_color(RED);
            printf("  [!] DETECTED: Datacenter/Cloud/Analysis ISP found: %s\n", blocked);
            detected = true;
            break;
        }
    }

    if (!detected) {
        set_color(GREEN);
        printf("  [+] Residential/Safe Network Detected.\n");
    }

    // Clean up response for clean printing (removing potential newlines)
    while (!response.empty() && (response.back() == '\n' || response.back() == '\r')) {
        response.pop_back();
    }

    printf("      [-] ISP Info: %s\n", response.c_str());
    set_color(WHITE);
}

// -----------------------------------------------------------------------------------------
// T10: Human-Like Behaviour - Recent Files Check
// Source: Adapted from Check Point Evasions (https://evasions.checkpoint.com/src/Evasions/techniques/human-like-behavior.html#human-like-behavior-detection-methods)
// -----------------------------------------------------------------------------------------
void t10_human_behavior_check() {
    set_color(CYAN);
    printf("[T10] Human-Like Behaviour Check: Initiated\n");
    set_color(WHITE);

    char recentPath[MAX_PATH];
    // Retrieve the path to the current user's "Recent" directory
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath))) {
        std::string searchPath = std::string(recentPath) + "\\*";
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

        int fileCount = 0;
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                // Skip the standard directory artifacts "." and ".."
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    fileCount++;
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }

        printf("  [-] Recent Files Count: %d\n", fileCount);

        if (fileCount < 15) {
            set_color(RED);
            printf("  [!] DETECTED: Sterile environment (No recent user activity).\n");
        }
        else {
            set_color(GREEN);
            printf("  [+] Human user verified (Recent activity found).\n");
        }
    }
    else {
        set_color(RED);
        printf("  [-] Error: Could not resolve Recent folder path.\n");
    }
    set_color(WHITE);
}

int main(int argc, char* argv[]) {
    set_color(YELLOW);
    printf("=== Sandbox Detection Proof of Concept ===\n");
    printf("Target Platform: Windows 11\n\n");
    set_color(WHITE);

    bool run_t01 = false, run_t02 = false, run_t03 = false, run_t04 = false;
    bool run_t05 = false, run_t06 = false, run_t07 = false, run_t08 = false;
    bool run_t09 = false, run_t10 = false;

    if (argc == 1) {
        run_t01 = run_t02 = run_t03 = run_t04 = run_t05 = run_t06 = run_t07 = run_t08 = run_t09 = run_t10 = true;
    }
    else {
        for (int i = 1; i < argc; i++) {
            if (_stricmp(argv[i], "all") == 0 || _stricmp(argv[i], "-all") == 0) {
                run_t01 = run_t02 = run_t03 = run_t04 = run_t05 = run_t06 = run_t07 = run_t08 = run_t09 = run_t10 = true;
            }
            else if (_stricmp(argv[i], "t01") == 0 || _stricmp(argv[i], "-t01") == 0) run_t01 = true;
            else if (_stricmp(argv[i], "t02") == 0 || _stricmp(argv[i], "-t02") == 0) run_t02 = true;
            else if (_stricmp(argv[i], "t03") == 0 || _stricmp(argv[i], "-t03") == 0) run_t03 = true;
            else if (_stricmp(argv[i], "t04") == 0 || _stricmp(argv[i], "-t04") == 0) run_t04 = true;
            else if (_stricmp(argv[i], "t05") == 0 || _stricmp(argv[i], "-t05") == 0) run_t05 = true;
            else if (_stricmp(argv[i], "t06") == 0 || _stricmp(argv[i], "-t06") == 0) run_t06 = true;
            else if (_stricmp(argv[i], "t07") == 0 || _stricmp(argv[i], "-t07") == 0) run_t07 = true;
            else if (_stricmp(argv[i], "t08") == 0 || _stricmp(argv[i], "-t08") == 0) run_t08 = true;
            else if (_stricmp(argv[i], "t09") == 0 || _stricmp(argv[i], "-t09") == 0) run_t09 = true;
            else if (_stricmp(argv[i], "t10") == 0 || _stricmp(argv[i], "-t10") == 0) run_t10 = true;
        }
    }

    if (run_t01) {
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
    }

    if (run_t02) t02_mac_check();
    if (run_t03) t03_driver_files();
    if (run_t04) t04_process_scan();
    if (run_t05) t05_process_count_check();
    if (run_t06) t06_rdtsc_check();
    if (run_t07) t07_audio_device_check();
    if (run_t08) t08_resolution_check();
    if (run_t09) t09_network_check();
    if (run_t10) t10_human_behavior_check();

    set_color(YELLOW);
    printf("\n=== Analysis Complete ===\n");
    set_color(WHITE);

    if (argc == 1) {
        printf("Press Enter to exit...");
        getchar();
    }

    return 0;
}
