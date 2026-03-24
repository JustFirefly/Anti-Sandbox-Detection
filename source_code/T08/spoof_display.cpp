#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Function signature for QueryDisplayConfig
typedef LONG (WINAPI *PQUERY_DISPLAY_CONFIG)(
    UINT32 flags, UINT32* numPathArrayElements, DISPLAYCONFIG_PATH_INFO* pathInfoArray,
    UINT32* numModeInfoArrayElements, DISPLAYCONFIG_MODE_INFO* modeInfoArray,
    DISPLAYCONFIG_TOPOLOGY_ID* currentTopologyId
);

// Global variables for our inline hook
void* pOrigFunc = NULL;
BYTE originalBytes[12];
BYTE hookBytes[12] = {
    0x48, 0xB8,                   // mov rax, [8-byte address]
    0x00, 0x00, 0x00, 0x00,       // -- Address placeholder --
    0x00, 0x00, 0x00, 0x00,       // -- Address placeholder --
    0xFF, 0xE0                    // jmp rax
};

// Helper: Overwrite memory with our JMP instruction
void InstallHook() {
    if (pOrigFunc) {
        DWORD oldProtect;
        VirtualProtect(pOrigFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pOrigFunc, hookBytes, 12);
        VirtualProtect(pOrigFunc, 12, oldProtect, &oldProtect);
    }
}

// Helper: Restore original memory
void RemoveHook() {
    if (pOrigFunc) {
        DWORD oldProtect;
        VirtualProtect(pOrigFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pOrigFunc, originalBytes, 12);
        VirtualProtect(pOrigFunc, 12, oldProtect, &oldProtect);
    }
}

// Our Malicious Faked Function
LONG WINAPI HookedQueryDisplayConfig(
    UINT32 flags, UINT32* numPathArrayElements, DISPLAYCONFIG_PATH_INFO* pathInfoArray,
    UINT32* numModeInfoArrayElements, DISPLAYCONFIG_MODE_INFO* modeInfoArray, DISPLAYCONFIG_TOPOLOGY_ID* currentTopologyId) 
{
    // 1. Unhook so we can call the real API without creating an infinite loop
    RemoveHook();

    // 2. Call the real Windows API
    PQUERY_DISPLAY_CONFIG orig = (PQUERY_DISPLAY_CONFIG)pOrigFunc;
    LONG result = orig(flags, numPathArrayElements, pathInfoArray, numModeInfoArrayElements, modeInfoArray, currentTopologyId);

    // 3. Tamper with the results if successful
    if (result == ERROR_SUCCESS && modeInfoArray != NULL) {
        for (UINT32 i = 0; i < *numModeInfoArrayElements; i++) {
            if (modeInfoArray[i].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_TARGET) {
                
                // Spoof Resolution
                modeInfoArray[i].targetMode.targetVideoSignalInfo.activeSize.cx = 1920;
                modeInfoArray[i].targetMode.targetVideoSignalInfo.activeSize.cy = 1080;
                
                // Spoof Refresh Rate to 60Hz (60000 / 1000)
                modeInfoArray[i].targetMode.targetVideoSignalInfo.vSyncFreq.Numerator = 60000;
                modeInfoArray[i].targetMode.targetVideoSignalInfo.vSyncFreq.Denominator = 1000;
                
                printf("[Hook] Intercepted QueryDisplayConfig! Spoofed 1920x1080 @ 60Hz.\n");
            }
        }
    }

    // 4. Re-install the hook before returning
    InstallHook();
    return result;
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        
        // Ensure User32 is loaded
        HMODULE hUser32 = LoadLibraryA("user32.dll");
        pOrigFunc = (void*)GetProcAddress(hUser32, "QueryDisplayConfig");

        if (pOrigFunc) {
            // Backup the original 12 bytes of the function
            memcpy(originalBytes, pOrigFunc, 12);

            // Insert the address of our fake function into the assembly payload
            void* hookAddr = (void*)&HookedQueryDisplayConfig;
            memcpy(&hookBytes[2], &hookAddr, 8);

            // Apply the hook
            InstallHook();
            printf("[PoC] Display Spoofing DLL Loaded and Hook Installed!\n");
        } else {
            printf("[PoC] Failed to find QueryDisplayConfig in memory.\n");
        }
    }
    return TRUE;
}
