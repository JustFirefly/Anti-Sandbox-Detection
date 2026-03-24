#include <windows.h>
#include <stdio.h>

/*
 * DYNAMIC DLL INJECTOR
 * Starts a target process in a suspended state, injects a user-specified DLL,
 * and then resumes the process. This guarantees hooks are active before execution.
 */

int main(int argc, char* argv[]) {
    // Check if the user provided both required arguments
    if (argc < 3) {
        printf("Usage: injector.exe <path_to_target_exe> <path_to_dll>\n");
        printf("Example: injector.exe main.exe spoof_display.dll\n");
        return 1;
    }

    char* targetExe = argv[1];
    char* dllPath = argv[2]; // The dynamic DLL path from the command line

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    printf("[+] Launching target: %s\n", targetExe);
    printf("[+] Injecting DLL: %s\n", dllPath);

    // 1. Create the process in a SUSPENDED state (Crucial for early evasion)
    if (!CreateProcessA(NULL, targetExe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to start target EXE.\n");
        return 1;
    }

    // 2. Allocate memory inside the target process for the DLL path string
    LPVOID remoteBuf = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteBuf) {
        printf("[-] Failed to allocate memory in target process.\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    WriteProcessMemory(pi.hProcess, remoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL);

    // 3. Create a thread in the target process that calls 'LoadLibraryA'
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), 
        remoteBuf, 0, NULL);

    if (hThread) {
        printf("[+] Injection successful. Hooks placed.\n");
        
        // Wait for the DLL to finish loading
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    } else {
        printf("[-] Injection failed.\n");
    }

    // 4. Unfreeze the program now that our evasion DLL is inside
    printf("[+] Resuming target process execution...\n\n");
    ResumeThread(pi.hThread);

    // Wait for the target program to finish running before closing the injector
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
