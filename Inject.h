/*
--------------------------------------------------------------------------------------------
@Author: Yenn
@website:
--------------------------------------------------------------------------------------------
*/

#pragma once
#include "common.h"

// Global syscall numbers
extern DWORD g_NtOpenProcessSSN;
extern DWORD g_NtAllocateVirtualMemorySSN;
extern DWORD g_NtWriteVirtualMemorySSN;
extern DWORD g_NtProtectVirtualMemorySSN;
extern DWORD g_NtCreateThreadExSSN;
extern DWORD g_NtWaitForSingleObjectSSN;
extern DWORD g_NtFreeVirtualMemorySSN;
extern DWORD g_NtCloseSSN;

typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// Function declarations
extern NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);

extern NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

extern NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

extern NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

extern NTSTATUS NtWaitForSingleObject(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout
);

extern NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
);

extern NTSTATUS NtClose(
    IN HANDLE Handle
);

// Function declarations
VOID SyscallNumber(
    _In_ HMODULE NtdllHandle,
    _In_ LPCSTR NtFunctionName,
    _Out_ PDWORD SyscallNumber
);

BOOL DirectSyscalls(
    _In_ CONST DWORD PID,
    _In_ CONST PVOID Payloadbuffer,
    _In_ CONST DWORD PayloadSize
);

VOID PrintBanner(VOID);
BOOL FetchResource(VOID);



