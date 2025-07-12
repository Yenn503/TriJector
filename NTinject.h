#pragma once
#include "common.h"

// Function type definitions for NT APIs
typedef NTSTATUS(NTAPI* function_NtOpenProcess)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* function_NtAllocateVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

typedef NTSTATUS(NTAPI* function_NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(NTAPI* function_NtProtectVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

typedef NTSTATUS(NTAPI* function_NtCreateThreadEx)(
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
    IN PVOID AttributeList OPTIONAL);

typedef NTSTATUS(NTAPI* function_NtWaitForSingleObject)(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL);

typedef NTSTATUS(NTAPI* function_NtFreeVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType);

typedef NTSTATUS(NTAPI* function_NtClose)(
    IN HANDLE Handle);

// Function declarations
UINT_PTR GetNativeFunctionAddress(
    _In_ HMODULE NtdllHandle,
    _In_ LPCSTR NtFunctionName);

BOOL FetchResourceNTAPI(VOID);

BOOL NTAPIinjector(
    _In_ CONST DWORD ProcessId,
    _In_ LPCSTR Payload,
    _In_ CONST SIZE_T PayloadSize);

