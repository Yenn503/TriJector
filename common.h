#pragma once
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// Helper macros for output
#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] " MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME, NTSTATUS_ERROR) \
    do { \
        fprintf(stderr, \
                "[!] [" FUNCTION_NAME "] [%s:%d] failed, error: 0x%lx\n", \
                __FILE__, __LINE__, NTSTATUS_ERROR); \
    } while (0)

// NT API Structures
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Common macros
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

BOOL FetchResourceWin32();
BOOL Win32Injection(
    _In_ CONST DWORD ProcessId,
    _In_ PBYTE Payload,
    _In_ CONST SIZE_T PayloadSize
);