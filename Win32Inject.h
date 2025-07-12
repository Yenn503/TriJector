#pragma once
#include "common.h"

BOOL FetchResourceWin32();
BOOL Win32Injection(
    _In_ CONST DWORD ProcessId,
    _In_ PBYTE Payload,
    _In_ CONST SIZE_T PayloadSize
);
