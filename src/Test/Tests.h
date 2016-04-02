#pragma once
#include <ntdef.h>

VOID TestStart( IN BOOLEAN SyscallHook, IN BOOLEAN PageHook1, IN IN BOOLEAN PageHook2 );
VOID TestStop();
VOID TestPrintResults();