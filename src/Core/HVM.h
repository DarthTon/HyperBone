#pragma once
#include <ntddk.h>

/// <summary>
/// Check if VT-x/AMD-V is supported
/// </summary>
/// <returns>TRUE if supported</returns>
BOOLEAN HvmIsHVSupported();

/// <summary>
/// CPU virtualization features
/// </summary>
VOID HvmCheckFeatures();

 /// <summary>
 /// Virtualize each CPU
 /// </summary>
 /// <returns>Status code</returns>
NTSTATUS StartHV();

/// <summary>
/// Devirtualize each CPU
/// </summary>
/// <returns>Status code</returns>
NTSTATUS StopHV();
