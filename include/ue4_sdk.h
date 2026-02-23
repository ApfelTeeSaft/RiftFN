#pragma once

#include "globals.h"
#include <string>

namespace UE4 {
    // Get GWorld pointer value
    // Dereferences the resolved GWorld address
    UWorld* GetWorld();

    // Call ProcessEvent on a UObject
    // Original: Globals::qword_18004FDE8(object, function, params, 0)
    void ProcessEvent(UObject* object, UFunction* function, void* params);

    // Convert FName to std::string
    // Calls the resolved FNameToString function pointer (qword_18004FDC8)
    // then narrows the result from wchar_t to char via sub_180005030
    std::string FNameToString(int nameIndex);

    // Get the name string of a UObject at the given address
    // Reads FName at object + 24, calls FNameToString, and narrows
    // Used internally by GObjects search functions
    std::string GetObjectName(__int64 objectPtr);

    // Find a UObject by name in GObjects array
    // Original: sub_1800072D0 - uses PatternLink type byte to dispatch:
    //   type 1 -> sub_1800056F0 (linear GObjects array, 24-byte stride)
    //   type 2 -> sub_180006450 (chunked GObjects array via sub_1800063A0)
    __int64 StaticFindObject(const char* name);

    // Find property offset from class + property name pair
    // Original: sub_180007790 - uses PatternLink type to dispatch:
    //   type 1 -> sub_180005F70 (linear iteration, offset at +68)
    //   type 2 -> sub_180006CA0 (chunked iteration or property chain walk)
    // Returns: byte offset of the property within the class (from UProperty + 68 or + 76)
    int FindPropertyOffset(const char* className, const char* propertyName);

    // Initialize console and viewport setup
    // Original: sub_18000E8A0
    // Navigates: World -> OwningGameInstance -> GameInstance -> LocalPlayers
    //            -> LocalPlayer -> ViewportClient
    // Then creates Console object and assigns it to ViewportConsole
    unsigned int InitConsoleAndViewport();

    // Initialize UE4 SDK (resolve all property offsets)
    // Corresponds to sub_180007CB0
    void InitializeSDK();
}
