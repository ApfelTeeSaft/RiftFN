/*
 * Rift DLL - Unreal Engine 4 SDK Interaction Layer
 *
 * Provides access to UE4 internals via resolved pattern addresses.
 *
 * Original functions:
 *   sub_1800072D0 (StaticFindObject)    - Find UObject by name, dispatches to type 1/2
 *   sub_180007790 (FindPropertyOffset)  - Find property offset by class+name, dispatches
 *   sub_1800056F0 (FindObjectType1)     - Linear GObjects iteration (type 1)
 *   sub_180006450 (FindObjectType2)     - Chunked GObjects iteration (type 2)
 *   sub_1800063A0 (ChunkedArrayAccess)  - Chunked array element accessor
 *   sub_180005F70 (FindPropertyType1)   - Property offset search (type 1, linear)
 *   sub_180006CA0 (FindPropertyType2)   - Property offset search (type 2, chunked/chain)
 *   sub_18000E8A0 (InitConsoleAndViewport) - Console/Viewport initialization
 *   sub_180007CB0 (InitializeSDK)       - Full property offset resolution
 *
 * The PatternLink structure (at qword_18004FDF0) controls dispatch:
 *   byte 0:   type (1 = old engine layout, 2 = new engine layout)
 *   bytes 8-15: GObjects base address
 *
 * UObject layout (both types):
 *   +0x00  vtable
 *   +0x08  ObjectFlags
 *   +0x0C  InternalIndex
 *   +0x10  ClassPrivate
 *   +0x18  NamePrivate (FName, 8 bytes)
 *   +0x20  OuterPrivate (UObject*)
 *
 * Type 1 GObjects array (older UE4):
 *   base+0:   QWORD* array pointer (elements at 24-byte stride)
 *   base+12:  int32 count
 *
 * Type 2 GObjects array (newer UE4):
 *   base+0:   QWORD** chunk pointer array (each chunk holds up to 0xFFFF objects)
 *   base+20:  int32 count
 *
 * UProperty offset field:
 *   +0x44 (68) for older UE4 (type 1 and type 2 with version < 11794982)
 *   +0x4C (76) for newer UE4 (type 2 with version >= 11794982, via property chain)
 */

#include "ue4_sdk.h"
#include "string_utils.h"
#include <cstring>
#include <cwchar>

namespace UE4 {

// ============================================================================
// Internal constants matching UE4 object layout from IDA analysis
// ============================================================================

// UObject field offsets
static constexpr int FNAME_OFFSET = 24;          // FName at UObject + 0x18
static constexpr int OUTER_OFFSET = 32;           // Outer at UObject + 0x20

// Type 1 array layout
static constexpr int TYPE1_COUNT_OFFSET = 12;     // *(int*)(base + 12)
static constexpr int TYPE1_ELEMENT_STRIDE = 24;   // 24 bytes per element slot

// Type 2 array layout
static constexpr int TYPE2_COUNT_OFFSET = 20;     // *(int*)(base + 20)
static constexpr int TYPE2_CHUNK_SIZE = 0xFFFF;   // Max objects per chunk

// Property offset field within UProperty
static constexpr int PROP_OFFSET_FIELD = 68;      // 0x44 - Offset_Internal

// Newer UE4 property chain layout (version >= 11794982)
static constexpr int CLASS_PROPLINK_OFFSET = 80;   // UStruct::PropertyLink at +0x50
static constexpr int PROP_NEXT_OFFSET = 32;        // Property chain next ptr at +0x20
static constexpr int PROP_NAME_OFFSET_NEW = 40;    // FName in property chain at +0x28
static constexpr int PROP_OFFSET_FIELD_NEW = 76;   // 0x4C - Offset in property chain

// Version threshold for newer property chain walk
static constexpr int VERSION_PROPCHAIN = 11794982;

// ============================================================================
// Internal helper: Get name string from a UObject
// ============================================================================

// Reads FName at objectPtr + offset, calls the resolved FNameToString function
// pointer (qword_18004FDC8), then narrows the wide string result.
//
// Original pattern:
//   v20 = *(_QWORD *)(object + 24);
//   v21[0] = 0; v21[1] = 0;
//   qword_18004FDC8(&v20, v21);
//   if (v21[0]) sub_180005030(v21, output);
static std::string GetNameAtOffset(__int64 objectPtr, int offset)
{
    if (!objectPtr || !Globals::qword_18004FDC8)
        return "";

    // Read FName value (8 bytes at the given offset)
    __int64 fname = *reinterpret_cast<__int64*>(objectPtr + offset);

    // FString output: { wchar_t* Data, int32 Num+Max packed }
    __int64 fstringBuf[2] = {0, 0};

    // Call the resolved FNameToString function
    auto fnameToStr = reinterpret_cast<void(__fastcall*)(__int64*, __int64*)>(
        Globals::qword_18004FDC8);
    fnameToStr(&fname, fstringBuf);

    // If no data returned, return empty string
    // (original falls through to sub_180030850 to create empty std::string)
    if (!fstringBuf[0])
        return "";

    // Convert wide string to narrow
    // fstringBuf[0] = wchar_t* pointer to the name data
    const wchar_t* wdata = reinterpret_cast<const wchar_t*>(fstringBuf[0]);
    size_t wlen = wcslen(wdata);
    return StringUtils::WideToNarrow(wdata, wlen);
}

// ============================================================================
// GObjects search: Type 1 - Linear array (sub_1800056F0)
// ============================================================================
//
// Original: sub_1800056F0(__int64 gobjectsBase, _QWORD* targetName)
// Iterates a flat array of object pointers with 24-byte stride.
// Array pointer at *(QWORD*)gobjectsBase, count at *(int*)(gobjectsBase + 12).
// For each non-null object, gets FName at +24, converts to string, compares.
// Returns matching object pointer or 0.

static __int64 FindObjectType1(__int64 gobjectsBase, const std::string& name)
{
    int count = *reinterpret_cast<int*>(gobjectsBase + TYPE1_COUNT_OFFSET);
    if (count <= 0)
        return 0;

    __int64 arrayPtr = *reinterpret_cast<__int64*>(gobjectsBase);

    for (int i = 0; i < count; ++i)
    {
        __int64 obj = *reinterpret_cast<__int64*>(
            arrayPtr + static_cast<__int64>(i) * TYPE1_ELEMENT_STRIDE);
        if (!obj)
            continue;

        std::string objName = GetNameAtOffset(obj, FNAME_OFFSET);
        if (objName == name)
            return obj;
    }

    return 0;
}

// ============================================================================
// Chunked array accessor (sub_1800063A0)
// ============================================================================
//
// Original: sub_1800063A0(_QWORD* arrayBase, int index)
// The GObjects array in newer UE4 is organized as an array of chunk pointers.
// Each chunk holds up to 0xFFFF (65535) objects at 24-byte stride.
// Some leading chunks may be null (skipped).
//
// Algorithm:
//   1. Find first non-null chunk pointer
//   2. Count valid (non-null) chunk pointers
//   3. Calculate chunk index = index / 0xFFFF
//   4. Edge case: if index is exact multiple of 0xFFFF, use previous chunk
//   5. Access: chunks[firstValid + chunkIdx] + 24 * (index - 0xFFFF * chunkIdx)

static __int64 ChunkedArrayAccess(__int64 arrayBase, int index)
{
    __int64* chunks = *reinterpret_cast<__int64**>(arrayBase);

    // Find first non-null chunk
    int firstValid = 0;
    if (!chunks[0])
    {
        do {
            ++firstValid;
        } while (!chunks[firstValid]);
    }

    // Count total valid chunks (from firstValid until we hit null again)
    int lastValid = firstValid;
    while (chunks[lastValid])
        ++lastValid;

    // Calculate chunk index and within-chunk offset
    int chunkIdx = index / TYPE2_CHUNK_SIZE;
    int chunkBase = TYPE2_CHUNK_SIZE * chunkIdx;
    if (chunkBase && chunkBase == index)
        --chunkIdx;

    // Bounds check
    if (firstValid + chunkIdx >= lastValid)
        return 0;

    // Access the element: chunk pointer + 24 * (index - chunkBase)
    __int64 chunkPtr = chunks[firstValid + chunkIdx];
    int withinChunk = index - TYPE2_CHUNK_SIZE * chunkIdx;
    return *reinterpret_cast<__int64*>(
        chunkPtr + static_cast<__int64>(withinChunk) * TYPE1_ELEMENT_STRIDE);
}

// ============================================================================
// GObjects search: Type 2 - Chunked array (sub_180006450)
// ============================================================================
//
// Original: sub_180006450(__int64 gobjectsBase, _QWORD* targetName)
// Same algorithm as Type 1 but uses ChunkedArrayAccess (sub_1800063A0)
// instead of direct pointer arithmetic.
// Count at *(int*)(gobjectsBase + 20).

static __int64 FindObjectType2(__int64 gobjectsBase, const std::string& name)
{
    int count = *reinterpret_cast<int*>(gobjectsBase + TYPE2_COUNT_OFFSET);
    if (count <= 0)
        return 0;

    for (int i = 0; i < count; ++i)
    {
        __int64 obj = ChunkedArrayAccess(gobjectsBase, i);
        if (!obj)
            continue;

        std::string objName = GetNameAtOffset(obj, FNAME_OFFSET);
        if (objName == name)
            return obj;
    }

    return 0;
}

// ============================================================================
// FindPropertyOffset: Type 1 - Linear search (sub_180005F70)
// ============================================================================
//
// Original: sub_180005F70(__int64 gobjectsBase, _QWORD* className, _QWORD* propName)
// Iterates GObjects linearly looking for a property matching propName.
// When found, follows the Outer pointer (object + 32) to get the owning class,
// reads the class name at +24, and compares with className.
// Returns *(DWORD*)(property + 68) - the Offset_Internal field.
//
// Algorithm:
//   for each object in GObjects (24-byte stride):
//     if object.name == propName:
//       classObj = *(QWORD*)(object + 32)  // Outer
//       if classObj.name == className:
//         return *(int*)(object + 68)       // Offset_Internal
//   return 0

static int FindPropertyType1(__int64 gobjectsBase,
                              const std::string& className,
                              const std::string& propName)
{
    int count = *reinterpret_cast<int*>(gobjectsBase + TYPE1_COUNT_OFFSET);
    if (count <= 0)
        return 0;

    __int64 arrayPtr = *reinterpret_cast<__int64*>(gobjectsBase);

    for (int i = 0; i < count; ++i)
    {
        __int64 obj = *reinterpret_cast<__int64*>(
            arrayPtr + static_cast<__int64>(i) * TYPE1_ELEMENT_STRIDE);
        if (!obj)
            continue;

        // Check if this object's name matches the property name
        std::string objName = GetNameAtOffset(obj, FNAME_OFFSET);
        if (objName != propName)
            continue;

        // Match found - check the owning class name
        // Follow Outer pointer at +32 to get class object,
        // then get class name at +24 from that object
        // Original: v46 = *(_QWORD *)(*(_QWORD *)(v8 + 32) + 24LL)
        __int64 outerObj = *reinterpret_cast<__int64*>(obj + OUTER_OFFSET);
        if (!outerObj)
            continue;

        std::string outerName = GetNameAtOffset(outerObj, FNAME_OFFSET);
        if (outerName == className)
        {
            // Return the Offset_Internal field at UProperty + 68
            return *reinterpret_cast<int*>(obj + PROP_OFFSET_FIELD);
        }
    }

    return 0;
}

// ============================================================================
// FindPropertyOffset: Type 2 - Chunked search (sub_180006CA0)
// ============================================================================
//
// Original: sub_180006CA0(__int64 gobjectsBase, unsigned __int64* className,
//                         _QWORD** propName)
//
// Two code paths based on engine version:
//
// 1. Version < 11794982:
//    Same as Type 1 but uses ChunkedArrayAccess for iteration.
//    Property offset at UProperty + 68 (0x44).
//
// 2. Version >= 11794982:
//    First finds the CLASS object in GObjects by name (via sub_180006450).
//    Then walks the property linked list:
//      - Start: *(QWORD*)(classObj + 80) = UStruct::PropertyLink
//      - Each property: name at +40, offset at +76, next at +32
//      - Uses IsBadReadPtr for safety checks
//    This path handles newer UE4 where properties are accessed via
//    the class's property chain rather than by searching all objects.

static int FindPropertyType2(__int64 gobjectsBase,
                              const std::string& className,
                              const std::string& propName)
{
    int version = Globals::dword_18004FDE0;

    if (version < VERSION_PROPCHAIN)
    {
        // Older path: iterate all objects via chunked array
        int count = *reinterpret_cast<int*>(gobjectsBase + TYPE2_COUNT_OFFSET);
        if (count <= 0)
            return 0;

        for (int i = 0; i < count; ++i)
        {
            __int64 obj = ChunkedArrayAccess(gobjectsBase, i);
            if (!obj)
                continue;

            // Check property name
            std::string objName = GetNameAtOffset(obj, FNAME_OFFSET);
            if (objName != propName)
                continue;

            // Check owning class name via Outer at +32
            __int64 outerPtr = *reinterpret_cast<__int64*>(obj + OUTER_OFFSET);
            if (!outerPtr)
                continue;

            std::string outerName = GetNameAtOffset(outerPtr, FNAME_OFFSET);
            if (outerName == className)
            {
                // Return Offset_Internal at UProperty + 68
                return *reinterpret_cast<int*>(obj + PROP_OFFSET_FIELD);
            }
        }

        return 0;
    }

    // Newer path (version >= 11794982):
    // Find the class object first, then walk its property chain.
    __int64 classObj = FindObjectType2(gobjectsBase, className);
    if (!classObj)
        return 0;

    // Walk the property linked list starting at class + 80 (PropertyLink)
    __int64 propNode = *reinterpret_cast<__int64*>(classObj + CLASS_PROPLINK_OFFSET);

    while (propNode)
    {
        // Safety check (original uses IsBadReadPtr)
        if (IsBadReadPtr(reinterpret_cast<const void*>(propNode), 8))
            return 0;

        // Check if the property node is valid
        __int64 propData = *reinterpret_cast<__int64*>(propNode + 8);
        if (IsBadReadPtr(reinterpret_cast<const void*>(propData), 8) || !propData)
        {
            // Move to next property in chain
            propNode = *reinterpret_cast<__int64*>(propNode + PROP_NEXT_OFFSET);
            continue;
        }

        // Check property offset field (must be non-zero)
        int offset = *reinterpret_cast<int*>(propNode + PROP_OFFSET_FIELD_NEW);
        if (!offset)
        {
            propNode = *reinterpret_cast<__int64*>(propNode + PROP_NEXT_OFFSET);
            continue;
        }

        // Get property name at +40 and compare
        std::string nodeName = GetNameAtOffset(propNode, PROP_NAME_OFFSET_NEW);
        if (nodeName == propName)
            return offset;

        // Move to next property
        propNode = *reinterpret_cast<__int64*>(propNode + PROP_NEXT_OFFSET);
    }

    return 0;
}

// ============================================================================
// Public API implementations
// ============================================================================

UWorld* GetWorld()
{
    if (!Globals::qword_18004FDB0)
        return nullptr;
    return *reinterpret_cast<UWorld**>(Globals::qword_18004FDB0);
}

void ProcessEvent(UObject* object, UFunction* function, void* params)
{
    if (!Globals::qword_18004FDE8 || !object || !function)
        return;

    Globals::qword_18004FDE8(
        reinterpret_cast<__int64>(object),
        reinterpret_cast<__int64>(function),
        reinterpret_cast<__int64>(params),
        0);
}

std::string FNameToString(int nameIndex)
{
    if (!Globals::qword_18004FDC8)
        return "";

    // FName value (index-based, 8 bytes for alignment)
    __int64 fname = static_cast<__int64>(nameIndex);

    __int64 fstringBuf[2] = {0, 0};
    auto fnameToStr = reinterpret_cast<void(__fastcall*)(__int64*, __int64*)>(
        Globals::qword_18004FDC8);
    fnameToStr(&fname, fstringBuf);

    if (!fstringBuf[0])
        return "";

    const wchar_t* wdata = reinterpret_cast<const wchar_t*>(fstringBuf[0]);
    size_t wlen = wcslen(wdata);
    return StringUtils::WideToNarrow(wdata, wlen);
}

std::string GetObjectName(__int64 objectPtr)
{
    return GetNameAtOffset(objectPtr, FNAME_OFFSET);
}

// Original: sub_1800072D0
// Dispatches to version-specific object lookup based on PatternLink type.
// On failure, shows MessageBoxA error.
__int64 StaticFindObject(const char* name)
{
    __int64 patternLink = Globals::qword_18004FDF0;
    if (!patternLink)
        return 0;

    unsigned char type = *reinterpret_cast<unsigned char*>(patternLink);
    __int64 gobjectsBase = *reinterpret_cast<__int64*>(patternLink + 8);

    __int64 result = 0;

    if (type == 1)
    {
        result = FindObjectType1(gobjectsBase, name);
    }
    else if (type == 2)
    {
        result = FindObjectType2(gobjectsBase, name);
    }

    if (!result)
    {
        MessageBoxA(nullptr,
            "Value is NULL, please report the game version to Rift developers.",
            "Error", MB_ICONERROR);
    }

    return result;
}

// Original: sub_180007790
// Find a property offset given class name and property name.
// Dispatches based on PatternLink type.
// On failure, shows MessageBoxA error.
int FindPropertyOffset(const char* className, const char* propertyName)
{
    __int64 patternLink = Globals::qword_18004FDF0;
    if (!patternLink)
        return 0;

    unsigned char type = *reinterpret_cast<unsigned char*>(patternLink);
    __int64 gobjectsBase = *reinterpret_cast<__int64*>(patternLink + 8);

    int result = 0;

    if (type == 1)
    {
        result = FindPropertyType1(gobjectsBase, className, propertyName);
    }
    else if (type == 2)
    {
        result = FindPropertyType2(gobjectsBase, className, propertyName);
    }

    if (!result)
    {
        MessageBoxA(nullptr,
            "Value is NULL, please report the game version to Rift developers.",
            "Error", MB_ICONERROR);
    }

    return result;
}

// Original: sub_18000E8A0
// Initializes console and viewport for the local player.
// Navigation chain:
//   1. Find "Default__GameplayStatics" UObject
//   2. Find "Console" UObject
//   3. Get OwningGameInstance from World
//   4. Get GameInstance -> LocalPlayers[0] -> LocalPlayer
//   5. Get ViewportClient from LocalPlayer
//   6. Call ProcessEvent(GameplayStatics, ConsoleFunc, {Console, ViewportClient})
//   7. Assign constructed console to ViewportConsole property on ViewportClient
unsigned int InitConsoleAndViewport()
{
    // Resolve required objects
    __int64 gameplayStatics = StaticFindObject("Default__GameplayStatics");
    __int64 consoleObj = StaticFindObject("Console");

    // Find "OwningGameInstance" offset on "World" class
    int worldOffset = FindPropertyOffset("World", "OwningGameInstance");

    // Navigate: *GWorld -> [OwningGameInstance offset]
    __int64 owningGameInstance = *reinterpret_cast<__int64*>(
        worldOffset + *reinterpret_cast<__int64*>(Globals::qword_18004FDB0));

    if (!owningGameInstance)
    {
        return MessageBoxA(nullptr, "OwningGameInstance was nullptr.",
                           "Error", MB_ICONERROR);
    }

    // Navigate: GameInstance -> LocalPlayers[0]
    int localPlayersOffset = FindPropertyOffset("GameInstance", "LocalPlayers");
    __int64 localPlayer = **reinterpret_cast<__int64**>(
        localPlayersOffset + owningGameInstance);

    if (!localPlayer)
    {
        return MessageBoxA(nullptr, "LocalPlayer was nullptr.",
                           "Error", MB_ICONERROR);
    }

    // Navigate: LocalPlayer -> ViewportClient
    int viewportClientOffset = FindPropertyOffset("LocalPlayer", "ViewportClient");
    __int64 viewportClient = *reinterpret_cast<__int64*>(
        viewportClientOffset + localPlayer);

    if (!viewportClient)
    {
        return MessageBoxA(nullptr, "ViewportClient was nullptr.",
                           "Error", MB_ICONERROR);
    }

    // Call ProcessEvent to construct console
    // Original: qword_18004FDE8(gameplayStatics, qword_18004FFF0, params, 0)
    __int64 params[2] = { consoleObj, static_cast<__int64>(viewportClient) };
    Globals::qword_18004FDE8(gameplayStatics, Globals::qword_18004FFF0,
                              reinterpret_cast<__int64>(params), 0);

    // Get the constructed console from the result
    __int64 constructedConsole = params[1];  // output parameter

    if (!constructedConsole)
    {
        return MessageBoxA(nullptr, "ConstructedConsole was nullptr.",
                           "Error", MB_ICONERROR);
    }

    // Assign to ViewportConsole property
    int viewportConsoleOffset = FindPropertyOffset(
        "GameViewportClient", "ViewportConsole");
    *reinterpret_cast<__int64*>(viewportConsoleOffset + viewportClient) =
        constructedConsole;

    return static_cast<unsigned int>(viewportConsoleOffset);
}

// Original: sub_180007CB0
void InitializeSDK()
{
    // This function resolves all UE4 property offsets by iterating
    // class hierarchies and property chains. It is called once during
    // startup and populates the global offset cache.
    //
    // The implementation is a large function with many FindPropertyOffset
    // calls that build up the internal state needed for game interaction.
    // Full reconstruction requires mapping all property offset globals.
}

} // namespace UE4
