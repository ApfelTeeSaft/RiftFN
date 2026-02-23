#pragma once

#include "globals.h"
#include <string>
#include <vector>

// String utility functions reconstructed from IDA decompilation.
//
// Original functions:
//   sub_180005030 - wchar_t string to narrow char string (using std::ctype<wchar_t>::narrow)
//   sub_180004DE0 - Split string by delimiter into vector of strings
//   sub_180030850 - SSO string constructor (used pervasively)
//   sub_180004F70 - toupper string conversion

namespace StringUtils {

// Convert a wide character string to narrow (ASCII) string.
// Original: sub_180005030
// Used in StartAddress to convert the UE4 engine version string (wchar_t) to char.
std::string WideToNarrow(const wchar_t* wstr, size_t len);

// Split a string by a single-character delimiter.
// Returns a vector of string tokens.
// Original: sub_180004DE0
// Used in StartAddress to split the version string on '-'.
std::vector<std::string> SplitString(const std::string& str, char delimiter);

// Convert a string to uppercase.
// Original: sub_180004F70
std::string ToUpper(const std::string& str);

} // namespace StringUtils
