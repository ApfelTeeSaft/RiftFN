/*
 * Rift DLL - String Utility Functions
 *
 * Original functions:
 *   sub_180005030 (0x180005030) - wchar_t narrow conversion
 *   sub_180004DE0 (0x180004DE0) - String split by delimiter
 *   sub_180004F70 (0x180004F70) - String to uppercase
 *
 * These are MSVC STL helper functions used throughout the DLL.
 * The original implementations use MSVC std::locale and std::ctype<wchar_t>,
 * but the observable behavior is straightforward ASCII conversion.
 */

#include "string_utils.h"
#include <locale>
#include <cctype>

namespace StringUtils {

// Original: sub_180005030
// The original function:
//   1. Computes wcslen(wstr)
//   2. Resizes output string to that length
//   3. Gets std::ctype<wchar_t> facet from locale
//   4. Calls narrow() to convert wchar_t array to char array
//   5. Uses '?' as the default narrow character for unmappable chars
std::string WideToNarrow(const wchar_t* wstr, size_t len)
{
    std::string result;
    result.resize(len);

    // Match original behavior: use std::ctype<wchar_t>::narrow
    // The original uses locale facets directly. For binary parity,
    // we replicate the exact locale initialization sequence.
    std::locale loc;
    const auto& facet = std::use_facet<std::ctype<wchar_t>>(loc);
    facet.narrow(wstr, wstr + len, '?', &result[0]);

    return result;
}

// Original: sub_180004DE0
// The original function:
//   1. Gets begin/end pointers from std::string SSO buffer
//   2. Iterates character by character
//   3. When delimiter found: pushes accumulated token to result vector
//   4. When non-delimiter after delimiter: starts new token
//   5. After loop: pushes final token if any
//
// Result is stored in a std::vector<std::string> (32 bytes per element in MSVC).
// The original uses sub_180030850 for small string construction and
// sub_180035A80 for vector growth.
std::vector<std::string> SplitString(const std::string& str, char delimiter)
{
    std::vector<std::string> result;
    const char* begin = str.c_str();
    const char* end = begin + str.size();

    const char* tokenStart = end;  // sentinel: no current token
    const char* current = begin;

    if (begin != end)
    {
        do
        {
            if (*current == delimiter)
            {
                // Found delimiter - push accumulated token if any
                if (tokenStart != end)
                {
                    result.emplace_back(tokenStart, current);
                    tokenStart = end;  // reset
                }
            }
            else if (tokenStart == end)
            {
                // Start of new token
                tokenStart = current;
            }
            ++current;
        }
        while (current != end);

        // Push final token if any
        if (tokenStart != end)
            result.emplace_back(tokenStart, end);
    }

    return result;
}

// Original: sub_180004F70
// Simple toupper loop over each character.
std::string ToUpper(const std::string& str)
{
    std::string result;
    result.reserve(str.size());

    for (char c : str)
        result += static_cast<char>(toupper(static_cast<unsigned char>(c)));

    return result;
}

} // namespace StringUtils
