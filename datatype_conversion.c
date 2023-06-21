#include "ft_malcolm.h"

void    _mc_convert_string_to_byte_ip(const char* str_ip, uint8_t* byte_ip)
{
    in_addr_t   ip = inet_addr(str_ip);
    uint8_t*    ptr = (uint8_t*)&ip;

    for (int i = 0; i < 4; i++) {
        byte_ip[i] = ptr[i];
    }
}

unsigned char   _mc_hex_char_to_byte(char c)
{
    if (c >= '0' && c <= '9') {
        return (unsigned char)(c - '0');
    } else if (c >= 'a' && c <= 'f') {
        // Subtract the ASCII value of '0' from c to get the decimal value of the digit.
        // It is then casted to an unsigned char and returned as the byte value.
        return (unsigned char)(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
        return (unsigned char)(c - 'A' + 10);
    } else {
        return 0; // Invalid character, return 0 as default
    }
}

void    _mc_convert_mac_string_to_bytes(const char* mac_string, unsigned char* mac_bytes)
{
    int byte_index = 0;
    int str_index = 0;

    while (mac_string[str_index] && byte_index < 6) {
        // Skip delimiters (':', '-')
        if (mac_string[str_index] == ':' || mac_string[str_index] == '-') {
            str_index++;
            continue;
        }

        // Convert two hexadecimal characters to a byte
        unsigned char high_nibble = _mc_hex_char_to_byte(mac_string[str_index]);
        unsigned char low_nibble = _mc_hex_char_to_byte(mac_string[str_index + 1]);
        mac_bytes[byte_index++] = (high_nibble << 4) | low_nibble;

        // Move to the next pair of characters
        str_index += 2;
    }
}