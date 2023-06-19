#include "ft_malcolm.h"

bool    is_ip_address_ipv4(const char *ip_addr)
{
    if (inet_addr((const char*)ip_addr) == INADDR_NONE) 
	{	
        fprintf(stderr,
			"%s Invalid IP address format: At least one sender IP is not IPv4\n",
			(const char*)ip_addr);
        return false;
    }
    printf("IP value: %s (IPv4)\n", (const char*)ip_addr);
    return true;
}

bool	is_mac_address_valid(const char *mac_address) {
    // MAC address should be 17 characters long (e.g., "00:11:22:33:44:55")
    if (strlen(mac_address) != 17) return false;

    // Validate the MAC address format
    for (int i = 0; i < 17; i++) {
        char c = mac_address[i];

        // Check if the character is a valid hexadecimal digit or a separator
        if (i % 3 == 2) {
            // Separator should be a colon or a hyphen
            if (c != ':' && c != '-') return false;
        } else {
            // Digit should be a valid hexadecimal character
            if (!_mc_isxdigit(c)) return false;
        }
    }
    return true;
}
