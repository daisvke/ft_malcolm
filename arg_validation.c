#include "ft_malcolm.h"

bool    _mc_is_ip_address_ipv4(const char *ip_addr)
{
	static int	i;

	++i;
    if (inet_addr((const char*)ip_addr) == INADDR_NONE) 
	{	
        fprintf(stderr,
			_MC_RED_COLOR
			"%s:\tInvalid IP address format: At least one IP address is not IPv4"
			_MC_RESET_COLOR "\n\n", (const char*)ip_addr);
        return false;
    }
    return printf("IP value %d:\t%s (IPv4)\n", i, (const char*)ip_addr);
}

int	_mc_invalid_mac_address(const char *mac_addr)
{
	fprintf(stderr,
		_MC_RED_COLOR
		"%s:\tInvalid MAC address format: At least one MAC address is not valid"
		_MC_RESET_COLOR "\n\n", (const char*)mac_addr);
	return 0;
}

bool	_mc_is_mac_address_valid(const char *mac_addr) {
	static int	i;

	++i;
    // MAC address should be 17 characters long (e.g., "00:11:22:33:44:55")
    if (_mc_strlen(mac_addr) != 17) return _mc_invalid_mac_address(mac_addr);

    // Validate the MAC address format
    for (int i=0; i < 17; i++) {
        char c = mac_addr[i];

        // Check if the character is a valid hexadecimal digit or a separator
        if (i % 3 == 2) {
            // Separator should be a colon or a hyphen
            if (c != ':') return _mc_invalid_mac_address(mac_addr);
        } else {
            // Digit should be a valid hexadecimal character
            if (!_mc_isxdigit(c)) return _mc_invalid_mac_address(mac_addr);
         }
    }
    return printf("MAC value %d:\t%s\t\n", i, (const char*)mac_addr);
}
