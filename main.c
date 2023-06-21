#include "ft_malcolm.h"    

// This is the global variable
_mc_t_data	_mc_g_data;

/* Get the list of all network interfaces and find an active one
with an assigned IP address, which will be the interface we can use */
int	_mc_display_interface(void)
{
	struct	ifaddrs *ifaddr, *ifa;
	char	active_interface[IFNAMSIZ];

    // Retrieve the list of network interfaces
    if (getifaddrs(&ifaddr) == -1)
	{
        fprintf(stderr, _MC_RED_COLOR "ERROR: %s\n", strerror(errno));
        return 1;
    }

    // Traverse the list of network interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
        // Check if the interface has an assigned IPv4 address and is up
        if (ifa->ifa_addr != NULL && /* has an assigned IP address */
			ifa->ifa_addr->sa_family == AF_INET && /* IPv4 */
            (ifa->ifa_flags & IFF_UP) && /* is active and connected to our device */
			!(ifa->ifa_flags & IFF_LOOPBACK) && /* not localhost */
			!(ifa->ifa_flags & IFF_NOARP)) /* accepts ARP */
		{
			// Get the interface name
            _mc_memcpy(active_interface, ifa->ifa_name, IFNAMSIZ);
            break;
        }
    }

    // Print the active interface name
    if (_mc_strlen(active_interface) > 0)
        printf("Active Interface: %s\n\n", active_interface);
    else {
        fprintf(stderr, _MC_RED_COLOR
			"No active interface with IPv4 address found"
			_MC_RESET_COLOR "\n\n");
    	freeifaddrs(ifaddr);
		return 1;
    }

    // Free the memory allocated by getifaddrs
    freeifaddrs(ifaddr);
	return 0;
}

int	_mc_check_argc(size_t argc, char *argv[])
{
	if (argc < 5 || argc > 6)
	{
        fprintf(stderr, _MC_RED_COLOR "Wrong number of argument."
			_MC_RESET_COLOR "\n\n");
		_mc_print_usage();
		return 1;
	}

	// The 5th argument is only present when the "-v" (verbose) option is used
	// and can only exist at pos 1 or 5
	if (argc == 6)
	{
		if (_mc_strncmp(argv[1], "-v", _mc_strlen(argv[1])) == 0 ||
			_mc_strncmp(argv[5], "-v", _mc_strlen(argv[5])) == 0)
			_mc_g_data.verbose = true;
		else {
			_mc_print_usage();
			fprintf(stderr, _MC_RED_COLOR "Unknown 5th argument"
				_MC_RESET_COLOR "\n\n");
			return 1;
		}
		printf("[*] Activated verbose mode\n");
	}
	return 0;
}

int	_mc_validate_and_assign_args(char *argv[])
{
	// The only condition in which the ip and mac arguments will not begin
	// at argv[1] is when the '-v' option is present at argv[1]
	size_t	start = _mc_strncmp(argv[1], "-v", _mc_strlen(argv[1])) == 0 ? 2 : 1;
	int		ip_or_mac = 0;

	printf("\n");
	for (size_t i=start; i < start + 4; ++i)
	{
		if ((_mc_g_data.verbose == false ||
				(_mc_g_data.verbose == true &&
					_mc_strncmp(argv[i], "-v",
					_mc_strlen(argv[i])) != 0)
			) &&
			((ip_or_mac % 2 == 0 &&
				_mc_is_ip_address_ipv4(argv[i]) == false) ||
			(ip_or_mac % 2 != 0 &&
				_mc_is_mac_address_valid(argv[i]) == false))) return 1;
		++ip_or_mac;
	}
	printf("\n");

	// Assign
	_mc_convert_string_to_byte_ip(argv[start], _mc_g_data.host_ip);
	_mc_convert_mac_string_to_bytes(argv[start + 1], _mc_g_data.host_mac);
	_mc_convert_string_to_byte_ip(argv[start + 2], _mc_g_data.target_ip);
	_mc_convert_mac_string_to_bytes(argv[start + 3], _mc_g_data.target_mac);

	// // Save string forms of IP and MAC addresses to the global variable
	// // These will be used when displaying packet's data
	// _mc_g_data.host_ip_str = argv[start];
	// _mc_g_data.host_mac_str = argv[start + 1];
	// _mc_g_data.target_ip_str = argv[start + 2];
	// _mc_g_data.target_mac_str = argv[start + 3];
	
	return 0;
}

int	main(int argc, char *argv[])
{
	if (_mc_check_argc(argc, argv) == _MC_ERROR ||
		_mc_validate_and_assign_args(argv) == _MC_ERROR) return 1;

	// Check for root privileges
	if (getuid() == 0)
		printf("Root privileges detected\n");
	else {
		fprintf(stderr, "Not running with root privileges. Quitting...\n");
		return 1;
	}

	if (_mc_display_interface() == _MC_ERROR) return 1;

	_mc_start_sniffing_paquets();

	return 0;
}
