#include "ft_malcolm.h"    

// This is the global variable
_mc_t_data	_mc_g_data;

// Check if the string is IPv4
bool    isipv4(const char *ip_addr)
{
    if (inet_addr((const char*)ip_addr) == INADDR_NONE) 
	{	
        fprintf(stderr,
			"%s Invalid IP address format: At least one sender IP is not IPv4\n",
			(const char*)ip_addr);
        return 0;
    }
    printf("IP value: %s (IPv4)\n", (const char*)ip_addr);
        return 1;
}

void _mc_print_mac(const unsigned char* mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void _mc_print_ip(const unsigned char* ip)
{
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

/*
    Create a raw socket using socket to capture ARP packets on the network interface.
    Use a loop to continuously read packets from the socket using recvfrom.
    Parse the received packets to extract the necessary information, such as IP and MAC addresses.
    Compare the source IP and MAC addresses of each packet with the desired values.
    Process the packets that match the desired IP and MAC addresses
*/
void	_mc_start_sniffing_paquets(void)
{
	// Initial size of the buffer allocated to store src_addr
    socklen_t	addrlen = sizeof(struct sockaddr_in);

	// Buffer used to save all paquets read by recvfrom()
    unsigned char	buffer[_MC_MAX_PACKET_SIZE];

    // Create raw socket for capturing ARP packets,
	// and save the file descriptor
    _mc_g_data.raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (_mc_g_data.raw_sockfd == -1)
	{
        fprintf(stderr, "Failed to create raw socket");
        return;
    }

    while (1)
	{
		_mc_bzero(buffer, _MC_MAX_PACKET_SIZE);

        /* Read packets from the raw socket with RECVFROM */
        ssize_t bytes_read = recvfrom(
			_mc_g_data.raw_sockfd,
			buffer, _MC_MAX_PACKET_SIZE,
			0, (struct sockaddr*)&_mc_g_data.src_addr, &addrlen
		);
        if (bytes_read == -1)
		{
            fprintf(stderr,
				_MC_RED_COLOR "Error: %s\n" _MC_RESET_COLOR, strerror(errno)
			);
            close(_mc_g_data.raw_sockfd);
            return;
        }
        // From here, parse the received packet

		// The buffer contains the whole packet,
		// and the firt header in the packet is the ethernet header
        _mc_g_data.ethernet_header = (struct ethhdr*)buffer;

        // Check if the Ethernet type is ARP
        if (ntohs(_mc_g_data.ethernet_header->h_proto) == ETH_P_ARP)
		{
			
			// The ARP packet is located just after tje ethernet header
			_mc_g_data.arp_packet =
				(struct ether_arp *)(buffer + sizeof(struct ethhdr));

            // The ARP header is the first member of the ether_arp struct
            _mc_g_data.arp_header = (struct arphdr*)_mc_g_data.arp_packet;
			if (ntohs(_mc_g_data.arp_header->ar_pro) != ETH_P_IP)
			{
				fprintf(stderr, "Error: IP address is not IPv4!\n");
				close(_mc_g_data.raw_sockfd);
				return;
			}

			// The ARP opcode is the operation being performed in an ARP packet
			uint16_t arop_code = ntohs(_mc_g_data.arp_header->ar_op);

            // Check if the ARP operation is a request
            if (arop_code == ARPOP_REQUEST)
			{
                // Extract the sender IP and MAC addresses
				unsigned char* sender_mac = _mc_g_data.arp_packet->arp_sha;
                unsigned char* sender_ip = _mc_g_data.arp_packet->arp_spa;

                // Extract the target IP and MAC addresses
                unsigned char* target_mac = _mc_g_data.arp_packet->arp_tha;
                unsigned char* target_ip = _mc_g_data.arp_packet->arp_tpa;

				if (_mc_g_data.verbose == true)
				{
					// Print the sender and target IP and MAC addresses
					printf(_MC_GREEN_COLOR "Sender MAC:\t");
					_mc_print_mac(sender_mac);
					printf("Sender IP:\t");
					_mc_print_ip(sender_ip);

					printf(_MC_RED_COLOR "Target MAC:\t");
					_mc_print_mac(target_mac);
					printf("Target IP:\t");
					_mc_print_ip(target_ip);
					printf(_MC_RESET_COLOR "\n");
				}
            }
			else if (_mc_g_data.verbose == true)
			{
				const char* op_codes[] = _MC_OP_CODE_ARRAY;

				printf(
					_MC_YELLOW_COLOR "Received an %s, not an ARP request..."
					_MC_RESET_COLOR "\n\n",
					op_codes[arop_code - 1]
				);
			}
		}
	}
    // Close the raw socket
    close(_mc_g_data.raw_sockfd);
}

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
        if (ifa->ifa_addr != NULL &&
			ifa->ifa_addr->sa_family == AF_INET && /* IPv4 */
            (ifa->ifa_flags & IFF_UP) && /* is up */
			!(ifa->ifa_flags & IFF_LOOPBACK) && /* not localhost */
			!(ifa->ifa_flags & IFF_NOARP)) /* accepts ARP */
		{
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

void	_mc_print_usage(void)
{
	printf(
		"Usage: [SOURCE IP] [SOURCE MAC] [TARGET IP] [TARGET MAC]\n"
		"In that particular order.\n"
		"IP addresses have to be in the IPv4 format\n\n"
		"-v: verbose\n\n"
	);
}

int	_mc_check_arguments(size_t argc, char *argv[])
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
	
	// The only condition in which the ip and mac arguments will not begin
	// at argv[1] is when the '-v' option is present at argv[1]
	size_t	start = _mc_strncmp(argv[1], "-v", _mc_strlen(argv[1])) == 0 ?
		2 : 1;
	for (size_t i=start; i < argc; ++i)
	{
		if ((_mc_g_data.verbose == false ||
				(_mc_g_data.verbose == true &&
					_mc_strncmp(argv[i], "-v",
					_mc_strlen(argv[i])) != 0)
			) &&
			isipv4(argv[i]) == false) return 1;
	}
	return 0;
}

int	main(int argc, char *argv[])
{
	if (_mc_check_arguments(argc, argv) == _MC_ERROR) return 1;

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
