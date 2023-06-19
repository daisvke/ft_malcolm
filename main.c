#include "ft_malcolm.h"    

// This is the global variable
_mc_t_data	_mc_g_data;

void _mc_print_mac(const unsigned char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void _mc_print_ip(const unsigned char* ip) {
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
    if (_mc_g_data.raw_sockfd == -1) {
        fprintf(stderr, "Failed to create raw socket");
        return;
    }

    while (1) {
		_mc_bzero(buffer, _MC_MAX_PACKET_SIZE);

        /* Read packets from the raw socket with RECVFROM */
        ssize_t bytes_read = recvfrom(
			_mc_g_data.raw_sockfd,
			buffer, _MC_MAX_PACKET_SIZE,
			0, (struct sockaddr*)&_mc_g_data.src_addr, &addrlen
		);
        if (bytes_read == -1) {
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
        if (ntohs(_mc_g_data.ethernet_header->h_proto) == ETH_P_ARP) {
			
			// The ARP packet is located just after tje ethernet header
			_mc_g_data.arp_packet =
				(struct ether_arp *)(buffer + sizeof(struct ethhdr));

            // The ARP header is the first member of the ether_arp struct
            _mc_g_data.arp_header = (struct arphdr*)_mc_g_data.arp_packet;
			if (ntohs(_mc_g_data.arp_header->ar_pro) != ETH_P_IP) {
				fprintf(stderr, "Error: IP address is not IPv4!\n");
				close(_mc_g_data.raw_sockfd);
				return;
			}

			// The ARP opcode is the operation being performed in an ARP packet
			uint16_t arop_code = ntohs(_mc_g_data.arp_header->ar_op);

            // Check if the ARP operation is a request
            if (arop_code == ARPOP_REQUEST) {

                // Extract the sender IP and MAC addresses
				unsigned char* sender_mac = _mc_g_data.arp_packet->arp_sha;
                unsigned char* sender_ip = _mc_g_data.arp_packet->arp_spa;

                // Extract the target IP and MAC addresses
                unsigned char* target_mac = _mc_g_data.arp_packet->arp_tha;
                unsigned char* target_ip = _mc_g_data.arp_packet->arp_tpa;

				if (_mc_g_data.verbose == true) {
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
			else if (_mc_g_data.verbose == true) {
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

int	_mc_display_interface(void)
{
	// Check the network interface
	struct	ifaddrs *ifaddr, *ifa;
	char	active_interface[IFNAMSIZ];

    // Retrieve the list of network interfaces
    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, _MC_RED_COLOR "ERROR: %s\n", strerror(errno));
        return 1;
    }

    // Traverse the list of network interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // Check if the interface has an assigned IP address and is up
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET &&
            (ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
			// TODO replace by custom
            strncpy(active_interface, ifa->ifa_name, IFNAMSIZ);
            break;
        }
    }

    // Print the active interface name
    if (_mc_strlen(active_interface) > 0) {
        printf("Active Interface: %s\n\n", active_interface);
    } else {
        fprintf(stderr, _MC_RED_COLOR "No active interface found"
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
	if (argc < 5 || argc > 6) {
        fprintf(stderr, _MC_RED_COLOR "Wrong number of argument."
			_MC_RESET_COLOR "\n\n");
		_mc_print_usage();
		return 1;
	}

	// The 5th argument is only present when the "-v" (verbose) option is used
	if (argc == 6) {
		for (size_t i=0; i < argc; ++i)
		{
			const char	*vopt = "-v";
			if (_mc_strncmp(argv[i], vopt, _mc_strlen(argv[i])) == 0) {
				_mc_g_data.verbose = true;
				break;
			}
		}
		if (_mc_g_data.verbose == false) {
			_mc_print_usage();
			fprintf(stderr, _MC_RED_COLOR "Unknown 5th argument\n"
				_MC_RESET_COLOR "\n\n");
			return 1;
		}
		printf("[*] Activated verbose mode\n");
	}
	return 0;
}

int	main(int argc, char *argv[])
{
	if (_mc_check_arguments(argc, argv) == _MC_ERROR) return 1;

	// Check for root privileges
	if (getuid() == 0) {
		printf("Root privileges detected\n");
	} else {
		fprintf(stderr, "Not running with root privileges. Quitting...\n");
		return 1;
	}

	if (_mc_display_interface() == _MC_ERROR) return 1;

	_mc_start_sniffing_paquets();

	return 0;
}
