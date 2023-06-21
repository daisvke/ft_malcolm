#include "ft_malcolm.h"

/*
    Create a raw socket using socket to capture ARP packets on the network interface.
    Use a loop to continuously read packets from the socket using recvfrom.
    Parse the received packets to extract the necessary information, such as IP and MAC addresses.
    Compare the source IP and MAC addresses of each packet with the desired values.
    Process the packets that match the desired IP and MAC addresses
*/

// int _mc_compare_ip(const unsigned char* ip, const char* ip_string) {
//     // Convert unsigned char* IP address to string representation
//     char ip_buffer[16];  // Assumes IPv4 address

//     snprintf(ip_buffer, sizeof(ip_buffer), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

//     // Compare the IP addresses
//     return _mc_strncmp(ip_buffer, ip_string, 16);
// }

// int _mc_compare_mac_addr(const unsigned char* mac, const char* mac_string) {
// 	// Convert unsigned char* MAC address to string representation
// 	char mac_buffer[18]; // Assumes MAC address format "xx:xx:xx:xx:xx:xx"

// 	snprintf(mac_buffer, sizeof(mac_buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
// 	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

// 	// Compare the MAC addresses
// 	return _mc_strncmp(mac_buffer, mac_string, 18);
// }

void	_mc_start_sniffing_paquets(void)
{
	// Initial size of the buffer allocated to store src_addr
    socklen_t	addrlen = sizeof(struct sockaddr_in);

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
		// Buffer used to save all paquets read by recvfrom()
   		 unsigned char	buffer[_MC_MAX_PACKET_SIZE] = {0};

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
        /* From here, parse the received packet */

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
				
				// Only display packet details if in verbose mode
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
				// When the source data from the packet matches the data
				// given through command line, we launch the ARP spoofing
				if (_mc_memcmp(sender_ip, _mc_g_data.target_ip, _MC_IPV4_BYTE_SIZE) == 0 &&
					_mc_memcmp(sender_mac, _mc_g_data.target_mac, ETH_ALEN) == 0)
				{
					printf("MATCH\n");
					_mc_run_arp_spoofing();
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
