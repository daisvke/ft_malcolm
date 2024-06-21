#include "ft_malcolm.h"

/*
    Create a raw socket using socket to capture ARP packets on the network interface.
    Use a loop to continuously read packets from the socket using recvfrom.
    Parse the received packets to extract the necessary information, such as IP and MAC addresses.
    Compare the source IP and MAC addresses of each packet with the desired values.
    Process the packets that match the desired IP and MAC addresses
*/

int	_mc_handle_received_packet(unsigned char *buffer)
{
	// The buffer contains the whole packet,
	// and the firt header in the packet is the ethernet header
	_mc_g_data.ethernet_header = (struct ethhdr*)buffer;

	// Check if the Ethernet type is ARP
	if (ntohs(_mc_g_data.ethernet_header->h_proto) == ETH_P_ARP)
	{
		
		// The ARP packet is located just after the ethernet header
		_mc_g_data.arp_packet =
			(struct ether_arp *)(buffer + sizeof(struct ethhdr));

		// The ARP header is the first member of the ether_arp struct
		_mc_g_data.arp_header = (struct arphdr*)_mc_g_data.arp_packet;
		if (ntohs(_mc_g_data.arp_header->ar_pro) != ETH_P_IP)
		{
			fprintf(stderr, _MC_RED_CROSS " Error: IP address is not IPv4!\n");
			close(_mc_g_data.raw_sockfd);
			return 1;
		}

		// The ARP opcode is the operation being performed in an ARP packet
		uint16_t arop_code = ntohs(_mc_g_data.arp_header->ar_op);

		// Check if the ARP operation is a request
		if (arop_code == ARPOP_REQUEST)
		{
			// Extract the sender IP and MAC addresses
			unsigned char* sender_mac	= _mc_g_data.arp_packet->arp_sha;
			unsigned char* sender_ip	= _mc_g_data.arp_packet->arp_spa;
			
			_mc_print_packet_info(); /* Only if verbose mode is on */

			// When the source data from the packet matches the data
			// given through command line, we launch the ARP spoofing
			if (_mc_memcmp(sender_ip, _mc_g_data.target_ip, _MC_IPV4_BYTE_SIZE) == 0 &&
				_mc_memcmp(sender_mac, _mc_g_data.target_mac, ETH_ALEN) == 0)
			{
				printf(_MC_YELLOW_COLOR
					"Matched the target IP and MAC addresses, running ARP spoofing..."
					_MC_RESET_COLOR "\n\n");
				_mc_run_arp_spoofing();
				close(_mc_g_data.raw_sockfd);
				return 1;
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
	return 0;
}

// Signal handler function
void _mc_handle_ctrlc(int sig)
{
	(void)sig;
	// Stop the main packet reading loop
	_mc_g_data.stop_loop = true;
    printf("\nCtrl+C caught.\n");
}

int	_mc_start_sniffing_paquets(void)
{
	// Set up the signal handler
    signal(SIGINT, _mc_handle_ctrlc);

	// Initial size of the buffer allocated to store src_addr
    socklen_t	addrlen = sizeof(struct sockaddr_ll);

    // Create raw socket for capturing ARP packets,
	// and save the file descriptor
    _mc_g_data.raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (_mc_g_data.raw_sockfd == -1)
	{
        fprintf(stderr, _MC_RED_CROSS " Failed to create raw socket");
        close(_mc_g_data.raw_sockfd);
        return 1;
    }

    while (_mc_g_data.stop_loop == false)
	{
		// Buffer used to save all paquets read by recvfrom()
   		 unsigned char	buffer[_MC_MAX_PACKET_SIZE] = {0};

        /* Read packets from the raw socket with RECVFROM */
        ssize_t bytes_read =
			recvfrom(
				_mc_g_data.raw_sockfd,
				buffer,
				_MC_MAX_PACKET_SIZE,
				MSG_DONTWAIT, /* Unblocking mode lets us quit with ctrl C */
				(struct sockaddr*)&_mc_g_data.src_addr, &addrlen
		);
        if (bytes_read > 0 && _mc_handle_received_packet(buffer) == _MC_ERROR) return 1;
	}
    // Close the raw socket
    close(_mc_g_data.raw_sockfd);
	return 0;
}
