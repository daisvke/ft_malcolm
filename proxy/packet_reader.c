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
	// if (ntohs(_mc_g_data.ethernet_header->h_proto) == ETH_P_ARP)
	// {
		
		// The ARP packet is located just after the ethernet header
		_mc_g_data.packet = (uint8_t *)(buffer);

		// Extract sender MAC address
		unsigned char* sender_mac	= _mc_g_data.ethernet_header->h_source;
		unsigned char* dest_mac		= _mc_g_data.ethernet_header->h_dest;
		
		uint8_t gateway_mac[6];
		_mc_convert_mac_string_to_bytes("cc:fd:17:a6:cc:44 ", gateway_mac);
	    uint8_t gateway_ip[4];
    	_mc_convert_string_to_byte_ip("192.168.43.1", gateway_ip);

		// When the source data from the packet matches the data
		// given through command line, we launch the ARP spoofing
		if (_mc_memcmp(sender_mac, _mc_g_data.target_mac, ETH_ALEN) == 0
			&& _mc_memcmp(dest_mac, _mc_g_data.host_mac, ETH_ALEN) == 0)
		{
			printf(_MC_YELLOW_COLOR
				"Matched the target IP and MAC addresses, forwarding to the gateway..."
				_MC_RESET_COLOR "\n\n");
			_mc_run_arp_spoofing();
		}
		else if (_mc_memcmp(sender_mac, gateway_mac, ETH_ALEN) == 0
			&& _mc_memcmp(dest_mac, _mc_g_data.host_mac, ETH_ALEN) == 0)
		{
			printf(_MC_YELLOW_COLOR
				"Matched the Gateway IP and MAC addresses, forwarding to the gateway..."
				_MC_RESET_COLOR "\n\n");
			_mc_run_arp_spoofing2();

		}

		// else if (_mc_g_data.verbose == true)
		// {
		// 	const char* op_codes[] = _MC_OP_CODE_ARRAY;

		// 	printf(
		// 		_MC_YELLOW_COLOR "Received an %s, not an ARP request..."
		// 		_MC_RESET_COLOR "\n\n",
		// 		op_codes[arop_code - 1]
		// 	);
		// }
	// }
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
