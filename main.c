#include "ft_malcolm.h"    


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
    int	raw_socket;


	// Will be filled with the source address information
	struct sockaddr_in	src_addr;
	// Initial size of the buffer allocated to store src_addr
    socklen_t	addrlen = sizeof(struct sockaddr_in);

	// Size of the buffer for the packet data
	// Ethernet frames typically have a maximum payload size of 1500B
	size_t	bufflen = 1500;
	
    unsigned char	buffer[bufflen];
	bzero(buffer, bufflen);

    // Create raw socket for capturing ARP packets
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_socket == -1) {
        fprintf(stderr, "Failed to create raw socket");
        return;
    }

    while (1) {
        // Receive packets
        ssize_t bytes_read = recvfrom(
			raw_socket, buffer, bufflen, 0, (struct sockaddr*)&src_addr, &addrlen
		);
        if (bytes_read == -1) {
            fprintf(stderr, "Error: %d\n", errno);
            close(raw_socket);
            return;
        }

        // From here, parse the received packet

		// The buffer contains the whole packet.
		// The firt header in the packet is the ethernet header
        struct ethhdr* ethernet_header = (struct ethhdr*)buffer;

        // Check if the Ethernet type is ARP
        if (ntohs(ethernet_header->h_proto) == ETH_P_ARP) {
			
			// The ARP packet is located just after tje ethernet header
			struct ether_arp	*arp_packet =
				(struct ether_arp *)(buffer + sizeof(struct ethhdr));

            // The ARP header is the first member of the ether_arp struct
            struct arphdr* arp_header = (struct arphdr*)arp_packet;
			if (ntohs(arp_header->ar_pro) != ETH_P_IP) {
				fprintf(stderr, "Error: IP address is not IPv4!\n");
				close(raw_socket);
				return;
			}

			// The ARP opcode is the operation being performed in an ARP packet
			uint16_t arop_code = ntohs(arp_header->ar_op);

            // Check if the ARP operation is a request
            if (arop_code == ARPOP_REQUEST) {

                // Extract the sender IP and MAC addresses
				unsigned char* sender_mac = arp_packet->arp_sha;
                unsigned char* sender_ip = arp_packet->arp_spa;

                // Extract the target IP and MAC addresses
                unsigned char* target_mac = arp_packet->arp_tha;
                unsigned char* target_ip = arp_packet->arp_tpa;

                // Print the sender and target IP and MAC addresses
                printf(GREEN_COLOR "Sender MAC:\t");
                _mc_print_mac(sender_mac);
                printf("Sender IP:\t");
                _mc_print_ip(sender_ip);

                printf(RED_COLOR "Target MAC:\t");
                _mc_print_mac(target_mac);
                printf("Target IP:\t");
                _mc_print_ip(target_ip);
				printf(RESET_COLOR "\n");
            }
			else {
				const char* op_codes[] = OP_CODE_ARRAY;

				printf(
					YELLOW_COLOR "Received an %s, not an ARP request...\n\n"
					RESET_COLOR,
					op_codes[arop_code - 1]
				);
			}
		}
	}
    // Close the raw socket
    close(raw_socket);
}

int	main(int argc, char *argv[])
{
	// Check for root privileges
	if (getuid() == 0) {
		printf(YELLOW_COLOR "Root privileges detected.\n\n" RESET_COLOR);
	} else {
		fprintf(stderr, "Not running with root privileges. Quitting...\n");
		return 1;
	}

	_mc_start_sniffing_paquets();

	return 0;
}
