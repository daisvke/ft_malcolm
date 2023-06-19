#include "ft_malcolm.h"    


bool	isipv4(unsigned char *ip_addr){
    if (inet_addr((const char*)ip_addr) == INADDR_NONE) {
        fprintf(stderr, "%s Invalid IP address format: Sender IP is not IPv4\n",(const char*)ip_addr);
        return 0;
    }
    printf("IP value: %s (IPv4)\n", (const char*)ip_addr);
	return 1;
}

void print_mac(const unsigned char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const unsigned char* ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

/*
    Create a raw socket using socket to capture ARP packets on the network interface.
    Use a loop to continuously read packets from the socket using recvfrom.
    Parse the received packets to extract the necessary information, such as IP and MAC addresses.
    Compare the source IP and MAC addresses of each packet with the desired values.
    Process the packets that match the desired IP and MAC addresses
	*/
int	main(int argc, char *argv[])
{
	// Check for root privileges
	if (getuid() == 0) {
		printf(YELLOW_COLOR "Root privileges detected.\n\n" RESET_COLOR);
	} else {
		fprintf(stderr, "Not running with root privileges. Quitting...\n");
		return 1;
	}

    int					raw_socket;


	// Will be filled with the source address information
	struct sockaddr_in	src_addr;
	// Initial size of the buffer allocated to store src_addr
    socklen_t			addrlen = sizeof(struct sockaddr_in);

	// Size of the buffer for the packet data
	size_t				bufflen = (size_t)addrlen + sizeof(struct ethhdr) + sizeof(struct ether_arp) + sizeof(struct arphdr);
    unsigned char		buffer[bufflen];
	bzero(buffer, bufflen);

		printf("bufflen:  %zd\n",bufflen);
    // Create raw socket for capturing ARP packets
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_socket == -1) {
        fprintf(stderr, "Failed to create raw socket");
        return 1;
    }

    while (1) {
        // Receive packets
        ssize_t bytes_read = recvfrom(
			raw_socket, buffer, bufflen, 0, (struct sockaddr*)&src_addr, &addrlen
		);
		printf("byte: %zd\n",bytes_read);
		
        if (bytes_read == -1) {
            fprintf(stderr, "Error: %d\n", errno);
            close(raw_socket);
            return 1;
        }

         // Parse the received packet
        struct ethhdr* ethernetHeader = (struct ethhdr*)buffer;

        // Check if the Ethernet type is ARP
        if (ntohs(ethernetHeader->h_proto) == ETH_P_ARP) {
			struct ether_arp	*arp_packet = (struct ether_arp *)(buffer + sizeof(struct ethhdr));

            // Calculate the offset to the ARP header
            struct arphdr* arpHeader = 
				(struct arphdr*)(buffer + sizeof(struct ethhdr));

            // Check if the ARP operation is a request
            if (ntohs(arpHeader->ar_op) == ARPOP_REQUEST) {

                // Extract the sender IP and MAC addresses
				unsigned char* sender_mac = arp_packet->arp_sha;
                unsigned char* sender_ip = arp_packet->arp_spa;

                // Extract the target IP and MAC addresses
                unsigned char* target_mac = arp_packet->arp_tha;
                unsigned char* target_ip = arp_packet->arp_tpa;

                // Print the sender and target IP and MAC addresses
                printf(GREEN_COLOR "Sender MAC:\t");
                print_mac(sender_mac);
                printf("Sender IP:\t");
                print_ip(sender_ip);

                printf(RED_COLOR "Target MAC:\t");
                print_mac(target_mac);
                printf("Target IP:\t");
                print_ip(target_ip);
				printf(RESET_COLOR "\n");
            }
			else {
const char* op_codes[] = OP_CODE_ARRAY;

				printf(YELLOW_COLOR "Received an %s, not an ARP request...\n\n" RESET_COLOR, op_codes[ntohs(arpHeader->ar_op) - 1]);
			}
		}
	}

    // Close the raw socket
    close(raw_socket);



	return 0;
}
