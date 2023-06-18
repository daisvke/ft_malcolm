#include "ft_malcolm.h"    


bool	check_ip(){
	const char* ipAddress = "192.168.0.1"; // Example IP address
 // TODO check if ipv4
    uint32_t ipValue = inet_addr(ipAddress);
    if (ipValue == INADDR_NONE) {
        printf("Invalid IP address format\n");
        return 1;
    }

    printf("IP value: %u\n", ipValue);
	return 0;
}

void print_mac(const unsigned char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
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
		printf("Root privileges detected.\n");
	} else {
		fprintf(stderr, "Not running with root privileges. Quitting...\n");
		return 1;
	}

    int				raw_socket;
    unsigned char	buffer[BUFFER_SIZE];

    // Create raw socket for capturing ARP packets
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_socket == -1) {
        fprintf(stderr, "Failed to create raw socket");
        return 1;
    }

    while (1) {

        // Receive packets
        ssize_t bytes_read = recvfrom(raw_socket, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (bytes_read == -1) {
            fprintf(stderr, "Failed to receive packet");
            close(raw_socket);
            return 1;
        }

         // Parse the received packet
        struct ethhdr* ethernetHeader = (struct ethhdr*)buffer;

        // Check if the Ethernet type is ARP
        if (ntohs(ethernetHeader->h_proto) == ETH_P_ARP) {
            // Calculate the offset to the ARP header
            struct arphdr* arpHeader = (struct arphdr*)(buffer + sizeof(struct ethhdr));

            // Check if the ARP operation is a request
            if (ntohs(arpHeader->ar_op) == ARPOP_REQUEST) {
                // Extract the sender IP and MAC addresses
                unsigned char* sender_mac = buffer + sizeof(struct ethhdr) + sizeof(struct arphdr);
                unsigned char* sender_ip = buffer + sizeof(struct ethhdr) + sizeof(struct arphdr) + 6;

                // Extract the target IP and MAC addresses
                unsigned char* target_mac = sender_mac + 4;
                unsigned char* target_ip = sender_ip + 10;

                // Print the sender and target IP and MAC addresses
                printf("Sender IP: ");
                print_ip(sender_ip);
                printf("Sender MAC: ");
                print_mac(sender_mac);
                printf("Target IP: ");
                print_ip(target_ip);
                printf("Target MAC: ");
                print_mac(target_mac);
            }
		}
	}

    // Close the raw socket
    close(raw_socket);



	return 0;
}
