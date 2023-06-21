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

/* Define the structure of the packet according to the RFC 826 specification
 We will use this structure to imitate an authentic packet
 so that the reply to the ARP request will be accepted by the network
*/
unsigned char	*_mc_create_packet_for_spoofing(void)
{
    // Create the ARP reply packet
    unsigned char       packet[sizeof(struct ethhdr) + sizeof(struct ether_arp)];
    struct ethhdr       *eth_header = (struct ethhdr*)packet;
    struct ether_arp    *arp_header = (struct ether_arp*)(packet + sizeof(struct ethhdr));

	_mc_memcpy(eth_header->h_dest, _mc_g_data.ethernet_header->h_source, ETH_ALEN);
	_mc_memcpy(eth_header->h_source, _mc_g_data.ethernet_header->h_source, ETH_ALEN);

	eth_header->h_proto = htons(ETH_P_ARP);
}

void	_mc_run_arp_spoofing(void)
{
	unsigned char	packet = _mc_create_packet_for_spoofing();
}