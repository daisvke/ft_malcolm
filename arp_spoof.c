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

int convert_ip_string_to_bytes(const char* ip_string, unsigned char* ip_bytes) {
    // Split the IP address string into four components
    char* token;
    int i = 0;
    token = strtok((char*)ip_string, ".");
    while (token != NULL) {
        // Convert each component from string to integer
        int value = atoi(token);
        if (value < 0 || value > 255) {
            fprintf(stderr, "Invalid IP address component: %s\n", token);
            return 0;
        }
        ip_bytes[i++] = (unsigned char)value;
        token = strtok(NULL, ".");
    }

    // Check if all four components are present
    if (i != 4) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_string);
        return 0;
    }

    return 1;
}

_mc_t_packet	_mc_create_packet_for_spoofing(void)
{
	_mc_t_packet	packet;
    struct ethhdr* eth_header = (struct ethhdr*)packet;
	struct ether_arp* arp_header = (struct ether_arp*)(packet + ETHER_HDR_LEN);

	_mc_memcpy(
		packet.ethernet_header.h_dest,
		_mc_g_data.ethernet_header.h_source, ETH_ALEN
		);
	_mc_memcpy(
		packet.ethernet_header.h_source,
		_mc_g_data.ethernet_header.h_sou, ETH_ALEN
		);
	packet.ethernet_header.h_proto = eth_header->h_proto = htons(ETH_P_ARP);
}

void	_mc_run_arp_spoofing(void)
{
	_mc_t_packet	packet = _mc_create_packet_for_spoofing();
}
