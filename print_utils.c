#include "ft_malcolm.h"

void	_mc_print_usage(void)
{
	printf(
		"Usage: [HOST IP] [HOST MAC] [TARGET IP] [TARGET MAC]\n\n"
		"In that particular order.\n"
		"HOST = this computer\n"
		"TARGET = your target sending the ARP request\n\n"
		"IP addresses have to be in the IPv4 format,\n"
		"MAP addresses have to be in format xx:xx:xx:xx:xx:xx\n"
		"(Separator can be either ':' or '-')\n"
		"And letters can be both lower and upper case letters\n"
		"-v: verbose\n\n"
	);
}

void	_mc_print_mac(const unsigned char* mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void	_mc_print_ip(const unsigned char* ip)
{
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void	_mc_print_packet_info()
{
	// Extract the sender IP and MAC addresses
	unsigned char* sender_mac = _mc_g_data.arp_packet->arp_sha;
	unsigned char* sender_ip = _mc_g_data.arp_packet->arp_spa;

	// Extract the target IP and MAC addresses
	unsigned char* target_mac = _mc_g_data.arp_packet->arp_tha;
	unsigned char* target_ip = _mc_g_data.arp_packet->arp_tpa;
	
	// Only display packet details if in verbose mode
	if (_mc_g_data.verbose == true)
	{
		// Print the sender and target IP and MAC addresses
		printf(_MC_GREEN_COLOR "Sender MAC:\t");
		_mc_print_mac(sender_mac);
		printf("Sender IP:\t");
		_mc_print_ip(sender_ip);

		printf(_MC_RED_COLOR "Target MAC:\t");
		_mc_print_mac(target_mac);
		printf("Target IP:\t");
		_mc_print_ip(target_ip);
		printf(_MC_RESET_COLOR "\n");
	}
}