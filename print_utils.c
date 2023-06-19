#include "ft_malcolm.h"

void	_mc_print_usage(void)
{
	printf(
		"Usage: [SOURCE IP] [SOURCE MAC] [TARGET IP] [TARGET MAC]\n"
		"In that particular order.\n"
		"IP addresses have to be in the IPv4 format\n\n"
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
