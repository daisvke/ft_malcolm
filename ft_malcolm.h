#ifndef _FT_MALCOLM_H
# define _FT_MALCOLM_H

# include <stdbool.h>
# include <unistd.h>
# include <stdint.h>
# include <stdio.h>
# include <arpa/inet.h>			// For inet_addr()
# include <stdlib.h>
# include <string.h>
# include <sys/socket.h>
# include <netinet/if_ether.h>
# include <errno.h>
# include <net/if.h>			// For interface
# include <ifaddrs.h>			// For getifaddrs()

/*  Colors */
# define _MC_RED_COLOR		"\033[31m"
# define _MC_GREEN_COLOR	"\033[32m"
# define _MC_YELLOW_COLOR	"\033[33m"
# define _MC_RESET_COLOR	"\033[0m"

/* Return */
# define _MC_ERROR		1

/* Size */
// Ethernet frames typically have a maximum payload size of 1500B
# define _MC_MAX_PACKET_SIZE	1500

#define _MC_OP_CODE_ARRAY \
{ \
	"ARP Request",					/* 1 */ \
	"ARP Reply",					/* 2 */ \
	"RARP Request (Reverse ARP)",	/* 3 */ \
	"RARP Reply",					/* 4 */ \
	"DRARP Request (Dynamic RARP)",	/* 5 */ \
	"DRARP Reply",					/* 6 */ \
	"DRARP Error",					/* 7 */ \
	"InARP Request (Inverse ARP)",	/* 8 */ \
	"InARP Reply",					/* 9 */ \
	"ARP NAK"						/* 10 */ \
}

/* Define the structure of the packet according to the RFC 826 specification
 We will use this structure to imitate an authentic packet
 so that the reply to the ARP request will be accepted by the network
*/
typedef struct	_mc_s_packet
{
	struct ethhdr		ethernet_header; 
	struct ether_arp	arp_packet;
}	_mc_t_packet;

// Define the structure of the ARP packet according to the RFC 826 specification
typedef struct _s_mc_arp_header
{
    uint16_t	hardware_type;  // Hardware type (e.g., Ethernet)
    uint16_t	protocol_type;  // Protocol type (e.g., IPv4)
    uint8_t		hardware_size;  // Hardware address length (6 for MAC addr)
    uint8_t		protocol_size;  // Protocol address length (4 for IPv4 addr)
    uint16_t	opcode;         // Operation code (ARP Request or ARP Reply)
    uint8_t		sender_mac[6];  // Sender's MAC address
    uint32_t	sender_ip;      // Sender's IP address
    uint8_t		target_mac[6];  // Target's MAC address
    uint32_t	target_ip;      // Target's IP address
}	_t_mc_arp_header;

/* Global structure */
typedef struct _mc_s_data
{
	bool				verbose;
	int					raw_sockfd;
	struct sockaddr_in	src_addr;
	struct ethhdr*		ethernet_header;
	struct ether_arp	*arp_packet;
	struct arphdr*		arp_header;
	char				*host_mac_str;
	char				*host_ip_str;
	char				*host_mac_byte;
	char				*host_ip_byte;
	char				*target_mac;
	char				*target_ip;
}	_mc_t_data;

extern _mc_t_data	_mc_g_data;

size_t	_mc_strlen(const char *s);
void	_mc_bzero(void *s, size_t n);
int		_mc_strncmp(const char *s1, const char *s2, size_t n);
void	*_mc_memcpy(void *dest, const void *src, size_t n);
int		_mc_isxdigit(int c);

void	_mc_print_usage(void);
void	_mc_print_mac(const unsigned char* mac);
void	_mc_print_ip(const unsigned char* ip);

bool    _mc_is_ip_address_ipv4(const char *ip_addr);
bool 	_mc_is_mac_address_valid(const char *mac_address);

void	_mc_start_sniffing_paquets(void);

#endif
