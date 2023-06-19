#ifndef _FT_MALCOLM_H
# define _FT_MALCOLM_H

# include <stdbool.h>
# include <unistd.h>
# include <stdint.h>
# include <stdio.h>
# include <arpa/inet.h>			// For inet_addr
# include <stdlib.h>
# include <string.h>
# include <sys/socket.h>
# include <netinet/if_ether.h>
# include <errno.h>

// Colors
# define RED_COLOR "\033[31m"
# define GREEN_COLOR "\033[32m"
# define YELLOW_COLOR "\033[33m"
# define RESET_COLOR "\033[0m"

# define IPV4_ADDR_SIZE	4

#define OP_CODE_ARRAY \
{ \
	"ARP Request",                   /* 1 */ \
	"ARP Reply",                     /* 2 */ \
	"RARP Request (Reverse ARP)",     /* 3 */ \
	"RARP Reply",                     /* 4 */ \
	"DRARP Request (Dynamic RARP)",   /* 5 */ \
	"DRARP Reply",                    /* 6 */ \
	"DRARP Error",                    /* 7 */ \
	"InARP Request (Inverse ARP)",    /* 8 */ \
	"InARP Reply",                    /* 9 */ \
	"ARP NAK"                         /* 10 */ \
}

// Define the structure of the ARP packet according to the RFC 826 specification
typedef struct s_arp_header
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
}	t_arp_header;

#endif
