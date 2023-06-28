# ft_malcolm

## Description

This project is about implementing the Address Resolution
Protocol spoofing/poisoning method, which is one of the most basic Man In The Middle
attacks. This attack is possible using a vulnerability present in the the way the ARP
protocol works and interacts in a network.

## Allowed functions

Only the following functions were used:

◦ sendto, recvfrom.
◦ socket, setsockopt.
◦ inet_pton, inet_ntop.
◦ if_nametoindex, sleep.
◦ getuid, close.
◦ sigaction, signal.
◦ inet_addr.
◦ gethostbyname.
◦ getaddrinfo, freeaddrinfo.
◦ getifaddrs, freeifaddrs.
◦ htons, ntohs.
◦ strerror / gai_strerror.
◦ printf and its family.
◦ write, malloc.

## Usage

Usage: [HOST IP] [HOST MAC] [TARGET IP] [TARGET MAC]<br />
In that particular order.<br />
HOST = this computer<br />
TARGET = your target sending the ARP request<br />
IP addresses have to be in the IPv4 format,<br />
MAP addresses have to be in format xx:xx:xx:xx:xx:xx<br />
(Separator can be either ':' or '-')<br />
And letters can be both lower and upper case letters<br />
-v: verbose

## Additional functionalities
* Checks for root privileges when launched
* Displays information about all received random ARP request packets while the verbose mode is on
