# ft_malcolm

This project is about  mplementing the Address Resolution
Protocol spoofing/poisoning method, which is one of the most basic Man In The Middle
attacks. This attack is possible using a vulnerability present in the the way the ARP
protocol works and interacts in a network.

## Usage

Usage: [HOST IP] [HOST MAC] [TARGET IP] [TARGET MAC]<br />
In that particular order.<br />
HOST = this computer<br />
TARGET = your target sending the ARP request<br />
IP addresses have to be in the IPv4 format,<br />
MAP addresses have to be in format xx:xx:xx:xx:xx:xx<br />
(Separator can be either ':' or '-')<br />
-v: verbose