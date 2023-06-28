# ft_malcolm

## Description

This project is about implementing the Address Resolution Protocol spoofing/poisoning method, which is one of the most basic Man In The Middle attacks.<br />
This attack is possible using a vulnerability present in the way the ARP protocol works and interacts in a network.

## Usage

```
[HOST IP] [HOST MAC] [TARGET IP] [TARGET MAC]
In that particular order.
HOST = this computer
TARGET = your target sending the ARP request
IP addresses have to be in the IPv4 format,
MAP addresses have to be in format xx:xx:xx:xx:xx:xx
(Separator can be either ':' or '-')
And letters can be both lower and upper case letters
-v: verbose
```

## Additional functionalities

* Checks for root privileges when launched
* Displays the hostname for the source and the target
* While the verbose mode is on, it displays information about all received random ARP request packets
