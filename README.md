# ft_malcolm

## Description

This project is about implementing the Address Resolution Protocol spoofing/poisoning method, which is one of the most basic Man In The Middle attacks.<br />
This attack is possible using a vulnerability present in the way the ARP protocol works and interacts in a network.<br />

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

## Technical aspects
### ARP spoofing

ARP spoofing is a technique used to manipulate network communication by sending forged ARP packets. In this attack, a malicious actor crafts and sends ARP packets over a network, tricking the network devices into associating the attacker's MAC address with a legitimate IP address. This allows the attacker to intercept and manipulate network traffic. By utilizing raw sockets, the attacker can create and send custom ARP packets, enabling them to carry out the spoofing attack.
```
    1. Monitoring the Network:
        Attacker listens to the network, capturing ARP packets
		through raw socket for sending and receiving network packets.
        Analyzes the captured packets to identify potential targets.

    2. Crafting Spoofed ARP Packets:
        Attacker constructs forged ARP packets with manipulated information.
        Spoofed packets typically contain the attacker's MAC address and a target IP address.

    3. Sending Spoofed ARP Packets:
        Attacker sends the spoofed ARP packets onto the network.
        Packets are broadcasted to all devices within the local network.

    4. Updating ARP Tables:
        Target devices receive the spoofed ARP packets.
        ARP tables on target devices are updated, associating the
		attacker's MAC address with the target IP address.

    5. Interception and Manipulation:
        Attacker now controls network communication between the 
		target and other devices.
        Can intercept, modify, or redirect network traffic as desired.
```

### Raw socket

A raw socket is a type of network socket that provides direct access to the underlying network protocols at a lower level than the standard socket APIs. It allows applications to send and receive network packets at a raw level, bypassing the higher-level protocols and operating system's network stack.

With a raw socket, an application can construct and manipulate network packets at a granular level, including crafting custom headers and handling protocols that are not typically accessible through higher-level APIs. Raw sockets operate at the network or data link layer, depending on the specific implementation and configuration.

### Network packet
When making an ARP request/reply, a packet is generated and sent
to the network. Here's a diagram illustrating such packet:

```
	// Ethernet header
    +-------------------------------+
    |  Destination MAC Address      |
    |        (6 bytes)              |
    +-------------------------------+
    |   Source MAC Address          |
    |        (6 bytes)              |
    +-------------------------------+
    |        EtherType (2 bytes)    |
    +-------------------------------+

	// ARP header
    +-------------------------------+
    |    Hardware Type (2 bytes)    |
    +-------------------------------+
    |    Protocol Type (2 bytes)    |
    +-------------------------------+
    |Hw Addr Len (1 byte)|Prot Addr |
    +-------------------------------+
    |    Operation (2 bytes)        |
    +-------------------------------+
    |    Sender Hardware Address    |
    |        (variable length)      |
    +-------------------------------+
    |    Sender Protocol Address    |
    |        (variable length)      |
    +-------------------------------+
    |    Target Hardware Address    |
    |        (variable length)      |
    +-------------------------------+
    |    Target Protocol Address    |
    |        (variable length)      |
    +-------------------------------+
```
To access a specific layer within a network packet, we can navigate to that layer by moving a certain number of bytes from the start of the packet. Each layer within the packet contributes a specific number of bytes to its overall structure. By understanding the layout of the packet and the headers associated with each layer, we can calculate the offset needed to reach the desired layer. This allows us to extract or manipulate the information specific to that layer.<br />
To determine the length of a variable IP address in the packet, we can rely on the IP type provided within the IP header. 

## Additional functionalities

* Checks for root privileges when launched
* Displays the hostname for the source and the target
* While the verbose mode is on, it displays information about all received random ARP request packets

## Useful links

https://www.youtube.com/watch?v=YJGGYKAV4pA<br />
https://www.youtube.com/watch?v=EC1slXCT3bg