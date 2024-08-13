# ft_malcolm

## Description

This project is about implementing the Address Resolution Protocol spoofing/poisoning method, which is one of the most basic Man In The Middle attacks.<br />
This attack is possible using a vulnerability present in the way the ARP protocol works and interacts in a network.<br />

## Commands

```
/* Usage */

make
sudo ./ft_malcolm [HOST IP] [HOST MAC] [TARGET IP] [TARGET MAC] -v
In that particular order.

HOST = this computer
TARGET = your target sending the ARP request
IP addresses have to be in the IPv4 format,
MAP addresses have to be in format xx:xx:xx:xx:xx:xx
(Separator can be either ':' or '-')
And letters can be both lower and upper case letters
-v: verbose

Ex.: ./ft_malcolm 10.0.2.15 08:00:27:e1:ad:e1 10.0.2.4 08:00:27:b9:e6:05 -v

/* Useful commands */

// Show an easily readable ARP table with no fixed columns
arp -a
// Delete an IP address from the ARP table
arp -d [IP ADDRESS]
// Send an ARP request
sudo arping -c 1 -i [INTERFACE NAME] [TARGET IP ADDRESS]
Ex.: sudo arping -c 1 -i enp0s3 10.24.104.3
```
## Exemple of use

This section provides step-by-step instructions for setting up a Man-in-the-Middle (MiM) attack simulation using our program. The simulation involves two virtual machines (VMs) running on VirtualBox, where one VM performs ARP spoofing to intercept traffic intended for another machine.

1. Open VirtualBox and create 2 VMs (we used Ubuntu) with sufficient specs (we had a 6400MB base memory and 7 CPUs and 42MB of video memory with a VMSVGA graphic controller with 3D acceleration enabled) and create virtual hard disks (10GB is enough).

2. Configure Network Settings:
- In VirtualBox, go to File > Tools > Network Manager.
- On the `NAT Networks` tab, create a new NAT network if one does not already exist.
- Configure both VMs to use that NAT network by selecting a VM, and then selecting `NAT network` option at Settings > Network > Attached to, with the previous network name.

3. Install the required tools on both VMs:
- Ex.: `sudo apt install git make net-tools -y` (net-tools to get the ifconfig command) on VM1.
- Ex.: `sudo apt install net-tools arping -y` on VM2.

4. Start the MiM Attack Program:
- VM1: Clone, compile, and run the program using VM2's IP and MAC addresses as target IP and MAC adresses. VM1 is now listening for ARP requests comming from VM2.
- VM2: send an ARP request to the host IP address.

5. Verify ARP Spoofing:
- Return to VM1 and observe the output of the program. It should indicate that ARP spoofing has been achieved.
- On VM2, check the ARP table to verify the spoofing with `arp -a`. Look for the entry corresponding to the host IP. It should show the MAC address of VM1 (= the 2nd argument given to the program) instead of the host's MAC address.

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
to the network. Here's the structure of such packet:
```
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
```
To access a specific layer within a network packet, we can navigate to that layer by moving a certain number of bytes from the start of the packet. <br />
Each layer within the packet contributes a specific number of bytes to its overall structure.<br />
By understanding the layout of the packet and the headers associated with each layer, we can calculate the offset needed to reach the desired layer. This allows us to extract or manipulate the information specific to that layer.<br />
To determine the length of a variable IP address in the packet, we can rely on the IP type provided within the IP header. 

## Additional functionalities

* Checks for root privileges when launched
* Displays the hostname for the source and the target
* While the verbose mode is on, it displays information about all received random ARP request packets

## Useful links

https://www.youtube.com/watch?v=YJGGYKAV4pA<br />
https://www.youtube.com/watch?v=EC1slXCT3bg<br />
https://www.rfc-editor.org/rfc/rfc826
