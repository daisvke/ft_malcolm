# ft_malcolm

## Description

This project is for educational purposes only. It implements **Address Resolution Protocol (ARP) spoofing/poisoning**, a foundational Man-in-the-Middle (MiM) attack.  
The attack exploits a vulnerability in the ARP protocol, tricking devices into associating the attacker’s MAC address with a legitimate IP address.  

---

## Commands

### Usage
```bash
make
sudo ./ft_malcolm [HOST IP] [HOST MAC] [TARGET IP] [TARGET MAC] -v
```

- **HOST**: This machine (attacker).  
- **TARGET**: The victim device sending ARP requests.  
- **IP Format**: IPv4 (e.g., 192.168.1.1).  
- **MAC Format**: `xx:xx:xx:xx:xx:xx` (separator can be `:` or `-`, case insensitive).  
- **`-v`**: Enables verbose mode.  

#### Example:
```bash
sudo ./ft_malcolm 10.0.2.15 08:00:27:e1:ad:e1 10.0.2.4 08:00:27:b9:e6:05 -v
```

---

### Useful Commands
| Command                           | Description                                                                                  |
|-----------------------------------|----------------------------------------------------------------------------------------------|
| `arp -a`                          | Displays the ARP table in a readable format.                                                 |
| `arp -d [IP ADDRESS]`             | Deletes an IP address from the ARP table.                                                   |
| `sudo arping -c 1 -i [INTERFACE] [IP]` | Sends a single ARP request. Example: `sudo arping -c 1 -i enp0s3 192.168.1.10`              |

---

## Example of Use

The following example simulates a MiM attack using two virtual machines (VMs) in **VirtualBox**.

### Step-by-Step Guide

1. **Set Up Virtual Machines**:
   - Create 2 VMs (e.g., Ubuntu) with sufficient resources:  
     - 6.4 GB memory, 7 CPUs, 42 MB video memory, VMSVGA with 3D acceleration enabled.  
     - Virtual hard disks (10 GB is sufficient).

2. **Configure Network Settings**:
   - Open **VirtualBox > Tools > Network Manager**.  
   - Under the **NAT Networks** tab, create a new NAT network if not already present.  
   - Attach both VMs to the same NAT network:  
     - Select VM > Settings > Network > Attached to: `NAT Network`.

3. **Install Required Tools**:
   - VM1:  
     ```bash
     sudo apt install git make net-tools -y
     ```
   - VM2:  
     ```bash
     sudo apt install net-tools arping -y
     ```

4. **Run the Attack**:
   - **VM1 (Attacker)**:  
     Clone, compile, and execute the program using VM2’s IP and MAC as targets.  
   - **VM2 (Victim)**:  
     Send an ARP request to the attacker’s IP.

5. **Verify Results**:
   - On **VM1**, check the program output for ARP spoofing success.  
   - On **VM2**, inspect the ARP table with `arp -a`.  
     - The attacker’s MAC address should appear in the table for the host’s IP.  

---

## Technical Aspects

### **What is ARP Spoofing?**

**ARP spoofing** manipulates network communication by sending forged ARP packets. This allows an attacker to intercept, modify, or redirect network traffic.  

#### ARP Spoofing Steps:
1. **Monitor the Network**:  
   - Capture ARP packets using raw sockets.
2. **Craft Spoofed Packets**:  
   - Replace the legitimate MAC address with the attacker’s.
3. **Send Forged Packets**:  
   - Broadcast them to the network.
4. **Update ARP Tables**:  
   - Devices update their tables with incorrect MAC-IP mappings.
5. **Intercept/Manipulate Traffic**:  
   - The attacker now controls communication between devices.  

---

### **Raw Sockets**

A **raw socket** provides direct access to network protocols, bypassing standard APIs. This allows granular control of packet creation and manipulation, enabling custom headers and protocols.

---

### **ARP Packet Structure**

Each ARP packet has a specific structure, as shown below:

| **Layer**          | **Field**                    | **Details**                          |
|---------------------|------------------------------|--------------------------------------|
| **Ethernet Header** | Destination MAC Address      | Receiver's MAC address              |
|                     | Source MAC Address          | Sender's MAC address                |
|                     | EtherType                   | Identifies ARP (`0x0806`)           |
| **ARP Header**      | Hardware Type               | Ethernet (`1`)                      |
|                     | Protocol Type               | IPv4 (`0x0800`)                     |
|                     | Hardware Address Length     | MAC address length (`6`)            |
|                     | Protocol Address Length     | IPv4 address length (`4`)           |
|                     | Operation                   | ARP Request (`1`), ARP Reply (`2`)  |
|                     | Sender MAC Address          | Source MAC address                  |
|                     | Sender IP Address           | Source IP address                   |
|                     | Target MAC Address          | Destination MAC address             |
|                     | Target IP Address           | Destination IP address              |

---

### **Network Packet Navigation**

To access specific layers:
- Calculate offsets based on the header sizes.  
- Use raw sockets to extract or manipulate packet fields.  

---

## Additional Functionalities

- **Root Privilege Check**: Ensures the program is run as root.  
- **Verbose Mode**: Displays ARP requests received in real-time.  
- **Hostname Display**: Shows source and target hostnames.  

---

## Useful Links

- [ARP Spoofing Explanation](https://www.youtube.com/watch?v=YJGGYKAV4pA)  
- [Man-in-the-Middle Attack](https://www.youtube.com/watch?v=EC1slXCT3bg)  
- [RFC 826 (ARP Protocol)](https://www.rfc-editor.org/rfc/rfc826)
- [Address Resolution Protocol (ARP) Parameters](https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml)
