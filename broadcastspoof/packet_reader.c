#include "ft_malcolm.h"

int	_mc_handle_received_packet(unsigned char *buffer)
{
	_mc_run_arp_spoofing();
	return 0;
}

// Signal handler function
void _mc_handle_ctrlc(int sig)
{
	(void)sig;
	// Stop the main packet reading loop
	_mc_g_data.stop_loop = true;
    printf("\nCtrl+C caught.\n");
}

int	_mc_start_sniffing_paquets(void)
{
	// Set up the signal handler
    signal(SIGINT, _mc_handle_ctrlc);


    // Create raw socket for capturing ARP packets,
	// and save the file descriptor
    _mc_g_data.raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (_mc_g_data.raw_sockfd == -1)
	{
        fprintf(stderr, _MC_RED_CROSS " Failed to create raw socket");
        close(_mc_g_data.raw_sockfd);
        return 1;
    }

    while (_mc_g_data.stop_loop == false)
		_mc_run_arp_spoofing();

    // Close the raw socket
    close(_mc_g_data.raw_sockfd);
	return 0;
}
