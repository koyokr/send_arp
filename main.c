#include "header.h"

int main(int argc, char *argv[]) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Check the validity of the command line */
	if (argc != 2) {
		printf("Usage: %s <Victim IP>\n", argv[0]);
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

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i) {
		perror("\nInterface number out of range.\n");
		// Free the device list
		pcap_freealldevs(alldevs);
		exit(1);
	}

	// Jump to the selected adapter
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	/* Open the output device */
	fp = pcap_open_live(d->name, 65536, 0, 1000, errbuf);
	if (fp == NULL) {
		perror(errbuf);
		exit(1);
	}

	u_char s_ip[4], s_mac[ETHER_ADDR_LEN];

	get_my_address(d->name, s_ip, s_mac);
	printf("%d.%d.%d.%d\n", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
	// 공유기 IP 알아내는 방법만 알면 됨

	u_char packet[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H];
	struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)packet;
	struct libnet_arp_eth_hdr *arp = (struct libnet_arp_eth_hdr *)packet + LIBNET_ETH_H;
	// 피해자 ip 주소와, 내 ip, mac 주소를 알면 arp 방송 때려서 mac 주소를 얻자
	
	/* Fill the rest of the packet */
	for (int i = 12; i<100; i++) {
		packet[i] = i % 256;
	}

	/* Send down the packet */
	if (pcap_sendpacket(fp, packet, 100 /* size */) != 0) {
		perror(pcap_geterr(fp));
		exit(1);
	}
	
	// Free the device list
	pcap_freealldevs(alldevs);
	return 0;
}

