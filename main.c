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

	printf("Enter the interface number (1-%d): ", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i) {
		perror("\nInterface number out of range.\n");
		// Free the device list
		pcap_freealldevs(alldevs);
		exit(1);
	}

	// Jump to the selected adapter
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	// Open the output device
	fp = pcap_open_live(d->name, 65536, 0, 1000, errbuf);
	if (fp == NULL) {
		perror(errbuf);
		exit(1);
	}
	
	
	// Declare Interface
	u_char *interface = NULL;
	interface = (u_char *)malloc(strlen(d->name));
	memcpy(interface, d->name, strlen(d->name));
	// Free the device list
	pcap_freealldevs(alldevs);
	
	// Declare IP, MAC necessary 
	struct data_ip_mac data;
	// Declare IP String Buffer
	u_char ip_addr_buf[16];
	
	// Get my ip, my mac
	get_my_ip_mac(interface, &data.my_ip.s_addr, data.my_mac);
	
	puts("");
	inet_ntop(AF_INET, &data.my_ip.s_addr, ip_addr_buf, sizeof(ip_addr_buf));
	printf(" my ip:      %s\n", ip_addr_buf);
	printf(" my mac:     %02x:%02x:%02x:%02x:%02x:%02x\n", data.my_mac[0], data.my_mac[1], data.my_mac[2], data.my_mac[3], data.my_mac[4], data.my_mac[5]);
	
	// Get gateway ip, victim ip
	get_gateway_ip(interface, &data.gateway_ip.s_addr);
	inet_pton(AF_INET, argv[1], &data.victim_ip.s_addr);
	
	inet_ntop(AF_INET, &data.gateway_ip.s_addr, ip_addr_buf, sizeof(ip_addr_buf));
	printf(" gateway ip: %s\n", ip_addr_buf);
	inet_ntop(AF_INET, &data.victim_ip.s_addr, ip_addr_buf, sizeof(ip_addr_buf));
	printf(" victim ip:  %s\n", ip_addr_buf);
	puts("");

	// Declare ARP packet: 42bytes + 혹시 모르니까 임시로 100바이트 추가 + get_your_mac 함수도 똑같이 선언
	u_char packet[ETH_ARP_H + 100];
	struct eth_arp_hdr *pkt = (struct eth_arp_hdr *)packet;
	
	// 피해자 ip 주소와, 내 ip, mac 주소를 알면 arp 방송 때려서 mac 주소를 얻자
	
 	
	/* Send down the packet */
	if (pcap_sendpacket(fp, packet, ETH_ARP_H) != 0) {
		perror(pcap_geterr(fp));
		exit(1);
	}
	
	
	return 0;
}

