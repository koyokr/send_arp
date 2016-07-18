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
	u_char *interface = (u_char *)malloc(strlen(d->name));
	memcpy(interface, d->name, strlen(d->name));
	// Free the device list
	pcap_freealldevs(alldevs);
	
	// Declare IP, MAC necessary
	// Declare IP String Buffer
	struct data_ip_mac data;
	u_char ip_addr_str[IP_ADDR_STR_SIZE];
	
	// Get my ip, my mac
	get_my_ip_mac(interface, &data.my_ip.s_addr, data.my_mac);
	
	puts("");
	inet_ntop(AF_INET, &data.my_ip.s_addr, ip_addr_str, IP_ADDR_STR_SIZE);
	printf(" my ip:      %s\n", ip_addr_str);
	printf(" my mac:     %02x:%02x:%02x:%02x:%02x:%02x\n", data.my_mac[0], data.my_mac[1], data.my_mac[2], data.my_mac[3], data.my_mac[4], data.my_mac[5]);
	
	// Get gateway ip, victim ip
	get_gateway_ip(interface, &data.gateway_ip.s_addr);
	inet_pton(AF_INET, argv[1], &data.victim_ip.s_addr);
	
	inet_ntop(AF_INET, &data.gateway_ip.s_addr, ip_addr_str, IP_ADDR_STR_SIZE);
	printf(" gateway ip: %s\n", ip_addr_str);
	inet_ntop(AF_INET, &data.victim_ip.s_addr, ip_addr_str, IP_ADDR_STR_SIZE);
	printf(" victim ip:  %s\n", ip_addr_str);
	puts("");

	// Declare ARP packet: 42bytes + 혹시 모르니까 임시로 100바이트 추가 + get_your_mac 함수도 똑같이 선언
	u_char packet[ETH_ARP_H + 100];
	struct eth_arp_hdr *pkt = (struct eth_arp_hdr *)packet;
	
	// 피해자 mac주소 확인: Broadcast에 arp request 보내기 --> 1초 응답 대기 --> 안오면 또 보내기 --> 반복
	// 피해자 감염: 피해자에게 arp reply 패킷 때리기 --> 1초 간격 반복 --> arp request로 감염 확
 	
	/* Send down the packet
	if (pcap_sendpacket(fp, packet, ETH_ARP_H) != 0) {
		perror(pcap_geterr(fp));
		exit(1);
	}
	 */
	 
	return 0;
}

