#include "header.h"

void get_my_ip_mac(const u_char *interface, in_addr_t *my_ip, uint8_t *my_mac) {
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, interface);

	if (ioctl(fd, SIOCGIFADDR, &s) == -1) {
		perror("\nFinding IP is failed.\n");
		exit(1);
	}
	// 왜 2byte를 추가해줘야 할까?
	memcpy(my_ip, s.ifr_addr.sa_data + 2, IP_ADDR_LEN);

	if (ioctl(fd, SIOCGIFHWADDR, &s) == -1) {
		perror("\nFinding MAC is failed.\n");
		exit(1);
	}
	memcpy(my_mac, s.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

#define CMD_BUF_SIZE 128
void get_gateway_ip(const u_char *interface, in_addr_t *gateway_ip) {
	u_char cmd[CMD_BUF_SIZE] = { 0 };
	u_char line[IP_ADDR_STR_SIZE] = { 0 };

	sprintf(cmd, "route -n |grep %s |grep 'UG[ \t]' |awk '{print $2}'", interface);
	FILE* fp = popen(cmd, "r");

	if(fgets(line, IP_ADDR_STR_SIZE, fp) != NULL) {
		line[strlen(line) - 1] = '\0';
		inet_pton(AF_INET, line, gateway_ip);
	}

	pclose(fp);
}

void get_your_mac(const u_char *interface, const in_addr_t your_ip, uint8_t *your_mac) {
	// Declare ARP packet: 42bytes + main 함수도 똑같이 선언
	u_char packet[ETH_ARP_H + 100];
	struct eth_arp_hdr *pkt = (struct eth_arp_hdr *)packet;
	
	
	
}
