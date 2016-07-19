#include "header.h"

void get_my_ip_host(const u_char *interface, in_addr_t *my_ip, uint8_t *my_host) {
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, interface);

	if (ioctl(fd, SIOCGIFADDR, &s) == -1) {
		perror("\nFinding my IP fail.\n");
		exit(1);
	}
	// 왜 2byte를 추가해줘야 할까?
	memcpy(my_ip, s.ifr_addr.sa_data + 2, IP_ADDR_LEN);

	if (ioctl(fd, SIOCGIFHWADDR, &s) == -1) {
		perror("\nFinding my MAC fail.\n");
		exit(1);
	}
	memcpy(my_host, s.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

#define CMD_BUF_SIZE 128
void get_gateway_ip(const u_char *interface, in_addr_t *gateway_ip) {
	u_char cmd[CMD_BUF_SIZE] = { 0 };
	u_char line[IP_ADDR_STR_SIZE] = { 0 };

	sprintf(cmd, "route -n |grep %s |grep 'UG[ \t]' |awk '{print $2}'", interface);
	FILE* fp = popen(cmd, "r");

	if(fgets(line, IP_ADDR_STR_SIZE, fp) == NULL) {
		perror("\nFinding gateway IP fail.\n");
		exit(1);
	}
	line[strlen(line) - 1] = '\0';
	inet_pton(AF_INET, line, gateway_ip);

	pclose(fp);
}

void init_arp_packet(struct eth_arp_hdr *pkt, const struct data_ip_host *data) {
	// ethernet
	// memset(pkt->_eth->eth_dhost, MEMSET_BROADCAST, ETHER_ADDR_LEN);
	memcpy(pkt->_eth->eth_shost, data->my_host, ETHER_ADDR_LEN);
	pkt->_eth->eth_type = htons(ETHERTYPE_ARP);
	// arp base
	pkt->_arp->ar_hrd = htons(ARPHRD_ETHER);
	pkt->_arp->ar_pro = htons(ARPPRO_IP);
	pkt->_arp->ar_hln = ETHER_ADDR_LEN;
	pkt->_arp->ar_pln = IP_ADDR_LEN;
	pkt->_arp->ar_op  = htons(ARPOP_RESERVE); // 0
	// arp add
	memcpy(pkt->_arp->ar_eth_shost, data->my_host, ETHER_ADDR_LEN);
	memcpy(pkt->_arp->ar_ip_src_addr, &data->my_ip.s_addr, IP_ADDR_LEN);
	// memset(pkt->_arp->ar_eth_dhost, MEMSET_NULL, ETHER_ADDR_LEN);
	memset(pkt->_arp->ar_ip_dst_addr, MEMSET_NULL, IP_ADDR_LEN);
}

void set_arp_packet(struct eth_arp_hdr *pkt, const in_addr_t *ip, const uint8_t *host, const uint16_t opcode) {
	pkt->_arp->ar_op = htons(opcode);
	memcpy(pkt->_arp->ar_ip_dst_addr, ip, IP_ADDR_LEN);
	if (host == NULL) {
		memset(pkt->_eth->eth_dhost, MEMSET_BROADCAST, ETHER_ADDR_LEN);
		memset(pkt->_arp->ar_eth_dhost, MEMSET_NULL, ETHER_ADDR_LEN);
	}
	else {
		memcpy(pkt->_eth->eth_dhost, host, ETHER_ADDR_LEN);
		memcpy(pkt->_arp->ar_eth_dhost, host, ETHER_ADDR_LEN);
	}
}

void send_arp_packet(pcap_t *fp, const u_char *packet) {
	if (pcap_sendpacket(fp, packet, ETH_ARP_H) != 0) {
		perror(pcap_geterr(fp));
		exit(1);
	}
}

void get_your_host(const u_char *interface, struct eth_arp_hdr *pkt_req, struct data_ip_host *data) {
	
	
}

