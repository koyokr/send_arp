#include "header.h"

// 사용자의 ip와 mac 주소를 얻어옵니다.
void get_my_ip_host(const uint8_t *interface, struct in_addr *my_ip, uint8_t *my_host) {
	struct ifreq ifr;
	int32_t fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(fd < 0) {
		perror( "\nsocket() error\n" );
		exit(1);
	}

	memcpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		perror("\nioctl() error. finding my ip fail.\n");
		exit(1);
	}

	memcpy(&my_ip->s_addr, ifr.ifr_addr.sa_data + (ETHER_ADDR_LEN-IP_ADDR_LEN), IP_ADDR_LEN);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		perror("\nFinding my MAC fail.\n");
		exit(1);
	}
	memcpy(my_host, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

// route -n 명령어에서 gateway ip를 얻습니다.
#define CMD_BUF_SIZE 128
void get_gateway_ip(const uint8_t *interface, struct in_addr *gateway_ip) {
	uint8_t cmd[CMD_BUF_SIZE] = { 0 };
	uint8_t line[IP_ADDR_STR_SIZE] = { 0 };

	sprintf(cmd, "route -n |grep %s |grep 'UG[ \t]' |awk '{print $2}'", interface);
	FILE* fp = popen(cmd, "r");

	if(fgets(line, IP_ADDR_STR_SIZE, fp) == NULL) {
		perror("\nFinding gateway IP fail.\n");
		exit(1);
	}
	line[strlen(line) - 1] = '\0';
	inet_pton(AF_INET, line, &gateway_ip->s_addr);
	pclose(fp);
}

// arp 패킷을 초기화하는 함수입니다.
void init_arp_packet(struct eth_arp_hdr *pkt, const struct data_ip_host *data) {
	// ethernet
	// memset(pkt->eth_h.eth_dhost, MEMSET_BROADCAST, ETHER_ADDR_LEN);
	memcpy(pkt->eth_h.eth_shost, data->my_host, ETHER_ADDR_LEN);
	pkt->eth_h.eth_type = htons(ETHERTYPE_ARP);
	// arp base
	pkt->arp_h.ar_hrd = htons(ARPHRD_ETHER);
	pkt->arp_h.ar_pro = htons(ARPPRO_IP);
	pkt->arp_h.ar_hln = ETHER_ADDR_LEN;
	pkt->arp_h.ar_pln = IP_ADDR_LEN;
	pkt->arp_h.ar_op  = htons(ARPOP_RESERVE); // 0
	// arp add
	memcpy(pkt->arp_h.ar_eth_shost, data->my_host, ETHER_ADDR_LEN);
	memcpy(pkt->arp_h.ar_ip_src_addr, &data->my_ip.s_addr, IP_ADDR_LEN);
	// memset(pkt->arp_h.ar_eth_dhost, MEMSET_NULL, ETHER_ADDR_LEN);
	memset(pkt->arp_h.ar_ip_dst_addr, MEMSET_NULL, IP_ADDR_LEN);
}

// arp 패킷에 필요한 정보를 설정하는 함수입니다.
void set_arp_packet(struct eth_arp_hdr *pkt, const struct in_addr *src_ip, const struct in_addr *dst_ip, const uint8_t *dst_host, const uint16_t opcode) {
	pkt->arp_h.ar_op = htons(opcode);
	memcpy(pkt->arp_h.ar_ip_dst_addr, &src_ip->s_addr, IP_ADDR_LEN);
	memcpy(pkt->arp_h.ar_ip_src_addr, &dst_ip->s_addr, IP_ADDR_LEN);
	// Broadcast
	if (dst_host == NULL) {
		memset(pkt->eth_h.eth_dhost, MEMSET_BROADCAST, ETHER_ADDR_LEN);
		memset(pkt->arp_h.ar_eth_dhost, MEMSET_NULL, ETHER_ADDR_LEN);
	}
	// Destination
	else {
		memcpy(pkt->eth_h.eth_dhost, dst_host, ETHER_ADDR_LEN);
		memcpy(pkt->arp_h.ar_eth_dhost, dst_host, ETHER_ADDR_LEN);
	}
}

// arp 패킷을 보내는 함수입니다.
void send_arp_packet(pcap_t *fp, const uint8_t *packet) {
	if (pcap_sendpacket(fp, packet, ETH_ARP_H) != 0) {
		perror(pcap_geterr(fp));
		exit(1);
	}
}

// arp 패킷을 받는 함수입니다. 패킷을 받을 때까지 계속 대기합니다.
void recv_arp_packet(pcap_t *fp, uint8_t *host, const uint8_t *dst_host, const uint16_t opcode) {
	int res;
	struct pcap_pkthdr *header;
	const uint8_t *packet;
	struct eth_arp_hdr *pkt;

	while ((res = pcap_next_ex(fp, &header, &packet)) >= 0) {
		// Timeout elapsed
		if (res == 0) continue;
		// Check arp
		pkt = (struct eth_arp_hdr *)packet;
		if (pkt->eth_h.eth_type != htons(ETHERTYPE_ARP)) continue;
		if (pkt->arp_h.ar_op != htons(opcode)) continue;
		if (dst_host != NULL) if (strcmp(dst_host, pkt->eth_h.eth_dhost)) continue;
		break;
	}
	if (res == -1) {
		perror(pcap_geterr(fp));
		exit(1);
	}
	if (host != NULL)
		memcpy(host, pkt->eth_h.eth_shost, ETHER_ADDR_LEN);
}

// 주소를 출력하는 함수입니다. main 함수가 지저분한 것 같아 만들었습니다.
void addr_print(const uint8_t *addr, const uint32_t addr_len) {
	uint8_t ip_addr_str[IP_ADDR_STR_SIZE];
	switch (addr_len) {
	case IP_ADDR_LEN:
		inet_ntop(AF_INET, addr, ip_addr_str, IP_ADDR_STR_SIZE);
		printf("%s\n", ip_addr_str);
		break;
	case ETHER_ADDR_LEN:
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		break;
	default:
		break;
	}
}

