#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETH_H         14
#define ARP_H         28
#define ETH_ARP_H     42
#define PAD_H         18 // in arp packet
#define ETH_ARP_PAD_H 60

#define IP_ADDR_LEN      4
#define ETHER_ADDR_LEN   6
#define IP_ADDR_STR_SIZE 16

#define MEMSET_BROADCAST -1
#define MEMSET_NULL       0

#define SEC 1000000

struct eth_hdr {
	// 14 bytes
	uint8_t  eth_dhost[ETHER_ADDR_LEN]; // destination ethernet address
	uint8_t  eth_shost[ETHER_ADDR_LEN]; // source ethernet address
	uint16_t eth_type;                  // protocol
#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806
};

struct arp_hdr {
	// 28 bytes
	// 8 bytes: base
	uint16_t ar_hrd; // format of hardware address
	uint16_t ar_pro; // format of protocol address
#define ARPHRD_ETHER 1
#define ARPPRO_IP    0x0800
	uint8_t  ar_hln; // length of hardware address
	uint8_t  ar_pln; // length of protocol addres
	uint16_t ar_op;  // operation type
#define ARPOP_RESERVE    0
#define ARPOP_REQUEST    1
#define ARPOP_REPLY      2
#define ARPOP_REVREQUEST 3
#define ARPOP_REVREPLY   4
#define ARPOP_INVREQUEST 8
#define ARPOP_INVREPLY   9
	// 20 bytes
	uint8_t  ar_eth_shost[ETHER_ADDR_LEN];
	uint8_t  ar_ip_src_addr[IP_ADDR_LEN]; // preventing padding T^T
	uint8_t  ar_eth_dhost[ETHER_ADDR_LEN];
	uint8_t  ar_ip_dst_addr[IP_ADDR_LEN];
};

struct eth_arp_hdr {
	// 42 bytes
	struct eth_hdr eth_h;
	struct arp_hdr arp_h;
};

struct data_ip_host {
	struct in_addr my_ip;
	struct in_addr gateway_ip;
	struct in_addr victim_ip;
	uint8_t        my_host[ETHER_ADDR_LEN];
	uint8_t        gateway_host[ETHER_ADDR_LEN];
	uint8_t        victim_host[ETHER_ADDR_LEN];
};

// func.c
void get_my_ip_host(const uint8_t *interface, struct in_addr *my_ip, uint8_t *my_host);
void get_gateway_ip(const uint8_t *interface, struct in_addr *gateway_ip);

void init_arp_packet(struct eth_arp_hdr *pkt, const struct data_ip_host *data);
void set_arp_packet(struct eth_arp_hdr *pkt, const struct in_addr *src_ip, const struct in_addr *dst_ip, const uint8_t *dst_host, const uint16_t opcode);

void send_arp_packet(pcap_t *fp, const uint8_t *packet);
void recv_arp_packet(pcap_t *fp, uint8_t *host, const uint8_t *dst_host, const uint16_t opcode);

void addr_print(const uint8_t *addr, const uint32_t addr_len);

