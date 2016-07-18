#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
// sudo apt-get install libnet1*
//#include <libnet.h>

#define ETH_H     14
#define ARP_H     28
#define ETH_ARP_H 42

#define IP_ADDR_LEN    0x4
#define ETHER_ADDR_LEN 0x6

#define IP_ADDR_STR_SIZE 16

struct eth_hdr {
	// 14 bytes
    uint8_t  eth_dhost[ETHER_ADDR_LEN]; // destination ethernet address
    uint8_t  eth_shost[ETHER_ADDR_LEN]; // source ethernet address
    uint16_t eth_type;                  // protocol
};

struct arp_hdr {
	// 28 bytes
	// 8 bytes: base
	uint16_t        ar_hrd;      // format of hardware address
	uint16_t        ar_pro;      // format of protocol address
	uint8_t         ar_hln;      // length of hardware address
	uint8_t         ar_pln;      // length of protocol addres
	uint16_t        ar_op;       // operation type
	// 20 bytes: add
	uint8_t         ar_eth_shost[ETHER_ADDR_LEN];
	struct in_addr ar_ip_src;
	uint8_t         ar_eth_dhost[ETHER_ADDR_LEN];
	struct in_addr ar_ip_dst;
};

struct eth_arp_hdr {
	// 42 bytes
	struct eth_hdr _eth;
	struct arp_hdr _arp;
};

struct data_ip_mac {
	struct in_addr my_ip;
	struct in_addr gateway_ip;
	struct in_addr victim_ip;
	uint8_t         my_mac[ETHER_ADDR_LEN];
	uint8_t         gateway_mac[ETHER_ADDR_LEN];
	uint8_t         victim_mac[ETHER_ADDR_LEN];
};

void get_my_ip_mac(const u_char *interface, in_addr_t *my_ip, uint8_t *my_mac);
void get_gateway_ip(const u_char *interface, in_addr_t *gateway_ip);
void get_your_mac(const u_char *interface, const in_addr_t your_ip, uint8_t *your_mac);
