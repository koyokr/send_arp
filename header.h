#include <pcap.h>
#include <libnet.h> // sudo apt-get install libnet1*

struct libnet_arp_eth_hdr {
	u_int16_t      ar_hrd;      /* format of hardware address */
	u_int16_t      ar_pro;      /* format of protocol address */
	u_int8_t       ar_hln;      /* length of hardware address */
	u_int8_t       ar_pln;      /* length of protocol addres */
	u_int16_t      ar_op;       /* operation type */
	u_int8_t       arp_shost[ETHER_ADDR_LEN];
	struct in_addr ip_src;
	u_int8_t  arp_dhost[ETHER_ADDR_LEN];
	struct in_addr ip_dst;
};

void get_my_address(u_char *device_name, u_char *ip_address, u_char *mac_address);

