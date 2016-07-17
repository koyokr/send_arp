#include "header.h"

void get_my_address(u_char *device_name, u_char *ip_address, u_char *mac_address) {
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, device_name);

	if (ioctl(fd, SIOCGIFADDR, &s) == -1) {
		perror("");
		exit(1);
	}
	memcpy(ip_address, s.ifr_addr.sa_data+2, 4);

	if (ioctl(fd, SIOCGIFHWADDR, &s) == -1) {
		perror("");
		exit(1);
	}
	memcpy(mac_address, s.ifr_hwaddr.sa_data, 6);
}
