#include <stdlib.h>
#include "dhcp.h"


#define DHCP_MAX_SIZE 550


libnet_t *ln;
int sfd;


void cleanup()
{
	close(sfd);
	libnet_destroy(ln);
}


void stop(int signo)
{
	exit(EXIT_SUCCESS);
}


int main(int argc, char** argv)
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	char *interface_name;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s interface\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	interface_name = argv[1];

	ln = libnet_init(LIBNET_LINK, interface_name, errbuf);

	if (!ln)
	{
		fprintf(stderr, "libnet_init: %s", errbuf);
		exit(EXIT_FAILURE);
	}

	atexit(cleanup);
	signal(SIGINT, stop);

	int res;

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int broadcast = 1;
	res = setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
	if (res < 0)
	{
		fprintf(stderr, "Error setting socket broadcast option: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int rc;
	struct sockaddr_in saddr, caddr;
	unsigned char data[DHCP_MAX_SIZE];
	struct libnet_dhcpv4_hdr* hdr;
	unsigned char *options;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;  // inet_addr("255.255.255.255");
	saddr.sin_port = htons(67);
	if (bind(sfd, (struct sockaddr*) &saddr, sizeof(saddr)) < 0)
	{
		fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	uint32_t ip = libnet_get_ipaddr4(ln);
	printf("Listening on %s\n"
			"Libnet bound to %s\n",
			inet_ntoa(saddr.sin_addr), libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));

	// get interface netmask
	struct ifreq ifr;
	struct sockaddr_in *nmask;
	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);
	ioctl(sfd, SIOCGIFNETMASK, &ifr);
	nmask = (struct sockaddr_in*) &ifr.ifr_netmask;
	uint32_t netmask = nmask->sin_addr.s_addr;
	printf("Interface netmask: %s\n", ipaddr_to_str(ntohl(netmask)));

	read_config(netmask);
	init_context(ln);

	printf("\n");

	// main loop
	while (1)
	{
		memset(&data, 0, sizeof(data));
		memset(&caddr, 0, sizeof(caddr));
		socklen_t sl = sizeof(caddr);
		rc = recvfrom(sfd, data, DHCP_MAX_SIZE, 0, (struct sockaddr*) &caddr, &sl);

		hdr = (struct libnet_dhcpv4_hdr*) data;
		// pointer to dhcp packet payload
		options = data + LIBNET_DHCPV4_H;

		reply(ln, rc, options, ntohl(hdr->dhcp_xid), hdr->dhcp_chaddr);

		printf("\n");
	}
}
