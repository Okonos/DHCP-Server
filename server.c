#include <stdlib.h>
#include "dhcp.h"


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

	// bind to interface
	// struct ifreq ifr;
	// // ifr.ifr_name po prostu?
	// strncpy(ifr.ifr_ifrn.ifrn_name, interface_name, IFNAMSIZ);
	// res = setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr));
	// if (res < 0)
	// {
	// 	fprintf(stderr, "Error binding socket to interface\n");
	// 	exit(EXIT_FAILURE);
	// }

	int rc;
	struct sockaddr_in saddr, caddr;
	char *data;
	struct libnet_dhcpv4_hdr* hdr;
	char* options;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;  // inet_addr("255.255.255.255");
	saddr.sin_port = htons(67);
	if (bind(sfd, (struct sockaddr*) &saddr, sizeof(saddr)) < 0)
	{
		fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int ip = libnet_get_ipaddr4(ln);
	printf("Listening on %s\nLibnet bound to %s\n", inet_ntoa(saddr.sin_addr),
			libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));

	init_context(ln);

	// main loop
	while (1)
	{
		data = malloc(550);
		memset(&caddr, 0, sizeof(caddr));
		socklen_t sl = sizeof(caddr);
		rc = recvfrom(sfd, data, 550, 0, (struct sockaddr*) &caddr, &sl);

		hdr = (struct libnet_dhcpv4_hdr*) data;
		options = data + LIBNET_DHCPV4_H;

		switch (options[2])  // DHCP Message Type
		{
			case LIBNET_DHCP_MSGDISCOVER:
				printf("Received %d bytes DISCOVER packet\nSending OFFER\n", rc);
				send_message(ln, LIBNET_DHCP_MSGOFFER, ntohl(hdr->dhcp_xid),
						hdr->dhcp_chaddr);
				break;

			case LIBNET_DHCP_MSGREQUEST:
				printf("Received %d bytes REQUEST packet\n", rc);
				send_message(ln, LIBNET_DHCP_MSGACK, ntohl(hdr->dhcp_xid),
						hdr->dhcp_chaddr);
				break;

			default:
				printf("Received unknown packet, ignoring\n");
		}

		free(data);
	}
}
