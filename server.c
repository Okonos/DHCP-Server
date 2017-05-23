#include <stdlib.h>
#include "dhcp.h"


#define DHCP_MAX_SIZE 550


libnet_t *ln;
int sfd;
uint32_t *addr_pool;


void cleanup()
{
	free(addr_pool);
	close(sfd);
	libnet_destroy(ln);
}


void stop(int signo)
{
	exit(EXIT_SUCCESS);
}


char* ipaddr_to_str(uint32_t addr)
{
	struct in_addr sa;
	sa.s_addr = htonl(addr);
	return inet_ntoa(sa);
}


uint32_t get_next_address(uint32_t *addr_pool)
{
	// *addr_pool = htonl(ntohl(*addr_pool) + 1);
	*addr_pool = *addr_pool + 1;
	return *addr_pool;
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
	unsigned char data[DHCP_MAX_SIZE];
	struct libnet_dhcpv4_hdr* hdr;
	unsigned char *options;
	addr_pool = malloc(sizeof(uint32_t));
	*addr_pool = htonl(inet_addr("192.168.56.150"));

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
	printf("Listening on %s\n"
			"Libnet bound to %s\n",
			inet_ntoa(saddr.sin_addr), libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));

	printf("Address pool starting at %s\n\n", ipaddr_to_str(*addr_pool));

	init_context(ln);

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

		uint32_t client_addr = 0;
		unsigned char *opt;
		int i = 3;

		do
		{
			if (*(opt = options + i) == LIBNET_DHCP_DISCOVERADDR)
			{
				// network format
				memcpy(&client_addr, opt + 2, sizeof(uint32_t));
				client_addr = ntohl(client_addr);
				break;
			}
			// move to the next option
			i += options[i+1] + 2;
		}
		while (*opt != LIBNET_DHCP_END && i < (rc - LIBNET_DHCPV4_H));

		if (!client_addr)
		{
			client_addr = get_next_address(addr_pool);
		}
		else
		{
			printf("Request for %s\n", ipaddr_to_str(client_addr));
		}

		switch (options[2])  // DHCP Message Type
		{
			case LIBNET_DHCP_MSGDISCOVER:
				printf("Received %d bytes DISCOVER packet\nOffering %s\n",
						rc, ipaddr_to_str(client_addr));
				send_message(ln, LIBNET_DHCP_MSGOFFER, (client_addr),
						ntohl(hdr->dhcp_xid), hdr->dhcp_chaddr);
				break;

			case LIBNET_DHCP_MSGREQUEST:
				printf("Received %d bytes REQUEST packet\nAcknowledging %s\n",
						rc, ipaddr_to_str(client_addr));
				send_message(ln, LIBNET_DHCP_MSGACK, (client_addr),
						ntohl(hdr->dhcp_xid), hdr->dhcp_chaddr);
				break;

			default:
				printf("Received unknown packet, ignoring\n");
		}

		printf("\n");
	}
}
