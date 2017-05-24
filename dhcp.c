#include "dhcp.h"

#define BUFF_SIZE 100


libnet_ptag_t ip;
libnet_ptag_t udp;
libnet_ptag_t dhcp;

uint32_t mask;
uint32_t router;
char domain[50] = "";
uint32_t dns;


void read_config(char *filepath)
{
	FILE *fh;
	char buff[BUFF_SIZE];

	fh = fopen(filepath, "r");

	while (fgets(buff, BUFF_SIZE, fh) != NULL)
	{
		char option[100], value[100];
		char tmp[16];

		sscanf(buff, "%s = %s", option, value);
		if (strcmp(option, "mask") == 0)
		{
			strncpy(tmp, value, 15);
			tmp[15] = '\0';
			if ((mask = inet_addr(tmp)) == -1)
				mask = inet_addr("255.255.255.0");
			printf("%u\n", mask);
		}
		else if (strcmp(option, "router") == 0)
		{
			strncpy(tmp, value, 15);
			tmp[15] = '\0';
			if ((router = inet_addr(tmp)) == -1)
				router = 0;
			printf("%u\n", router);
		}
		else if (strcmp(option, "domain") == 0)
		{
			strncpy(domain, value, 50);
			printf("%s\n", domain);
		}
		else if (strcmp(option, "dns") == 0)
		{
			strncpy(tmp, value, 15);
			tmp[15] = '\0';
			if ((dns = inet_addr(tmp)) == -1)
				dns = 0;
			printf("%u\n", dns);
		}
	}

	fclose(fh);
}


void init_context(libnet_t* ln)
{
	uint8_t enet_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	dhcp = libnet_build_dhcpv4(
			LIBNET_DHCP_REPLY,				/* opcode */
			1,                              /* hardware type */
			6,                              /* hardware address length */
			0,                              /* hop count */
			0,								/* transaction id */
			0,                              /* seconds since bootstrap */
			0,								/* flags */
			0,                              /* client ip */
			0,								/* your ip */
			0,                              /* server ip */
			0,                              /* gateway ip */
			0,								/* client hardware addr */
			NULL,                           /* server host name */
			NULL,                           /* boot file */
			NULL,							/* dhcp options in payload */
			0,								/* length of options */
			ln,                             /* libnet context */
			0);								/* libnet ptag */

	udp = libnet_build_udp(
			67,                             /* source port */
			68,                             /* destination port */
			LIBNET_UDP_H + LIBNET_DHCPV4_H, /* packet size */
			0,                              /* checksum */
			NULL,                           /* payload */
			0,                              /* payload size */
			ln,                             /* libnet context */
			0);								/* libnet ptag */

	ip = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DHCPV4_H,	/* length */
			0x10,                           /* TOS */
			0,                              /* IP ID */
			0,                              /* IP Frag */
			16,                             /* TTL */
			IPPROTO_UDP,                    /* protocol */
			0,                              /* checksum */
			0,								/* src ip */
			inet_addr("255.255.255.255"),   /* destination ip */
			NULL,                           /* payload */
			0,                              /* payload size */
			ln,                             /* libnet context */
			0);								/* libnet ptag */

	libnet_autobuild_ethernet(
			enet_dst,                       /* ethernet destination */
			ETHERTYPE_IP,                   /* protocol type */
			ln);							/* libnet context */
}


void send_message(libnet_t* ln, uint8_t msgtype, uint32_t client_ip, uint32_t xid,
		uint8_t* chaddr)
{
	uint8_t* options;
	uint32_t options_len;
	uint32_t server_ip;
	int i = 0;

	options_len = 60; // LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H;
	options = malloc(options_len);
	options[i++] = LIBNET_DHCP_SERVIDENT;
	options[i++] = 4;
	server_ip = libnet_get_ipaddr4(ln);
	memcpy(options + i, (char *)&server_ip, sizeof(server_ip));
	i += sizeof(server_ip);

	options[i++] = LIBNET_DHCP_MESSAGETYPE;
	options[i++] = 1;
	options[i++] = msgtype;

	options[i++] = LIBNET_DHCP_LEASETIME;
	options[i++] = 4;
	uint32_t leasetime = htonl(1200);  // seconds
	memcpy(options + i, (char *)&leasetime, 4);
	i += 4;

	options[i++] = LIBNET_DHCP_SUBNETMASK;
	options[i++] = 4;
	memcpy(options + i, (char *)&mask, 4);
	i += 4;

	if (router != 0)
	{
		options[i++] = LIBNET_DHCP_ROUTER;
		options[i++] = 4;
		memcpy(options + i, (char *)&router, 4);
		i += 4;
	}

	if (dns != 0)
	{
		options[i++] = LIBNET_DHCP_DNS;
		options[i++] = 4;
		memcpy(options + i, (char *)&dns, 4);
		i += 4;
	}

	if (strcmp(domain, "") != 0)
	{
		int len = strlen(domain);
		if (i + len + 1 > options_len)
		{
			options_len = i + len + 1;
			options = realloc(options, options_len);
		}
		options[i++] = LIBNET_DHCP_DOMAINNAME;
		options[i++] = len;
		memcpy(options + i, domain, len);
		i += len;
	}

	options[i++] = LIBNET_DHCP_END;

	// add padding
	if (i < options_len)
		memset(options + i, 0, options_len - i);
	// if (options_len + LIBNET_DHCPV4_H < LIBNET_BOOTP_MIN_LEN)
	// {
	// 	options_len = LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H;
	// 	options = realloc(options, options_len);
	// 	memset(options + i, 0, options_len - i);
	// }

	// uint32_t client_ip = htonl(inet_addr("192.168.56.115"));
	struct libnet_ether_addr *ethaddr;
	ethaddr = (struct libnet_ether_addr*) chaddr;

	libnet_build_dhcpv4(
			LIBNET_DHCP_REPLY,				/* opcode */
			1,                              /* hardware type */
			6,                              /* hardware address length */
			0,                              /* hop count */
			xid,		                    /* transaction id */
			0,                              /* seconds since bootstrap */
			0,								/* flags */
			0,								/* client ip */
			client_ip,                      /* your ip */
			0,                              /* server ip */
			0,                              /* gateway ip */
			ethaddr->ether_addr_octet,		/* client hardware addr */
			NULL,                           /* server host name */
			NULL,                           /* boot file */
			options,                        /* dhcp options in payload */
			options_len,                    /* length of options */
			ln,                             /* libnet context */
			dhcp);							/* libnet ptag */

	libnet_build_udp(
			67,                             /* source port */
			68,                             /* destination port */
			LIBNET_UDP_H + LIBNET_DHCPV4_H + options_len,  /* packet size */
			0,                              /* checksum */
			NULL,                           /* payload */
			0,                              /* payload size */
			ln,                             /* libnet context */
			udp);							/* libnet ptag */

	libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DHCPV4_H
			+ options_len,                  /* length */
			0x10,                           /* TOS */
			0,                              /* IP ID */
			0,                              /* IP Frag */
			16,                             /* TTL */
			IPPROTO_UDP,                    /* protocol */
			0,                              /* checksum */
			server_ip,                      /* src ip */
			inet_addr("255.255.255.255"),   /* destination ip */
			NULL,                           /* payload */
			0,                              /* payload size */
			ln,                             /* libnet context */
			ip);							/* libnet ptag */

	if (libnet_write(ln) == -1)
	{
		fprintf(stderr, "libnet_write: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct libnet_stats ls;
	libnet_stats(ln, &ls);
	fprintf(stderr, "=== Statistics so far ===\n"
			"  Packets sent:  %lld\n"
			"  Packet errors: %lld\n"
			"  Bytes written: %lld\n",
			(long long)ls.packets_sent, (long long)ls.packet_errors,
			(long long)ls.bytes_written);

	free(options);
}
