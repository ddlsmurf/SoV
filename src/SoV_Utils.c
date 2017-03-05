/* (c) Copyright 2009 Eric Doughty-Papassideris. All Rights Reserved.
**
**  This file is part of oV - Starcraft over VPN v2.0.
**
**	http://s-softs.com/sov.html
**
**  License: IDC v2.0 ("I Dont Care")
**
**  Disclaimer: I don't want to know about what happened (or not) because of this code.
**  			You are running it "as-is", and it "is not my problem".
*/

#include "SoV.h"


char		*hexprint(u_char *data, u_int len, char *separators) {
	char	*res = malloc(len * 3 + 1);
	u_int	i;
	if (!data)
		return "<NULL>";
	for (i = 0; i < len; i++)
	{
		res[i * 3] = "0123456789ABCDEF"[(data[i] >> 4) & 0xf];
		res[i * 3 + 1] = "0123456789ABCDEF"[data[i] & 0xf];
		res[i * 3 + 2] = i == len - 1 ? 0 : (
			i % 4 == 3 ? (
			i % 16 == 15 ? separators[2] : separators[1]
			) : separators[0]);
	}
	res[len * 3] = 0;
	return res;
}
char	*hexdump(u_char *data, u_int len) {
	return hexprint(data, len, " \t\n");
}
char	*mactos(u_char *mac) {
	return hexprint(mac, SIZE_ETHERNET_MAC, ":::");
}

int	hexchar(char c) {
	if (!c) return -2;
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}
u_char		*parse_mac_addr(char *mac)
{
	char	*text;
	int		i;
	int		cur_char;
	int		cur_byte;
	u_char	*result;

	text = mac;
	result = (u_char*)malloc(SIZE_ETHERNET_MAC);
	i = 0;
	while (i < SIZE_ETHERNET_MAC)
	{
		while ((cur_char = hexchar(*text++)) == -1)
			;
		if (cur_char == -2) goto error;
		cur_byte = cur_char;
		while ((cur_char = hexchar(*text++)) == -1)
			;
		if (cur_char == -2) goto error;
		cur_byte = (cur_byte << 4) + cur_char;
		result[i++] = (u_char)cur_byte;
	}
	while ((cur_char = hexchar(*text++)) == -1)
			;
	if (cur_char != -2)
		fprintf(stderr, "Warning: '%s' is too long for a valid mac address." EOL, mac);
	return result;
error:
	free(result);
	fprintf(stderr, "Error: '%s' is not a valid mac address." EOL, mac);
	return NULL;
}

u_int		count_args(char **av)
{
	u_int	result = 0;
	while (*av++) result++;
	return result;
}

char		*packettos(u_int first_layer, packet_layers_t *packet, u_int last_layer, u_int with_raw) {
	int		line;
	char	*res;
	char	buffer[SNAP_LEN];

	res = NULL;
	while (first_layer <= last_layer)
	{
		line = 0;
		switch (first_layer)
		{
		case PACKET_LAYER_ETHERNET:
			if (packet->ether) {
				line = snprintf(buffer, SNAP_LEN,
					"%s\n  =ethe: from %s to %s\n",
					with_raw ? hexdump((u_char *)packet->ether, packet->ether_size) : "",
					mactos((u_char *)packet->ether->ether_shost),
					mactos((u_char *)packet->ether->ether_dhost));
			}
			break;
			
		case PACKET_LAYER_IP:
			if (packet->ip) {
				line = snprintf(buffer, SNAP_LEN,
					"%s\n  =  ip: from %s to %s\n",
					with_raw ? hexdump((u_char *)packet->ip, packet->ip_size) : "",
					iptos(packet->ip->ip_src.s_addr),
					iptos(packet->ip->ip_dst.s_addr));
			}
			break;
			
		case PACKET_LAYER_ICMP:
			if (packet->icmp)
			{
				line = snprintf(buffer, SNAP_LEN,
					"%s\n  =icmp: type %i (code %i)\n",
					with_raw ? hexdump((u_char *)packet->icmp, packet->icmp_size) : "",
					(int)packet->icmp->type,
					(int)packet->icmp->code);
			}
			break;

		case PACKET_LAYER_TCP:
			if (packet->tcp)
			{
				line = snprintf(buffer, SNAP_LEN,
					"%s\n  = tcp: from port %hu to %hu, %d data offset\n",
					with_raw ? hexdump((u_char *)packet->tcp, packet->tcp_size) : "",
					ntohs(packet->tcp->sport),
					ntohs(packet->tcp->dport),
					TCP_LEN(packet->tcp));
			}
			break;

		case PACKET_LAYER_UDP:
			if (packet->udp) {
				line = snprintf(buffer, SNAP_LEN,
					"%s\n  = udp: from port %hu to %hu, %u byte payload\n",
					with_raw ? hexdump((u_char *)packet->udp, packet->udp_size) : "",
					ntohs(packet->udp->sport),
					ntohs(packet->udp->dport),
					ntohs(packet->udp->len) - packet->udp_size);
			}
			break;

		case PACKET_LAYER_DATA:
			if (packet->data) {
				line = snprintf(buffer, SNAP_LEN,
					"%s\n  =data: of len %u\n",
					with_raw ? hexdump((u_char *)packet->data, packet->data_size) : "",
					packet->data_size);
			}
			break;
		}
		buffer[SNAP_LEN - 1] = 0; // ya never know
		if (line) {
			if (!res) {
				res = malloc(SNAP_LEN);
				res[0] = 0;
			}
			strlcat(res, buffer + (with_raw ? 0 : 1), SNAP_LEN);
		}
		first_layer++;
	}
	return res;
}

/* The next piece of code is shamelessy copied from the winpcap bundle example "iflist", which holds
the following notice. (I adapted the code, so get your own copy from another source) */
/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	snprintf(output[which], 3*4+3+1, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

	#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
	#else
	sockaddrlen = sizeof(struct sockaddr_storage);
	#endif


	if(getnameinfo(sockaddr, 
		sockaddrlen, 
		address, 
		addrlen, 
		NULL, 
		0, 
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
#endif /* __MINGW32__ */

void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
#ifdef PRINT_FULL_PACKET_DETAILS
  char ip6str[128];
#endif

  printf(EOL "%s" EOL,d->name);
  if (d->description)
	  printf("\tDescription: %s%s" EOL,d->description, d->flags & PCAP_IF_LOOPBACK ? " (loopback)" : "");
  for(a=d->addresses;a;a=a->next) {
    switch(a->addr->sa_family)
    {
      case AF_INET:
#ifdef PRINT_FULL_PACKET_DETAILS
        printf("\tAddress Family Name: AF_INET" EOL);
#endif
		printf("\t%-16s", !a->addr ? "n/a" : iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        printf(" mask: %-16s", !a->netmask ? "n/a" : iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        printf(" cast: %-16s", !a->broadaddr ? "n/a" : iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        printf(" gate: %-16s" EOL,!a->dstaddr ? "n/a" : iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;

#ifdef PRINT_FULL_PACKET_DETAILS
	  case AF_INET6:
       printf("\tAddress Family Name: AF_INET6" EOL);
#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
        if (a->addr)
          printf("\tAddress: %s" EOL, ip6tos(a->addr, ip6str, sizeof(ip6str)));
#endif
		break;

	  default:
        printf("\tAddress Family Name: Unknown (#%d)" EOL, a->addr->sa_family);
        break;
#endif
    }
  }
}

void	print_interfaces()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int count = 0;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	
	printf(
		EOL
		EOL
		"Here is a list of active accessible interface names :" EOL);
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s" EOL, errbuf);
		exit(1);
	}
	
	/* Scan the list printing every entry that has an address */
	for(d = alldevs; d; d = d->next)
	{
		if (d->addresses) {
			ifprint(d);
			count++;
		}
	}
	if (count == 0) {
		fprintf(stderr,"\tNo interfaces found."
#ifdef WIN32
			" Did you run with Administrative rights ?"
#else
			" Did you use sudo ?"
#endif
			EOL);
	}

	/* Free the device list */
	pcap_freealldevs(alldevs);
}
