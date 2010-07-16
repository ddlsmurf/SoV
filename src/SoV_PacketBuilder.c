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
/* Raw packet building code */
u_short			csum(int nwords, u_short *buf)
{
  unsigned long	sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (u_short)(~sum);
}

void build_layer_ethernet(ether_t *ether,
						  u_char *src_mac, u_char *dst_mac) {
	memcpy(ether->ether_shost, src_mac, SIZE_ETHERNET_MAC);
	memcpy(ether->ether_dhost, dst_mac, SIZE_ETHERNET_MAC);
	ether->ether_type = htons(0x0800); // IPv4
}

void build_layer_ip(ip_t *ip, u_int src_ip, u_int dst_ip) {
	ip->ip_vhl = 0x45;
	ip->ip_ttl = 128;
	ip->ip_id = htons(0x6a45); //<- Bogus non null value
	ip->ip_p = 0x11; //UDP
	ip->ip_src.s_addr = src_ip;
	ip->ip_dst.s_addr = dst_ip;
}

void build_layer_udp(udp_t *udp, u_short src_port, u_short dst_port) {
	udp->sport = htons(src_port);
	udp->dport = htons(dst_port);
}

void build_layer_finalise(packet_layers_t *packet) {
	if (packet->ip) {
		packet->ip->ip_len = htons(packet->ip_size + packet->udp_size + packet->data_size);
		packet->ip->ip_sum = csum(packet->ip_size / 2, (u_short*)(packet->ip));
	}
	if (packet->udp) {
		packet->udp->crc = 0; //Really should calculate the correct packet. But this works for now.
		packet->udp->len = htons(packet->udp_size + packet->data_size);
	}
}

packet_layers_t		*build_udp_packet(
						u_char	*src_mac, u_char	*dst_mac,
						u_int   src_ip,   u_int		dst_ip,
						u_short	src_port, u_short	dst_port,
						void *data, size_t len)
{
	u_char			*data_start;
	packet_layers_t *result;
	u_int			result_size;
	int				has_ethernet = src_mac && dst_mac;
	int				has_ip = src_ip && dst_ip;
	int				has_udp = src_port && dst_port;

	result_size = len;
	if (has_ethernet) result_size += sizeof(ether_t);
	if (has_ip) result_size += sizeof(ip_t);
	if (has_udp) result_size += sizeof(udp_t);
	NEWPAD(result,packet_layers_t,result_size);
	data_start = (u_char *)(result + 1);
	bzero(data_start, result_size);
	if (has_ethernet)
	{
		result->ether = (ether_t *)data_start;
		data_start += result->ether_size = sizeof(ether_t);
		build_layer_ethernet(result->ether, src_mac, dst_mac);
	}
	if (has_ip)
	{
		result->ip = (ip_t *)data_start;
		data_start += result->ip_size = sizeof(ip_t);
		build_layer_ip(result->ip, src_ip, dst_ip);
	}
	if (has_udp)
	{
		result->udp = (udp_t *)data_start;
		data_start += result->udp_size = sizeof(udp_t);
		build_layer_udp(result->udp, src_port, dst_port);
	}
	result->data = data_start;
	memcpy(result->data, data, len);
	result->data_size = len;
	build_layer_finalise(result);
	return result;
}

packet_layers_t		*packet_split(u_int first_layer, const u_char *data, u_int len)
{
	void			*data_start;
	packet_layers_t	*result;
	u_int			last_block_size;

	NEWPAD(result, packet_layers_t, len);
	data_start = (void *)(result + 1);
	memcpy(data_start, data, len);
	data = data_start;
	while (first_layer <= PACKET_LAYER_LAST)
	{
		last_block_size = 0;
		switch (first_layer)
		{
		case PACKET_LAYER_ETHERNET:
			result->ether = (ether_t *)data;
			result->ether_size = last_block_size = sizeof(ether_t);
			break;
			
		case PACKET_LAYER_IP:
			result->ip = (ip_t *)data;
			result->ip_size = last_block_size = IP_HL(result->ip) * 4;
			break;
			
		case PACKET_LAYER_UDP:
			if (!result->ip || result->ip->ip_p == IP_PROTOCOL_UDP)
			{
				result->udp = (udp_t *)data;
				result->udp_size = last_block_size = sizeof(udp_t);
			}
			break;
			
		case PACKET_LAYER_ICMP:
			if (!result->ip || result->ip->ip_p == IP_PROTOCOL_ICMP)
			{
				result->icmp = (icmp_t *)data;
				result->icmp_size = last_block_size = sizeof(icmp_t);
			}
			break;

		case PACKET_LAYER_TCP:
			if (!result->ip || result->ip->ip_p == IP_PROTOCOL_TCP)
			{
				result->tcp = (tcp_t *)data;
				result->tcp_size = last_block_size = TCP_LEN(result->tcp);
			}
			break;

		case PACKET_LAYER_DATA:
			result->data = (void*)data;
			result->data_size = last_block_size = len;
			if (result->udp) {
				if (((u_int)ntohs(result->udp->len) - result->udp_size) != len) {
					result->data_size = ntohs(result->udp->len) - result->udp_size;
					fprintf(stderr, "\nWarning: Inconsistent packet size (%u instead of %hu)\n",
						len, ntohs(result->udp->len) - result->udp_size);
				}
			}
			break;
		}
		if (last_block_size != 0) {
			data += last_block_size;
			len -= last_block_size;
		}
		first_layer++;
	}
	return result;
}
