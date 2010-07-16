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

#ifndef SOV_PACKETBUILDER_H_
#define SOV_PACKETBUILDER_H_

#define PACKET_LAYER_ETHERNET	0
#define PACKET_LAYER_IP			1
#define PACKET_LAYER_UDP		2
#define PACKET_LAYER_ICMP		3
#define PACKET_LAYER_TCP		4
#define PACKET_LAYER_DATA		5
#define PACKET_LAYER_FIRST		PACKET_LAYER_ETHERNET
#define PACKET_LAYER_LAST		PACKET_LAYER_DATA

typedef struct	packet_layers_s {
	ether_t 	*ether;
	u_int		ether_size;
	ip_t		*ip;
	u_int		ip_size;
	udp_t		*udp;
	u_int		udp_size;
	icmp_t		*icmp;
	u_int		icmp_size;
	tcp_t		*tcp;
	u_int		tcp_size;
	void		*data;
	u_int		data_size;
}				packet_layers_t;

packet_layers_t *build_udp_packet(
	u_char	*src_mac, u_char	*dst_mac,
	u_int   src_ip,   u_int		dst_ip,
	u_short	src_port, u_short	dst_port,
	void *data, size_t len);
packet_layers_t *packet_split(u_int first_layer, const u_char *data, u_int len);

#endif