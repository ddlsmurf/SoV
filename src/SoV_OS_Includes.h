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

#ifndef SOV_OS_INCLUDES_H_
#define SOV_OS_INCLUDES_H_

#ifdef WIN32
	#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef WIN32
	#include <winsock2.h>
	#include <process.h>
	#include <Ws2tcpip.h>
#else
	#define SOCKET			int
	#define INVALID_SOCKET	-1
	#define SOCKET_ERROR	-1
	#define closesocket		close
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
#endif

#if WIN32
	#define EOL					"\r\n"
	#define SWITCH_CHAR			'/'
	#define SWITCH_CHAR_OTHER	'-'
#else
	#define EOL					"\n"
	#define SWITCH_CHAR			'-'
	#define SWITCH_CHAR_OTHER	'/'
#endif

#ifdef WIN32
	#define bzero					ZeroMemory
	#define bcopy(src, dst, len)	memmove((dst), (src), (len))
	#define snprintf				sprintf_s
	#define strcasecmp				_stricmp
	#define	strlcat(dst,src,len)	strcat_s((dst),(len),(src))
#else
	#include <signal.h>
	#include <sys/time.h>
	#include <unistd.h>
#endif


#define SIZE_ETHERNET		14
#define SIZE_ETHERNET_MAC	6

/* Ethernet, IP and UDP headers */
typedef struct	sniff_ethernet
{
	u_char		ether_dhost[SIZE_ETHERNET_MAC];
	u_char		ether_shost[SIZE_ETHERNET_MAC];
	u_short		ether_type;
}				ether_t;

typedef struct		sniff_ip {
	u_char			ip_vhl; /* version << 4 | header length >> 2 */
	u_char			ip_tos; /* type of service */
	u_short			ip_len; /* total length */
	u_short			ip_id;  /* identification */
	u_short			ip_off; /* fragment offset field */
	u_char			ip_ttl; /* time to live */
	u_char			ip_p;   /* protocol */
	u_short			ip_sum; /* checksum */
	struct in_addr	ip_src,	/* source and dest address */
					ip_dst;
}					ip_t;

#define IP_RF		0x8000	/* reserved fragment flag */
#define IP_DF		0x4000	/* dont fragment flag */
#define IP_MF		0x2000	/* more fragments flag */
#define IP_OFFMASK	0x1fff	/* mask for fragmenting bits */
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

#define IP_PROTOCOL_ICMP	1
#define IP_PROTOCOL_TCP		6
#define IP_PROTOCOL_UDP		17

typedef struct	sniff_icmp
{
	u_char		type;
	u_char		code;
	u_short		crc;
}				icmp_t;


typedef struct	sniff_tcp
{
	u_short		sport;
	u_short		dport;
	u_int		seq;
	u_int		ack;
	u_char		flags[2];
	u_short		checksum;
	u_short		urgent_pointer;
	u_char		options[40];
}				tcp_t;

#define TCP_LEN(tcp)               ((((tcp)->flags[0] >> 4) & 0x0f) * 4)

typedef struct	sniff_udp
{
	u_short		sport;
	u_short		dport;
	u_short		len;
	u_short		crc;
}				udp_t;

#endif