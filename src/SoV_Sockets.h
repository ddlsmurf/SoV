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

#ifndef SOV_SOCKETS_H_
#define SOV_SOCKETS_H_

struct		hostinfo_s {
	char	*name;
	struct	sockaddr_in	sin;
	u_int	ipv4;
}; /* aka hostinfo_t */

typedef	struct	socket_output_s {
	SOCKET		output;
	int			raw;
	u_short		port_src;
	u_short		port_dst;
}				socket_output_t;

int			sockets_init();
void		sockets_cleanup();
hostinfo_t	*get_hostinfo(char *name, u_short port);
int			add_socket_output_device(queue_t *devices, u_short port, int raw);

#endif