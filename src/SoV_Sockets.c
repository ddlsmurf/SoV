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

int			sockets_init() {
#ifdef WIN32
	int		startup_result;
	WSADATA	wsaData;

	startup_result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (startup_result != 0) {
        fprintf(stderr, "WSAStartup failed: %d" EOL, startup_result);
        return 0;
    }
#endif
	return 1;
}
void sockets_cleanup() {
#ifdef WIN32
	WSACleanup();
#endif
}

hostinfo_t				*get_hostinfo(char *name, u_short port)
{
	hostinfo_t			*result;
#ifdef WIN32	
	struct sockaddr_in	*ipv4;
	struct addrinfo		*addrresult = NULL;
    struct addrinfo		*ptr = NULL;
	struct addrinfo		hints;
	DWORD				iResult;
#else
	struct hostent		*host;
#endif

	NEW(result,hostinfo_t);
	result->name = name;

#ifdef WIN32
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
	iResult = getaddrinfo(name, NULL, &hints, &addrresult);
	if (iResult != 0) {
		fprintf(stderr, "Error resolving '%s': getaddrinfo failed with error: %d\n", name, iResult);
		return 0;
	}
	for (ptr = addrresult; ptr != NULL ;ptr = ptr->ai_next) {
		if (ptr->ai_family == AF_INET) {
			ipv4 = (struct sockaddr_in *) ptr->ai_addr;
			bcopy(ipv4, &(result->sin), sizeof(struct sockaddr_in));
			break;
		}
	}
#else
	host = gethostbyname(name);
	if (host == NULL)
		return NULL;
	if (host->h_length != sizeof(int)) {
		fprintf(stderr, "Error resolving '%s': Weirdness detected, address length %hu." EOL, name, host->h_length);
		return NULL;
	}
	bcopy(host->h_addr, &(result->sin.sin_addr), host->h_length);
#endif

	result->sin.sin_family = AF_INET;
	result->sin.sin_port = htons(port);
	bcopy((void *)&result->sin.sin_addr, &(result->ipv4), sizeof(result->ipv4));
#ifdef WIN32
	freeaddrinfo(addrresult);
#endif
	return result;
}

SOCKET					socket_output_init(u_short port, int raw) {
	struct sockaddr_in	local;
	int					true_int;
	SOCKET				socket_handle;
	char				*failure;

	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	true_int = 1;
	socket_handle = socket(AF_INET, raw ? SOCK_RAW : SOCK_DGRAM, IPPROTO_UDP);
	if (socket_handle == INVALID_SOCKET) {
		failure = "Error: socket() failed";
		goto error;
	}
	if (!raw)
	{
		if (setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, (char *)&true_int, sizeof(true_int)) == SOCKET_ERROR) {
			failure = "Error: setsockopt(SO_REUSEADDR) failed";
			goto error;
		}
		if (bind(socket_handle, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR) {
			failure = "Error: bind failed";
			goto error;
		}
	}
	return socket_handle;
error:
	#ifdef WIN32
	fprintf(stderr, "%s. %ld" EOL, failure, WSAGetLastError());
	#else
	perror(failure);
	#endif
    if (socket_handle != INVALID_SOCKET)
		closesocket(socket_handle);
	return INVALID_SOCKET;
}

int					socket_send(void *udevice,
								hostinfo_t **remotes,
								packet_layers_t *packet,
								u_int *errors)
{
	socket_output_t	*device = (socket_output_t *)udevice;
	hostinfo_t		**host;
	hostinfo_t		*curhost;
	packet_layers_t	*new_packet;
	char			*data;
	u_int			size;
	int				i;

	i = 0;
	new_packet = NULL;
	data = (char *)packet->data;
	size = packet->data_size;
	if (device->raw) {
		new_packet = build_udp_packet(
			NULL, NULL, 0, 0,
			device->port_src,
			device->port_dst,
			packet->data, packet->data_size);
		data = (char *)new_packet->udp;
		size = new_packet->udp_size + new_packet->data_size;
	}
	host = (hostinfo_t **)remotes;
	while ((curhost = *host))
	{
		if (sendto(device->output,
			data,
			size, 0,
			(struct sockaddr*)&curhost->sin,
			sizeof(struct sockaddr_in)) != SOCKET_ERROR)
				i++;
		else
			*errors += 1;
		host++;
	}
	if (new_packet)
		free(new_packet);
	return i;
	//device->
}
void				socket_cleanup(void *udevice)
{
	socket_output_t	*device = (socket_output_t*)udevice;
	closesocket(device->output);
	free(device);
}
int					add_socket_output_device(queue_t *devices, u_short port, int raw)
{
	socket_output_t	*result;

	NEW(result, socket_output_t);

	result->raw = raw;
	result->port_src = port;
	result->port_dst = port;
	result->output = socket_output_init(port, raw);

	if (result->output == INVALID_SOCKET)
	{
		free(result);
		return 0;
	}
	add_device(devices, result, socket_cleanup, socket_send);
	return 1;
}

