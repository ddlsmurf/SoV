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


int			init_pcapture_interface(pcapdeviceif_t *device, char *device_name) {
	char	errbuf[PCAP_ERRBUF_SIZE];

	device->name = device_name;
	if (pcap_lookupnet(device_name, &(device->net_ip), &(device->net_mask), errbuf) == -1)
	{
		fprintf(stderr, "pcap_lookupnet: Couldn't get netmask for device: %s" EOL, errbuf);
		return 0;
	}
	device->handle = pcap_open_live(device_name, SNAP_LEN, 1, 100, errbuf);
	if (device->handle == NULL)
	{
		fprintf(stderr, "pcap_open_live: Couldn't open device %s: %s" EOL, device_name, errbuf);
		return 0;
	}
	return 1;
}

pcapdevice_t		*init_pcapture(char *device_name, char *filter) {
#ifndef WIN32
	char			errbuf[PCAP_ERRBUF_SIZE];
#endif
	pcapdevice_t	*result;

	NEW(result, pcapdevice_t);
	if (!init_pcapture_interface(&result->dev, device_name))
		goto error;
	if (pcap_datalink(result->dev.handle) != DLT_EN10MB)
	{
		fprintf(stderr, "pcap: %s is not an Ethernet device" EOL,  device_name);
		goto error;
	}
	if (pcap_compile(result->dev.handle, &(result->filter), filter, 0, result->dev.net_ip) == -1)
	{
		fprintf(stderr, "pcap_compile: Couldn't parse filter %s: %s" EOL,
			filter, pcap_geterr(result->dev.handle));
		goto error;
	}
	result->has_filter = 1;
	if (pcap_setfilter(result->dev.handle, &(result->filter)) == -1)
	{
		fprintf(stderr, "pcap_setfilter: Couldn't install filter %s: %s" EOL,
			filter, pcap_geterr(result->dev.handle));
		goto error;
	}
#ifndef WIN32
	if (pcap_setnonblock(result->dev.handle, 1, errbuf) == -1)
	{
		fprintf(stderr, "pcap_setnonblock: Couldn't set device %s to non-blocking mode: %s" EOL, device_name, errbuf);
		goto error;
	}
	if ((result->fd = pcap_get_selectable_fd(result->dev.handle)) == -1)
	{
		fprintf(stderr, "pcap_get_selectable_fd: Failed on %s: %s" EOL,
			device_name, pcap_geterr(result->dev.handle));
		goto error;
	}
#endif
	return result;
error:
	free_pcapture(result);
	return NULL;
}

pcapdevice_t			*store_current_pcapture_loop(pcapdevice_t *device, int store) {
	static pcapdevice_t	*last = NULL;
	if (store)
		last = device;
	return last;
}

/* libpcap callback */
void					got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	void				*user_data;
	callback_pcapture	*packet_cb;
	packet_layers_t		*layers;

	user_data = ((void**)args)[0];
	packet_cb = ((void**)args)[1];
	layers = packet_split(PACKET_LAYER_ETHERNET, packet, header->caplen);
	packet_cb((globals_t *)user_data, layers);
}

int						pcapture_inject(void *udevice,
										hostinfo_t **remotes,
										packet_layers_t *packet,
										u_int *errors)
{
	pcapinjectdevice_t	*device = (pcapinjectdevice_t *)udevice;
	hostinfo_t			**host;
	hostinfo_t			*curhost;
	u_int				sourceip;
	packet_layers_t 	*new_packet;
	int					i = 0;

	sourceip = packet->ip ? packet->ip->ip_src.s_addr : device->dev.net_ip;
	host = (hostinfo_t **)remotes;
	while ((curhost = *host))
	{
		new_packet = build_udp_packet(
#ifdef WIN32
			device->src_mac, device->dst_mac,
			/* on windows you need the ethernet header... which is a problem, yes */
#else
			NULL, NULL, /* on mac anyway pcap adds ethernet itself */
#endif
			sourceip, curhost->ipv4,
			device->port, device->port,
			packet->data, packet->data_size);
		if (pcap_inject(device->dev.handle,
			(void *)
#ifdef WIN32
			new_packet->ether,
			new_packet->ether_size +
#else
			new_packet->ip,
#endif
			new_packet->ip_size +
			new_packet->udp_size +
			new_packet->data_size) < 0)
		{
				fprintf(stderr, "Error: Injecting packet: %s into %s." EOL
					"***Please check sov is running as root (sudo)" EOL,
					pcap_geterr(device->dev.handle), device->dev.name);
				*errors += 1;
		}
		else
			i++;
		free(new_packet);
		host++;
	}
	return i;
}


void free_pcapture_if(pcapdeviceif_t *device) {
	if (device && device->handle) {
		pcap_close(device->handle);
	}
}
void					free_pcapture_injector(void *udevice) {
	pcapinjectdevice_t	*device = (pcapinjectdevice_t *)udevice;
	free_pcapture_if(&device->dev);

	if (device)
		free(device);
}
void free_pcapture(pcapdevice_t *device) {
	free_pcapture_if(&device->dev);
#ifndef WIN32
		if (device->fd > 0)
			close(device->fd);
#endif
	if (device && device->has_filter)
		pcap_freecode(&(device->filter));
	if (device)
		free(device);
}

pcapinjectdevice_t		*add_pcap_output_device(queue_t *devices,
											  char		*device_name,
#ifdef WIN32
											  u_char	*src_mac,
											  u_char	*dst_mac,
#endif
											  u_short	port
											  )
{
	pcapinjectdevice_t	*result;

	NEW(result, pcapinjectdevice_t);
	result->port = port;
#ifdef WIN32
	result->src_mac = src_mac;
	result->dst_mac = dst_mac;
#endif
	if (!init_pcapture_interface(&result->dev, device_name))
		goto error;

	add_device(devices, result, free_pcapture_injector, pcapture_inject);
	return result;
error:
	free_pcapture_injector(result);
	return NULL;
}
void stop_pcapture() {
	pcapdevice_t *device;
	device = store_current_pcapture_loop(NULL, 0);
	if (device)
		pcap_breakloop(device->dev.handle);
	store_current_pcapture_loop(NULL, 1);
}

void	signal_handler(int signum)
{
	printf(EOL "Gotcha!");
	stop_pcapture();
}

#ifdef WIN32
BOOL windows_ctrl_handler(DWORD fdwCtrlType) 
{ 
	switch( fdwCtrlType ) 
	{ 
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT: 
	case CTRL_BREAK_EVENT:
		signal_handler(1);
		return TRUE;

	case CTRL_LOGOFF_EVENT: 
	case CTRL_SHUTDOWN_EVENT: 
		return FALSE; 
	default: 
		return FALSE; 
	} 
}
#endif

void					setupsignals()
{
#ifdef WIN32
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)windows_ctrl_handler,TRUE);
#else
	struct sigaction	new_action,
						old_action;

	new_action.sa_handler = signal_handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction (SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction (SIGINT, &new_action, NULL);
	sigaction (SIGHUP, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction (SIGHUP, &new_action, NULL);
	sigaction (SIGTERM, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction (SIGTERM, &new_action, NULL);
#endif
}

void				run_pcapture(pcapdevice_t *device, callback_pcapture *new_packet, callback *idle, void *user) {
	int				res;
	void			*user_data[2];
#ifndef WIN32
	fd_set			readfds,
					writefds,
					errfds;
	int				maxfd;
	struct timeval	ts;
#endif

	setupsignals();
	user_data[0] = user;
	user_data[1] = new_packet;
	printf("Running... Press CTRL+C to stop." EOL);
	store_current_pcapture_loop(device, 1);
	while (1)
	{
#ifndef WIN32
		FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&errfds);
		FD_SET(device->fd, &readfds);
		FD_SET(device->fd, &errfds);
		maxfd = device->fd + 1;
		ts.tv_sec = 0;
		ts.tv_usec = 100;
		if (select(maxfd, &readfds, &writefds, &errfds, &ts) < 0)
		{
			perror("select failed");
			return;
		}
#endif
		res = pcap_dispatch(device->dev.handle, -1, got_packet, (u_char *)user_data);
		if (res == -2)
			return;
		else if (res == -1) {
			fprintf(stderr, "pcap_dispatch: error: %s" EOL, pcap_geterr(device->dev.handle));
			return;
		}
#ifdef WIN32
		else if (res == 0) {
			Sleep(10);
		}
#endif
		idle(user);
	}
}