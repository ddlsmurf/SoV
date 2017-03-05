/* (c) Copyright 2009 Eric Doughty-Papassideris. All Rights Reserved.
**
**  This file is part of oV - Starcraft over VPN v2.0.
**
**	http://s-softs.com/sov.html
**
**  Credits
**  -------
**    - sniffex.c sample by The Tcpdump Group
**	  - WinPCap team
**    - B. Borde, lemarsu for their patience in testing this.
**
**	Portions in SoV_Utils.* under the following notices:
**		Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
**		Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
**
**  License
**  -------
**  IDC v2.0 ("I Dont Care")
**
**  Disclaimer
**  ----------
**  Carefull: I don't want to know about what
**    happened (or not) because of this code.
**    You are running it "as-is",
**    and it "is not my problem".
*/

#include "SoV.h"


/* Printouts */
void				print_stats(globals_t *g)
{
	static long		last = 0;

	// Dont update statistics more than once per second
#ifdef WIN32
	long			ticks;

	ticks = GetTickCount() / 1000;
	if (ticks == last)
		return;
	last = ticks;
#else
	struct timeval	ts;

	gettimeofday(&ts, 0);
	if (ts.tv_sec == last)
		return;
	last = ts.tv_sec;
#endif
	printf("\rCaptured : %i   sent: %i   errors: %i    ",
		g->stats_cntcap, g->stats_cntsent, g->stats_cnterrorsent);
	fflush(stdout);
}

void	print_version()
{
	printf("%s" EOL "%s" EOL EOL, BANNER, pcap_lib_version());
}

void	print_use()
{
	print_version();
	printf(
		"A relay tool that captures outgoing broadcast starcraft packets" EOL
		"and injects them to a specific host." EOL
		EOL
		
		"Use: sov capture_device game_creator_ip" EOL
		"\tcapture_device:  the name of the interface to capture local starcraft packets from." EOL
		"\tgame_creator_ip: the host to forward packets to" EOL
		EOL
		"Arguments:" EOL);
	print_options(sov_arguments);
}

commandline_option_t sov_arguments[] = {
	{"p", "Set interception and forwarding target port", CLO_TYPE_PORT, CLO_SET_FIELD(options_t, port)},
	{"f", "Force PCap filter", CLO_TYPE_STR, CLO_SET_FIELD(options_t, pcap_filter)},
	{"bind", "Use bound UDP socket to forward packets." CLO_EOL
	 "Default is raw UDP packet writing, but it is " CLO_EOL
	 "possible to use a normal bound socket instead with" CLO_EOL
	 "SO_REUSEADDR on some OS. YMMV.", CLO_TYPE_BOOL, CLO_SET_FIELD(options_t, bind_udp_port)},
	{"i", "Inject packets into specified device using PCap (instead of UDP socket)", CLO_TYPE_STR, CLO_SET_FIELD(options_t, inject_device_name)}, 
#ifdef WIN32
	{"esrc", "Specify source MAC adress to use in injected packets", CLO_TYPE_MAC, CLO_SET_FIELD(options_t, inject_ethernet_source)},
	{"edst", "Specify destination MAC adress to use in injected packets", CLO_TYPE_MAC, CLO_SET_FIELD(options_t, inject_ethernet_destination)},
#endif
	{"nost", "Dont print packet statistics", CLO_TYPE_BOOL, CLO_SET_FIELD(options_t, hide_captured_packets_statistics)},
	{"pc", "Print captured packets", CLO_TYPE_BOOL, CLO_SET_FIELD(options_t, show_captured_packets)},
	{"pr", "Print captured packets raw contents", CLO_TYPE_BOOL, CLO_SET_FIELD(options_t, show_captured_packets_raw)},
	{"v", "Verbose - Output status info", CLO_TYPE_BOOL, CLO_SET_FIELD(options_t, verbose)},
	{"l", "List network interfaces", CLO_TYPE_TERMINAL, CLO_CALL(print_interfaces)},
	{"h", "Show this help screen", CLO_TYPE_TERMINAL, CLO_CALL(print_use)},
	{"help", NULL, CLO_TYPE_TERMINAL, CLO_CALL(print_use)},
	{"?", NULL, CLO_TYPE_TERMINAL, CLO_CALL(print_use)},
	{"ver", "Show version information", CLO_TYPE_TERMINAL, CLO_CALL(print_version)},
	{ NULL, NULL, 0, 0 }
};

/* Finalisation */

void	cleanup(globals_t *g)
{
	printf(" shutting down..." EOL);
	cleanup_devices(&g->output_devices);
	sockets_cleanup();
	free_pcapture(g->capture_device);
}

/* Packet queue */
void				dequeue_packet(globals_t *g)
{
	packet_layers_t *cur;

	cur = (packet_layers_t*)dequeue(&(g->packets_to_forward));
	if (!cur) return;
	g->stats_cntsent +=
		output_to_devices(
			&g->output_devices,
			g->hosts,
			cur,
			&g->stats_cnterrorsent);
}

void			add_packet(void *globals, packet_layers_t *packet)
{
	globals_t	*g = (globals_t*)globals;
	char		*debug;

	if (g->option.show_captured_packets || g->option.show_captured_packets_raw) {
		debug = packettos(
			PACKET_LAYER_FIRST,
			packet,
			PACKET_LAYER_LAST - (g->option.show_captured_packets_raw ? 0 : 1),
			g->option.show_captured_packets_raw);
		printf("\nGot packet:\n%s", debug);
		free(debug);
	}
	g->stats_cntcap++;
	enqueue(packet, &(g->packets_to_forward));
}

void			runloop_idle(void *globals)
{
	globals_t	*g = (globals_t*)globals;
	if (QUEUE_COUNT(&(g->packets_to_forward)) > 0)
		dequeue_packet(g);
	if (!g->option.hide_captured_packets_statistics)
		print_stats(g);
}


int			get_arguments(options_t *options, int ac, char **av) {
	char	**rest;
	u_int	cnt;

	options->port = STARCRAFT_PORT;
	
	rest = read_options(options, ac, av, sov_arguments);
	if (!rest)
		return 0;
	
	if (!options->pcap_filter) {
		options->pcap_filter = malloc(SNAP_LEN);
		snprintf(options->pcap_filter, SNAP_LEN, PCAP_FILTER_FORMAT, options->port);
	}
	cnt = count_args(rest);
	if (cnt < 2) {
		fprintf(stderr, "Error: not enough arguments." EOL);
		print_use();
		return 0;
	}
	options->capture_device_name = *rest++;
	options->hosts = rest;
	options->host_count = cnt - 1;

	if (options->inject_device_name)
	{
		if (options->bind_udp_port) {
			fprintf(stderr, "Invalid arguments: cannot bind UDP and use injection" EOL);
			return 0;
		}
#ifdef WIN32
		if (!options->inject_ethernet_source || !options->inject_ethernet_destination) {
			fprintf(stderr, "Invalid arguments: source and destination MAC addresses" EOL
				"are required when using injection under windows." EOL);
			return 0;
		}
#endif
	}

	return 1;
}

int			init_sov(globals_t *g)
{
	u_int	i;

	g->hosts = (hostinfo_t **)malloc(sizeof(hostinfo_t*) * g->option.host_count + 1);
	g->hosts[g->option.host_count] = 0;
	for (i = 0; i < g->option.host_count; i++)
	{
		if (g->option.verbose)
			printf("Resolving host '%s'..." EOL, g->option.hosts[i]);
		g->hosts[i] = get_hostinfo(g->option.hosts[i], g->option.port);
		if (!g->hosts[i])
			return 0;
	}

	if (g->option.inject_device_name)
	{
		if (g->option.verbose)
			printf("Preparing injection device '%s'..." EOL,
			g->option.inject_device_name);
		if (!add_pcap_output_device(&g->output_devices,
			g->option.inject_device_name,
	#ifdef WIN32
			g->option.inject_ethernet_source,
			g->option.inject_ethernet_destination,
	#endif
			g->option.port))
			return 0;
	}
	else
	{
	if (g->option.verbose)
		printf("Opening %s UDP socket on port %d..." EOL,
		g->option.bind_udp_port ? "listening" : "raw",
		g->option.port);
	if (!add_socket_output_device(&g->output_devices,
		g->option.port, !g->option.bind_udp_port))
		return 0;
	}

	if (g->option.verbose)
		printf("Capture '%s' on '%s'" EOL, g->option.pcap_filter, g->option.capture_device_name);
	g->capture_device = init_pcapture(g->option.capture_device_name, g->option.pcap_filter);
	if (!g->capture_device)
		return 0;
	return 1;
}

int				main(int ac, char**av)
{
	globals_t	globals;	

	bzero(&globals, sizeof(globals_t));
	if (!get_arguments(&globals.option, ac, av))
		return -1;
	
	if (globals.option.verbose)
		print_version();

	if (!sockets_init())
		return 0;

	if (!init_sov(&globals))
		return -1;

	if (globals.option.verbose)
		printf("Initialisation complete :)" EOL);

	run_pcapture(globals.capture_device, add_packet, runloop_idle, &globals);

	cleanup(&globals);

	return 0;
}

