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


#ifndef SOV_H_
#define SOV_H_

#include "SoV_OS_Includes.h"

#define NEWPAD(name, type, extra)	name = (type*)malloc(sizeof(type) + extra); \
									if (name) bzero(name, sizeof(type));
#define NEW(name, type)				NEWPAD(name,type,0);

typedef	struct hostinfo_s hostinfo_t; /* Need a forward declaration on this, the rest in SoV_Sockets.h */

typedef	void callback_empty();
typedef	void callback(void *param);

#include "SoV_Constants.h"
#include "SoV_Queue.h"
#include "SoV_PacketBuilder.h"
#include "SoV_OuputQueue.h"
#include "SoV_Sockets.h"
#include "SoV_PCap.h"
#include "SoV_Utils.h"
#include "SoV_CommandLineArguments.h"

typedef struct	options_s
{
	int			port;
	int			show_captured_packets;
	int			show_captured_packets_raw;
	int			hide_captured_packets_statistics;
	int			verbose;
	int			bind_udp_port;
	char		*pcap_filter;
	char		*capture_device_name;
	char		**hosts;
	char		*inject_device_name;
#ifdef WIN32
	u_char		*inject_ethernet_source;
	u_char		*inject_ethernet_destination;
#endif
	u_int		host_count;
}					options_t;

/* Global variables */
typedef struct		globals_s
{
	pcapdevice_t	*capture_device;		/* Capture interface for good packets  */
	options_t		option;					/* Command line arguments */
	hostinfo_t		**hosts;				/* Target hosts */
	DEFINE_QUEUE(	packets_to_forward);		/* Packet queue (yes, old school) */
	DEFINE_QUEUE(	output_devices);			/* Output devices to use */

	/* Statistics */
	u_int			stats_cntcap;
	u_int			stats_cntsent;
	u_int			stats_cnterrorsent;
}					globals_t;

extern commandline_option_t sov_arguments[];

#endif