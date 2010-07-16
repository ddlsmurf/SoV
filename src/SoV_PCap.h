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

#ifndef SOV_PCAP_H_
#define SOV_PCAP_H_

#include <pcap.h>

#define SNAP_LEN 65535

#ifdef WIN32
	#define pcap_inject	pcap_sendpacket
#endif

typedef	void callback_pcapture(void *g, packet_layers_t *packet);

typedef struct		pcapdeviceif_s {
	char			*name;
	pcap_t			*handle;
	bpf_u_int32		net_mask;
	bpf_u_int32		net_ip;
}					pcapdeviceif_t;

typedef struct			pcapdevice_s {
	pcapdeviceif_t		dev;
#ifndef WIN32
	int					fd;
#endif
	int					has_filter;
	struct bpf_program	filter;
}						pcapdevice_t;

typedef struct		pcapinjectdevice_s {
	pcapdeviceif_t	dev;
#ifdef WIN32
	u_char			*src_mac;
	u_char			*dst_mac;
#endif
	u_short			port;
}					pcapinjectdevice_t;

pcapdevice_t			*init_pcapture(char *device_name, char *filter);
void					run_pcapture(pcapdevice_t *device,callback_pcapture *new_packet, callback *idle, void *user);
void					stop_pcapture();
void					free_pcapture(pcapdevice_t *device);
pcapinjectdevice_t		*add_pcap_output_device(queue_t *devices,
											  char		*device_name,
#ifdef WIN32
											  u_char	*src_mac,
											  u_char	*dst_mac,
#endif
											  u_short	port
											  );

#endif
