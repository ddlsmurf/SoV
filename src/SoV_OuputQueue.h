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

#ifndef SOV_OUPUTQUEUE_H_
#define SOV_OUPUTQUEUE_H_

typedef	int callback_output(void *device, hostinfo_t **remotes,
							packet_layers_t *packet, u_int *errors);

typedef struct		output_device_s {
	callback		*finalizer;
	callback_output	*send;
	void			*device;
}					output_device_t;

void	add_device(queue_t *devices, void *device,
							callback *finalizer, callback_output *sender);
int		output_to_devices(queue_t *devices, hostinfo_t **remotes,
						  packet_layers_t *packet, u_int *errors);
void	cleanup_devices(queue_t *devices);
#endif