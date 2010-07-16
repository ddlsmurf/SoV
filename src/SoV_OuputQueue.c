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

void				add_device(queue_t *devices, void *device,
							callback *finalizer, callback_output *sender)
{
	output_device_t *new_device;
	
	NEW(new_device, output_device_t);
	new_device->device = device;
	new_device->finalizer = finalizer;
	new_device->send = sender;
	enqueue(new_device, devices);
}
int					output_to_devices(queue_t *devices, hostinfo_t **remotes,
						  packet_layers_t *packet, u_int *errors)
{
	output_device_t	*device;
	int				i;
	USES_QUEUE_FOREACH;

	i = 0;
	QUEUE_FOREACH(device, output_device_t, devices) {
		i += device->send(device->device, remotes, packet, errors);
	}
	return i;
}
void				cleanup_devices(queue_t *devices)
{
	output_device_t	*device;

	while ((device = (output_device_t *)dequeue(devices))) {
		device->finalizer(device->device);
	}
	free(device);
}