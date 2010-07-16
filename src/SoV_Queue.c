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


#include <ctype.h>
#include <stdlib.h>
#include "SoV.h"

void			*dequeue(queue_t *queue) {
	qitem_t		*cur;
	void		*res;

	if (queue->to_free) {
		free(queue->to_free);
		queue->to_free = NULL;
	}
	cur = queue->head;
	if (!cur) return NULL;
	queue->count--;
	queue->head = cur->next;
	if (!cur->next)
		queue->tail = 0;
	res = cur->data;
	queue->to_free = res;
	free(cur);
	return res;
}

u_int			enqueue(void *buffer, queue_t *queue) {
	qitem_t		*item;

	NEW(item, qitem_t);
	item->data = buffer;
	item->next = 0;
    queue->count++;
	if (!queue->tail)
	{
		queue->head = item;
		queue->tail = item;
	}
	else
	{
		queue->tail->next = item;
		queue->tail = item;
	}
	return queue->count;
}