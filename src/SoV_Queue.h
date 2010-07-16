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

#ifndef SOV_QUEUE_H_
#define SOV_QUEUE_H_

/* Queue item */
typedef struct		qitem_s
{
	void			*data;
	struct qitem_s	*next;
}					qitem_t;

/* Queue container */
typedef struct		queue_s
{
	qitem_t			*head;
	qitem_t			*tail;
	qitem_t			*to_free;
	u_int	count;
}					queue_t;

#define DEFINE_QUEUE(name) 	\
	queue_t			name
#define QUEUE_COUNT(name) 	((name)->count)

#define USES_QUEUE_FOREACH \
	qitem_t	*queue_enumerator_variable
#define QUEUE_FOREACH(var,type,queue) \
	for (queue_enumerator_variable = queue->head, \
	var = queue_enumerator_variable ? (type*)queue_enumerator_variable->data: NULL; \
		 queue_enumerator_variable; \
		 queue_enumerator_variable = queue_enumerator_variable->next, \
		 var = queue_enumerator_variable ? (type*)queue_enumerator_variable->data: NULL)

void	*dequeue(queue_t *queue);
u_int	enqueue(void *buffer, queue_t *queue);

#endif