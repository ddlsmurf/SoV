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

#ifndef SOV_COMMANDLINEARGUMENTS_H_
#define SOV_COMMANDLINEARGUMENTS_H_

#define CLO_TYPE_TERMINAL	0
#define CLO_TYPE_BOOL		1
#define CLO_TYPE_STR		2
#define CLO_TYPE_PORT		3
#define CLO_TYPE_MAC		4

#define CLO_CALL(method)			(uintptr_t)((callback_empty*)(method))
#define CLO_SET_FIELD(type,field)	((uintptr_t)(&(((type*)0)->field)))
#define CLO_EOL						EOL "\t\t\t"

typedef struct	commandline_option_s {
	char			*flag;
	char			*description;
	u_int			type;
	uintptr_t	offset;
}						commandline_option_t;

char **read_options(void *options, int ac, char **av, commandline_option_t *arguments);
void print_options(commandline_option_t *arguments);

#endif
