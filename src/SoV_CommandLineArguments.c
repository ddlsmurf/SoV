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

char		**copy_arguments(char **args, int count) {
	char	**newav;

	newav = (char **)malloc((count + 1) * sizeof(char *));
	bcopy(args, newav, sizeof(char *) * count);
	newav[count] = NULL;
	return newav;
}
void	remove_arguments(char **args, int start, int count) {
	int	i;

	i = start;
	while (args[i + count])
	{
		args[i] = args[i + count];
		i++;
	}
	args[i] = 0;
}
int			find_option(char *flag, char **av) {
	int		res = 0;
	char	*current;

	while (*av)
	{
		current = *av;
		while (*current == SWITCH_CHAR || *current == SWITCH_CHAR_OTHER)
			current++;

		if (current != *av &&
			strcasecmp(flag, current) == 0)
			return res;
		res++;
		av++;
	}
	return -1;
}
int		read_option(char *flag, char **av, char **value) {
	int	option_position;

	option_position = find_option(flag, av);
	if (option_position == -1)
		return 0;
	if (value) {
		*value = av[option_position + 1];
		if (!*value) {
			fprintf(stderr, "Error: argument %c%s requires another argument" EOL, SWITCH_CHAR, flag);
			return -1;
		}
	}
	remove_arguments(av, option_position, value ? 2 : 1);
	return 1;
}
int			read_int_option(char *flag, char **av, int *value) {
	char	*option_value;
	int		res;

	res = read_option(flag, av, &option_value);
	if (res == -1 || !res) return res;
	*value = atoi(option_value);
	return 1;
}
int		read_port_option(char *flag, char **av, int *value) {
	int	res;

	res = read_int_option(flag, av, value);
	if (res == -1 || !res) return res;
	if (*value <= 0 || *value > 0xffff) {
		fprintf(stderr, "Error: argument %c%s requires a valid port number" EOL, SWITCH_CHAR, flag);
		return -1;
	}
	return res;
}

int			read_mac_option(char *flag, char **av, u_char **value) {
	int		res;
	char	*opt_value;

	res = read_option(flag, av, &opt_value);
	if (res == -1 || !res) return res;
	*value = parse_mac_addr(opt_value);
	if (!*value) {
		fprintf(stderr, "Error: argument %c%s requires a valid mac address (12:34:56:78:9a:bc)" EOL, SWITCH_CHAR, flag);
		return -1;
	}
	return res;
}
void						print_options(commandline_option_t *arguments) {
	char					*argument_param;
	commandline_option_t	*argument;

	while (arguments->flag)
	{
		argument_param = "";
		argument = arguments;
		arguments++;
		if (!argument->description)
			continue;
		switch (argument->type)
		{
		case CLO_TYPE_STR:
			argument_param = " str";
			break;
		case CLO_TYPE_MAC:
			argument_param = " hex";
			break;
		case CLO_TYPE_PORT:
			argument_param = " port";
			break;
		}
		printf("\t%c%-5s%-5s : %s" EOL, SWITCH_CHAR, argument->flag, argument_param, argument->description);
	}
}

char						**read_options(void *options, int ac, char **av, commandline_option_t *arguments) {
	char					**newav;
	void					*result;
	char					*result_str;
	u_int					result_size;
	int						result_int;
	int						option_result;
	commandline_option_t	*argument;

	newav = copy_arguments(av + 1, ac - 1);
	while (arguments->flag)
	{
		argument = arguments;
		arguments++;
		result = NULL;
		switch (argument->type)
		{
		case CLO_TYPE_TERMINAL:
			result_int = read_option(argument->flag, newav, NULL);
			if (result_int) {
				((callback_empty*)((uintptr_t)argument->offset))();
				return 0;
			}
			break;

		case CLO_TYPE_BOOL:
			result_int = read_option(argument->flag, newav, NULL);
			result = &result_int;
			result_size = sizeof(u_int);
			break;
		case CLO_TYPE_MAC:
			option_result = read_mac_option(argument->flag, newav, (u_char **)&result_str);
			if (option_result == -1) return 0;
			if (option_result) {
				result = &result_str;
				result_size = sizeof(char *);
			}
			break;
		case CLO_TYPE_STR:
			option_result = read_option(argument->flag, newav, (char **)&result_str);
			if (option_result == -1) return 0;
			if (option_result) {
				result = &result_str;
				result_size = sizeof(char *);
			}
			break;
		case CLO_TYPE_PORT:
			option_result = read_port_option(argument->flag, newav, &result_int);
			if (option_result == -1) return 0;
			if (option_result) {
				result = &result_int;
				result_size = sizeof(u_int);
			}
			break;
		}

		if (result && result_size) {
			bcopy(result, (u_char*)options + argument->offset, result_size);
		}
	}
	return newav;
}