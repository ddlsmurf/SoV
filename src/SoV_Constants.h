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

#ifndef SOV_CONSTANTS_H_
#define SOV_CONSTANTS_H_

#define BANNER_TITLE		"Starcraft over VPN - http://s-softs.com/sov.html"
#define VERSION				"SoV 2.0"
#define BANNER				VERSION " - " BANNER_TITLE

#define STARCRAFT_PORT		6111
#define PCAP_FILTER_FORMAT	"udp port %d and dst net 255.255.255.255"

#endif