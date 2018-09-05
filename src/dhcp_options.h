#ifndef DHCP_OPTIONS_H
#define DHCP_OPTIONS_H

#include "dhcp.h"

/**
 * Global array of DHCP Options metadata
 */
#define DHCP_OPTION(tag_num, name, name_string, length) [tag_num] = (struct dhcp_option_meta) { tag_num, name_string, length },
static dhcp_option_meta dhcp_options_metadata[] = {
	#include "dhcp_options.def"
};
#undef DHCP_OPTION

#endif