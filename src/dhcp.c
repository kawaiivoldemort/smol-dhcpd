#include "dhcp.h"
#include "dhcp_options.h"

static const u8 dhcp_default_parameters[] = { SUBNET_MASK, ROUTER, NAME_SERVER, DOMAIN_SERVER, DOMAIN_NAME, NTP_SERVER };

/**
 * DHCP Encoding method (in place) to transform a dhcp_message into a dhcp_raw_data packet for transmission 
 */
void encode_dhcp_packet(dhcp_message* msg) {
	_dhcp_packet* packet = (_dhcp_packet*) msg;

	// Copy the contents of message as is into the data
	packet->raw_data.packet_length = DHCP_MESSAGE_SIZE + DHCP_COOKIE_SIZE + packet->message.options_length;
	// Fix endienness where necessary
	packet->message.xid = htonl(packet->message.xid);
	packet->message.secs = htons(packet->message.secs);
}

/**
 * DHCP Decoding method (in place) to transform a dhcp_raw_data packet into a dhcp_message for processing
 */
void decode_dhcp_packet(dhcp_raw_data* rd) {
	_dhcp_packet* packet = (_dhcp_packet*) rd;

	packet->message.options_length = packet->raw_data.packet_length - DHCP_MESSAGE_SIZE - DHCP_COOKIE_SIZE;
	// Fix endienness where necessary
	packet->message.xid = ntohl(packet->message.xid);
	packet->message.secs = ntohs(packet->message.secs);
}

/**
 * Display method
 */
void print_packet(dhcp_raw_data* packet) {
	printf("---\nDHCP Packet\n---\n");
	for(int i = 0; i < packet->packet_length; i += 4) {
		for(int j = i; (j < packet->packet_length) && (j < (i + 4)); j++) {
			printf("%u\t", packet->raw_data[j]);
		}
		printf("\n");
	}
	printf("---\n");
}

/**
 * DHCP Discover method
 */
dhcp_message dhcp_discover(struct net_if interface, u32 xid) {
	int options_index;
	dhcp_message discover;

	// Set the basic params
	init_dhcp_message(&discover, xid, interface.hw_addr, 6);
	discover.flags[0] = 0b10000000;
	// Set the options
	options_index = 0;
	// Standard Options
	/**
	 * SET MESSAGE TYPE TO DHCP DISCOVER
	 */
	// Message type
	discover.options[options_index++] = DHCP_MESSAGE_TYPE;
	discover.options[options_index++] = dhcp_options_metadata[DHCP_MESSAGE_TYPE].data_length;
	discover.options[options_index++] = DHCP_DISCOVER;
	// Client Identifier
	discover.options[options_index++] = CLIENT_IDENTIFIER;
	discover.options[options_index++] = 7;
	discover.options[options_index++] = 1;
	memcpy(discover.options + options_index, interface.hw_addr, 6);
	options_index += 6;
	// Ask for an IP Address
	discover.options[options_index++] = REQUESTED_IP_ADDRESS;
	discover.options[options_index++] = 4;
	memset(discover.options + options_index, 0, 4);
	options_index += 4;
	// Parameter request list
	discover.options[options_index++] = PARAMETER_REQUEST_LIST;
	discover.options[options_index++] = sizeof(dhcp_default_parameters);
	for(int i = 0; i < sizeof(dhcp_default_parameters); i++) {
		discover.options[options_index++] = dhcp_default_parameters[i];
	}
	// Non Standard options
	// TODO
	discover.options[options_index++] = 255;
	discover.options_length = options_index;
	return discover;
}

/**
 * Verify and unpack the packet from the server is a valid DHCP Offer
 */
dhcp_offered_params* unpack_dhcp_offer(struct net_if interface, u32 ss_ip, dhcp_message* dhcp_offer, u32 xid) {
	dhcp_offered_params*	params;
	int 					message_type;
	// Check if packet is a valid dhcp message
	if(is_dhcp_message(dhcp_offer, interface.hw_addr, xid) != 0) {
		// Not a DHCP packet, exit
		return 0;
	}
	// Get the offer from the body and verify message type
	params = get_dhcp_offered_params(dhcp_offer->options, dhcp_offer->options_length, &message_type);
	if(message_type != DHCP_OFFER) {
		close_dhcp_offered_params(params);
		return 0;
	}
	params->ip.s_addr = *((u32*) dhcp_offer->yiaddr);
	params->ss_ip.s_addr = ss_ip;
	return params;
}

/**
 * DHCP Request to get an IP
 */
dhcp_message dhcp_request(net_if interface, dhcp_offered_params* offer, u32 xid) {
	dhcp_message request;
	int options_index;

	// Set the basic params
	init_dhcp_message(&request, xid, interface.hw_addr, 6);
	memcpy(request.chaddr, interface.hw_addr, 6);
	// Set the options
	options_index = 0;
	/**
	 * SET MESSAGE TYPE TO DHCP REQUEST
	 */
	request.options[options_index++] = DHCP_MESSAGE_TYPE;
	request.options[options_index++] = dhcp_options_metadata[DHCP_MESSAGE_TYPE].data_length;
	request.options[options_index++] = DHCP_REQUEST;
	// Client Identifier
	request.options[options_index++] = CLIENT_IDENTIFIER;
	request.options[options_index++] = 7;
	request.options[options_index++] = 1;
	memcpy(request.options + options_index, interface.hw_addr, 6);
	options_index += 6;
	/*
	 * REQUEST FOR AN OFFERED IP
	 */
	request.options[options_index++] = REQUESTED_IP_ADDRESS;
	request.options[options_index++] = 4;
	*((u32*) (request.options + options_index)) = offer->ip.s_addr;
	options_index += 4;
	/**
	 * SPECIFY THE DHCP SERVER
	 */
	request.options[options_index++] = SERVER_IDENTIFIER;
	request.options[options_index++] = 4;
	*((u32*) (request.options + options_index)) = offer->dhcp_server_ip.s_addr;
	options_index += 4;
	// Parameter request list
	request.options[options_index++] = PARAMETER_REQUEST_LIST;
	request.options[options_index++] = sizeof(dhcp_default_parameters);
	for(int i = 0; i < sizeof(dhcp_default_parameters); i++) {
		request.options[options_index++] = dhcp_default_parameters[i];
	}
	// Non Standard options
	// TODO
	request.options[options_index++] = 255;
	request.options_length = options_index;
	return request;
}

/**
 * Verify and unpack the packet from the server is a valid DHCP Ack
 */
dhcp_offered_params* unpack_dhcp_ack(struct net_if interface, u32 ss_ip, dhcp_message* dhcp_ack, u32 xid) {
	dhcp_offered_params*	params;
	int 					message_type;
	// Check if packet is a valid dhcp message
	if(is_dhcp_message(dhcp_ack, interface.hw_addr, xid) != 0) {
		// Not a DHCP packet, exit
		return 0;
	}
	// Get the offer from the body and verify message type
	params = get_dhcp_offered_params(dhcp_ack->options, dhcp_ack->options_length, &message_type);
	if(message_type == DHCP_ACK) {
		params->ack = 1;
	} else if(message_type == DHCP_NAK) {
		params->ack = 0;
	} else {
		close_dhcp_offered_params(params);
		return 0;
	}
	params->ip.s_addr = *((u32*) dhcp_ack->yiaddr);
	params->ss_ip.s_addr = ss_ip;
	return params;
}

/**
 * Release the lease
 */
dhcp_message dhcp_release(net_if interface, dhcp_offered_params* offer, u32 xid) {
	dhcp_message release;
	int options_index;

	// Set the basic params
	init_dhcp_message(&release, xid, interface.hw_addr, 6);
	*((u32*) release.siaddr) = offer->ss_ip.s_addr;
	// Set the options
	options_index = 0;
	/**
	 * SET MESSAGE TYPE TO DHCP RELEASE
	 */
	release.options[options_index++] = DHCP_MESSAGE_TYPE;
	release.options[options_index++] = dhcp_options_metadata[DHCP_MESSAGE_TYPE].data_length;
	release.options[options_index++] = DHCP_RELEASE;
	// Client Identifier
	release.options[options_index++] = CLIENT_IDENTIFIER;
	release.options[options_index++] = 7;
	release.options[options_index++] = 1;
	memcpy(release.options + options_index, interface.hw_addr, 6);
	options_index += 6;
	/*
	 * RELEASE YOUR LEASED IP
	 */
	release.options[options_index++] = REQUESTED_IP_ADDRESS;
	release.options[options_index++] = 4;
	*((u32*) release.options + options_index) = offer->ip.s_addr;
	options_index += 4;
	/**
	 * SPECIFY THE DHCP SERVER
	 */
	release.options[options_index++] = SERVER_IDENTIFIER;
	release.options[options_index++] = 4;
	*((u32*) release.options + options_index) = offer->dhcp_server_ip.s_addr;
	options_index += 4;
	release.options[options_index++] = 255;
	release.options_length = options_index;
	return release;
}

/**
 * Initializes the basic parameters of the dhcp message to their default values
 */
void init_dhcp_message(dhcp_message* msg, u32 xid, u8* haddr, u8 hlen) {
	msg->opcode = BOOTREQUEST;
	msg->htype = 1;
	msg->hlen = hlen;
	msg->xid = xid;
	msg->secs = 0;
	msg->flags[0] = 0b00000000;
	msg->flags[1] = 0;
	memset(msg->ciaddr, 0, 4);
	memset(msg->yiaddr, 0, 4);
	memset(msg->siaddr, 0, 4);
	memset(msg->giaddr, 0, 4);
	memcpy(msg->chaddr, haddr, hlen);
	memset(msg->sname, 0, 64);
	memset(msg->file, 0, 128);
	*((u32*) msg->cookie) = DHCP_MAGIC_COOKIE;
}

/**
 * Check if the packet is indeed a DHCP packet with the correct transaction
 * id and destination hardware address
 */
int is_dhcp_message(dhcp_message* msg, u8* haddr, u32 xid) {
	if(msg->opcode != BOOTREPLY) {
		// Not a BOOTP Reply
		return -1;
	}
	if(msg->htype != 1 || msg->hlen != 6) {
		// Not an ethernet packet
		return -2;
	}
	if(msg->xid != xid) {
		// Different Transaction
		return -3;
	}
	if(memcmp(haddr, msg->chaddr, msg->hlen) != 0) {
		// Different Hardware Address Matched
		return -4;
	}
	if(*((u32*) msg->cookie) != DHCP_MAGIC_COOKIE) {
		// BOOTP packet, not DHCP
		return -5;
	}
	return 0;
}

/**
 * Parse the DHCP offered parameters
 */
dhcp_offered_params* get_dhcp_offered_params(u8* options_ptr, int options_length, int* message_type) {
	int 					i = 0;
	dhcp_offered_params*	out;
	// Initialize the out variable
	out = malloc(sizeof(dhcp_offered_params));
	memset(out, 0, sizeof(dhcp_offered_params));
	while((*(options_ptr + i) != 255) && (i < options_length)) {
		// Try Parse the DHCP Options
		if((i + options_ptr[i+1] + 2) > options_length) {
			perror("Overflow");
			return 0;
		}
		// TODO: Verify options length
		switch(options_ptr[i]) {
			case DHCP_MESSAGE_TYPE:
				*message_type = options_ptr[i+2];
				break;
			case SUBNET_MASK:
				out->netmask.s_addr = *((u32*) (options_ptr + i + 2));
				break;
			case ROUTER:
				out->n_routers = options_ptr[i+1] / 4;
				out->routers   = malloc(sizeof(struct in_addr) * out->n_routers);
				for(int i = 0; i < out->n_routers; i++) {
					out->routers[i].s_addr = *((u32*) (options_ptr + i + 2 + (4*i)));
				}
				break;
			case NAME_SERVER:
				out->n_nameservers = options_ptr[i+1] / 4;
				out->nameservers   = malloc(sizeof(struct in_addr) * out->n_nameservers);
				for(int i = 0; i < out->n_nameservers; i++) {
					out->nameservers[i].s_addr = *((u32*) (options_ptr + i + 2 + (4*i)));
				}
				break;
			case DOMAIN_SERVER:
				out->n_dns_servers = options_ptr[i+1] / 4;
				out->dns_servers   = malloc(sizeof(struct in_addr) * out->n_dns_servers);
				for(int i = 0; i < out->n_dns_servers; i++) {
					out->dns_servers[i].s_addr = *((u32*) (options_ptr + i + 2 + (4*i)));
				}
				break;
			case DOMAIN_NAME:
				out->domain_name = malloc(options_ptr[i+1] + 1);
				memcpy(out->domain_name, (u8*) options_ptr + i + 2, options_ptr[i+1]);
				out->domain_name[options_ptr[i+1]] = '\0';
				break;
			case NTP_SERVER:
				out->n_ntp_servers = options_ptr[i+1] / 4;
				out->ntp_servers   = malloc(sizeof(struct in_addr) * out->n_ntp_servers);
				for(int i = 0; i < out->n_ntp_servers; i++) {
					out->ntp_servers[i].s_addr = *((u32*) (options_ptr + i + 2 + (4*i)));
				}
				break;
			case IP_ADDRESS_LEASE_TIME:
				out->lease_time_in_seconds = ntohl(*((u32*) (options_ptr + i + 2)));
				break;
			case SERVER_IDENTIFIER:
				out->dhcp_server_ip.s_addr = *((u32*) (options_ptr + i + 2));
				break;
			case RENEWAL_TIME_VALUE:
				out->renew_in_seconds = ntohl(*((u32*) (options_ptr + i + 2)));
				break;
			case REBINDING_TIME_VALUE:
				out->rebind_in_seconds = ntohl(*((u32*) (options_ptr + i + 2)));
				break;
			default:
				break;
		}
		i += options_ptr[i+1] + 2;
	}
	if(*message_type != 0) {
		return out;
	} else {
		close_dhcp_offered_params(out);
		return 0;
	}
}

/**
 * Display the DHCP offered parameters
 */
void print_dhcp_offered_params(dhcp_offered_params* offered_params) {
	printf("---\nDHCP Offered Parameters\n---\n");
	if(offered_params->ip.s_addr != 0) {
		printf("\tIP Address:\t\t%s\n", inet_ntoa(offered_params->ip));
	}
	if(offered_params->netmask.s_addr != 0) {
		printf("\tSubnet Mask:\t\t%s\n", inet_ntoa(offered_params->netmask));
	}
	if(offered_params->n_routers != 0) {
		printf("\tRouters:\t\t");
		for(int i = 0; i < offered_params->n_routers; i++) {
			printf("%s ", inet_ntoa(offered_params->routers[i]));
		}
		printf("\n");
	}
	if(offered_params->n_nameservers != 0) {
		printf("\tName Servers:\t\t");
		for(int i = 0; i < offered_params->n_nameservers; i++) {
			printf("%s ", inet_ntoa(offered_params->nameservers[i]));
		}
		printf("\n");
	}
	if(offered_params->n_dns_servers != 0) {
		printf("\tDNS Servers:\t\t");
		for(int i = 0; i < offered_params->n_dns_servers; i++) {
			printf("%s ", inet_ntoa(offered_params->dns_servers[i]));
		}
		printf("\n");
	}
	if(offered_params->domain_name != 0) {
		printf("\tDomain Name:\t\t%s\n", offered_params->domain_name);
	}
	if(offered_params->ntp_servers != 0) {
		printf("\tNTP Servers:\t");
		for(int i = 0; i < offered_params->n_ntp_servers; i++) {
			printf("%s ", inet_ntoa(offered_params->ntp_servers[i]));
		}
		printf("\n");
	}
	if(offered_params->lease_time_in_seconds != 0) {
		printf("\tOffer Lease Time:\t%u s\n", offered_params->lease_time_in_seconds);
	}
	if(offered_params->dhcp_server_ip.s_addr != 0) {
		printf("\tDHCP Server IP:\t\t%s\n", inet_ntoa(offered_params->dhcp_server_ip));
	}
	if(offered_params->renew_in_seconds != 0) {
		printf("\tLease Renewal Time:\t%u s\n", offered_params->renew_in_seconds);
	}
	if(offered_params->rebind_in_seconds != 0) {
		printf("\tLease Rebind Time:\t%u s\n", offered_params->rebind_in_seconds);
	}
	printf("---\n");
}

/**
 * Free the DHCP offered parameters
 */
int close_dhcp_offered_params(dhcp_offered_params* offered_params) {
	if(offered_params->n_routers != 0) {
		free(offered_params->routers);
	}
	if(offered_params->n_nameservers != 0) {
		free(offered_params->nameservers);
	}
	if(offered_params->n_dns_servers != 0) {
		free(offered_params->dns_servers);
	}
	if(offered_params->domain_name != 0) {
		free(offered_params->domain_name);
	}
	if(offered_params->ntp_servers != 0) {
		free(offered_params->ntp_servers);
	}
	memset(offered_params, 0, sizeof(dhcp_offered_params));
}