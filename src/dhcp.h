#ifndef DHCP_H
#define DHCP_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "types.h"
#include "net_if.h"

/**
 * Size constants in Octets
 */
// DHCP Message size without options
#define	DHCP_MESSAGE_SIZE		236
// DHCP Cookie size
#define DHCP_COOKIE_SIZE		4
// DHCP Max Options Size
#define	DHCP_OPTIONS_MAX_SIZE	312 - DHCP_COOKIE_SIZE
// DHCP Packet Size
#define	DHCP_MAX_PACKET_SIZE	(DHCP_MESSAGE_SIZE + DHCP_COOKIE_SIZE + DHCP_OPTIONS_MAX_SIZE)
// Magic cookie to tell the server that its a DHCP request
#define DHCP_MAGIC_COOKIE htonl(0x63825363)

/**
 * DHCP message structure
 */
typedef struct __attribute__((__packed__)) dhcp_message {
	// Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
	u8					opcode;
	// Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet.
	u8					htype;
	// Hardware address length (e.g.  '6' for 10mb ethernet).
	u8					hlen;
	// Client sets to zero, optionally used by relay agents when booting via a relay agent.
	u8					hops;
	// Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server.
	u32					xid;
	// Filled in by client, seconds elapsed since client began address acquisition or renewal process.
	u16					secs;
	// First Bit is Broadcast Flag, the remaining are 0 and reserved for future use.
	u8					flags[2];
	// Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests. 0 otherwise.
	u8					ciaddr[4];
	// 'Your' (client) IP address.
	u8					yiaddr[4];
	// IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
	u8					siaddr[4];
	// Relay agent IP address, used in booting via a relay agent.
	u8					giaddr[4];
	// Client hardware address.
	u8					chaddr[16];
	// Server name.
	u8					sname[64];
	// Boot file name, null terminated string; "generic" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER.
	u8					file[128];
	// DHCP cookie
	u8					cookie[DHCP_COOKIE_SIZE];
	// Optional parameters field.
	u8					options[DHCP_OPTIONS_MAX_SIZE];
	// Options Length
	u16					options_length;
} dhcp_message;

/**
 * DHCP Packet raw data buffer
 */
typedef struct __attribute__((__packed__)) dhcp_raw_data {
	// Packet Data
	u8					raw_data[DHCP_MAX_PACKET_SIZE];
	// Packet Size
	u16					packet_length;
} dhcp_raw_data;

/**
 * DHCP Packet representation union
 */
typedef union _dhcp_packet {
	// Packet represented as a message with the last two octets specifying length of the options field
	struct dhcp_message		message;
	// Packet represented as raw data as byte long octets with their endienness corrected for network transmission
	struct dhcp_raw_data	raw_data;
} _dhcp_packet;

/**
 * DHCP Options metadata structure
 */
typedef struct dhcp_option_meta {
    u8      tag;
    char*   name;
    int		data_length;
} dhcp_option_meta;

/**
 * DHCP Options enumeration
 */
#define DHCP_OPTION(tag_num, name, name_string, length) name = tag_num,
typedef enum dhcp_options {
	#include "dhcp_options.def"
} dhcp_options;
#undef DHCP_OPTION

/**
 * DHCP Message Type Enum
 */
typedef enum dhcp_message_type {
	DHCP_DISCOVER	= 1,
	DHCP_OFFER 		= 2,
	DHCP_REQUEST	= 3,
	DHCP_DECLINE	= 4,
	DHCP_ACK		= 5,
	DHCP_NAK		= 6,
	DHCP_RELEASE	= 7,
	DHCP_INFORM		= 8
} dhcp_message_type;

/**
 * DHCP OP Code Enum
 */
typedef enum dhcp_op_code {
	BOOTREQUEST	= 1,
	BOOTREPLY	= 2,
} dhcp_op_code;

/**
 * DHCP Offered Parameters
 */
typedef struct dhcp_offered_params {
	// Acknowledge Byte, 0 for NACK/incomplete, 1 for ACK
	u8				ack;
	// Sending Server IP
	struct in_addr	ss_ip;
	// Offered IP and Network Mask
	struct in_addr	ip;
	struct in_addr	netmask;
	// Routers
	u32				n_routers;
	struct in_addr*	routers;
	// Name Servers
	u32				n_nameservers;
	struct in_addr*	nameservers;
	// DNS Servers
	u32				n_dns_servers;
	struct in_addr*	dns_servers;
	// Server Domain Name
	char*			domain_name;
	// NTP Servers
	u32				n_ntp_servers;
	struct in_addr*	ntp_servers;
	// IP Address Lease Time
	u32				lease_time_in_seconds;
	// DHCP Server ID to get more config parameters
	struct in_addr	dhcp_server_ip;
	// Renewal time
	u32				renew_in_seconds;
	// Rebinding time
	u32				rebind_in_seconds;
} dhcp_offered_params;

/**
 * Function Declerations
 */
void encode_dhcp_packet(dhcp_message* msg);
void decode_dhcp_packet(dhcp_raw_data* rd);
void print_packet(dhcp_raw_data* packet);
dhcp_message dhcp_discover(struct net_if interface, u32 xid);
dhcp_offered_params* unpack_dhcp_offer(struct net_if interface, u32 ss_ip, dhcp_message* dhcp_offer, u32 xid);
dhcp_message dhcp_request(net_if interface, dhcp_offered_params* offer, u32 xid);
dhcp_offered_params* unpack_dhcp_ack(struct net_if interface, u32 ss_ip, dhcp_message* dhcp_ack, u32 xid);
dhcp_message dhcp_release(net_if interface, dhcp_offered_params* offer, u32 xid);
void init_dhcp_message(dhcp_message* msg, u32 xid, u8* haddr, u8 hlen);
int is_dhcp_message(dhcp_message* msg, u8* haddr, u32 xid);
dhcp_offered_params* get_dhcp_offered_params(u8* options_ptr, int options_length, int* message_type);
void print_dhcp_offered_params(dhcp_offered_params* offered_params);
int close_dhcp_offered_params(dhcp_offered_params* offered_params);

#endif