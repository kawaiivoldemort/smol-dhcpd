#ifndef NETIF_H
#define NETIF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "types.h"

/**
 * Buffer length constants
 */
// Max length of a ethernet MAC
#define MAC_ADDR_LEN        6
// Max length of an ipv4 string
#define IPV4_ADDR_STRLEN    16
// Max length of a null terminated interface name in linux/bsd (actual max length is
// usually less due to dhcp bugs in debian. see https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=858580)
#define MAX_NET_IF_NAME_LEN 16
// Max number of network interfaces supported
#define MAX_NET_IFS         255

/**
 * Network interface structure
 */
typedef struct net_if {
    int     index;
    char    name[MAX_NET_IF_NAME_LEN];
    u8      hw_addr[MAC_ADDR_LEN];
    u32     inet_addr;
    u32     netmask;
    u32     broadcast;
} net_if;

/**
 * Network interfaces structure to represent a collection
 */
typedef struct net_ifs {
    int             closed;
    int             num_ifs;
    struct net_if*  ifs;
} net_ifs;

/**
 * Function declerations
 */
net_ifs get_network_interfaces();
void close_network_interfaces(net_ifs interfaces);
void print_ipv4_address(u32 ip_addr);
void print_mac_address(u8* mac_address);
void print_interface(net_if* interface);
void print_interfaces(net_ifs interfaces);

#endif