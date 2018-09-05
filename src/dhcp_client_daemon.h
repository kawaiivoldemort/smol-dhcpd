#ifndef DHCP_CLIENT_DAEMON_H
#define DHCP_CLIENT_DAEMON_H

#include <unistd.h>
#include <time.h>
#include "dhcp.h"
#include "net_if.h"
#include "raw_udp_sockets.h"

int dhcp_client_daemon(net_if interface);

#endif