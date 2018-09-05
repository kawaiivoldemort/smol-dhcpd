#include <time.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include "net_if.h"
#include "dhcp_client_daemon.h"

int main() {
    srand(time(0));
    // Get network interfaces and their metadata
    net_ifs ifaces = get_network_interfaces();
    print_interfaces(ifaces);
    net_if chosen_interface = ifaces.ifs[1];
    dhcp_client_daemon(chosen_interface);
    close_network_interfaces(ifaces);
    return 0;
}