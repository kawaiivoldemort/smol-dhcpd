#include "net_if.h"
#include "dhcp_options.h"

/**
 * Function to get the network interfaces in a net_ifs struct
 */
net_ifs get_network_interfaces() {
    u32             socket_fd;
    struct ifaddrs* ifaddr;
    struct ifreq    if_request;
    net_ifs         ifs;
    // Initialization of ifs
    ifs.closed  = 0;
    ifs.num_ifs = 0;
    ifs.ifs     = 0;
    // Open a UDP socket
    if((socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket() failed");
        return ifs;
    }
    // Get the linked list of interfaces
    getifaddrs(&ifaddr);
    // Allocate for the output
    ifs.ifs = (net_if*) malloc(MAX_NET_IFS * sizeof(net_if));
    // For each interface
    int num_ifs = 0;
    while(ifaddr != NULL) {
        memset(&if_request, 0, sizeof(struct ifreq));
        // If not IPv4 skip
        if ((ifaddr->ifa_addr == 0) || (ifaddr->ifa_addr->sa_family != PF_PACKET)) {
            ifaddr = ifaddr->ifa_next;
            continue;
        }
        strcpy(if_request.ifr_name, ifaddr->ifa_name);
        strcpy(ifs.ifs[num_ifs].name, ifaddr->ifa_name);

        // Stream the IOCTL SIOCGIFINDEX into the buffer to get the interface index
        if (ioctl(socket_fd, SIOCGIFINDEX, &if_request) == 0) {
            ifs.ifs[num_ifs].index = if_request.ifr_ifindex;
        }
        // Stream the IOCTL SIOCGIFADDR into the buffer to get the ipv4 subnet mask
        if (ioctl(socket_fd, SIOCGIFHWADDR, &if_request) == 0) {
            memcpy(ifs.ifs[num_ifs].hw_addr, if_request.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
        }
        // Stream the IOCTL SIOCGIFADDR into the buffer to get the ipv4 address
        if (ioctl(socket_fd, SIOCGIFADDR, &if_request) == 0) {
            ifs.ifs[num_ifs].inet_addr = ((struct sockaddr_in *)(&if_request.ifr_addr))->sin_addr.s_addr;
        }
        // Stream the IOCTL SIOCGIFBRDADDR into the buffer to get the ipv4 broadcast address
        if (ioctl(socket_fd, SIOCGIFBRDADDR, &if_request) == 0) {
            ifs.ifs[num_ifs].broadcast = ((struct sockaddr_in *)(&if_request.ifr_broadaddr))->sin_addr.s_addr;
        }
        // Stream the IOCTL SIOCGIFADDR into the buffer to get the ipv4 subnet mask
        if (ioctl(socket_fd, SIOCGIFNETMASK, &if_request) == 0) {
            ifs.ifs[num_ifs].netmask = ((struct sockaddr_in *)(&if_request.ifr_netmask))->sin_addr.s_addr;
        }
        num_ifs++;
        ifaddr = ifaddr->ifa_next;
    }
    ifs.ifs = realloc(ifs.ifs, num_ifs * sizeof(net_if));
    ifs.num_ifs = num_ifs;
    freeifaddrs(ifaddr);
    close(socket_fd);
    return ifs;
}

/**
 * Function to close the network interfaces struct
 */
void close_network_interfaces(net_ifs interfaces) {
    interfaces.closed = 1;
    if(interfaces.ifs != 0) {
        free(interfaces.ifs);
    }
    interfaces.num_ifs = 0;
}

/**
 * Display function for a 32 bit ipv4 address
 */
void print_ipv4_address(u32 ip_addr) {
    static char print_buffer[IPV4_ADDR_STRLEN];
    inet_ntop(AF_INET, &ip_addr, print_buffer, IPV4_ADDR_STRLEN);
    printf("%s", print_buffer);
}

/**
 * Display function for a 48 bit ethernet MAC address
 */
void print_mac_address(u8* mac_address) {
    for(int i = 0; i < MAC_ADDR_LEN; i++) {
        printf("%02x%s", mac_address[i], (i == 5 ? "" : ":"));
    }
}

/**
 * Display function for a nework interface represented as a struct net_if
 */
void print_interface(net_if* interface) {
    printf("%s:\n\tethernet:\t", interface->name);
    print_mac_address(interface->hw_addr);
    printf("\n\tnetmask:\t");
    print_ipv4_address(interface->netmask);
    printf("\n\tbroadcast:\t");
    print_ipv4_address(interface->broadcast);
    printf("\n");
}

/**
 * Display function for a collection of network interfaces represented in a struct net_ifs
 */
void print_interfaces(net_ifs interfaces) {
    if(interfaces.closed == 1) {
        perror("Cleaned up structure");
        return;
    }
    printf("---\nNetwork Interfaces\n---\n");
    for(int i = 0; i < interfaces.num_ifs; i++) {
        print_interface(&interfaces.ifs[i]);
    }
    printf("---\n");
}