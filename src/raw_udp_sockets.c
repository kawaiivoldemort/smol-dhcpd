#include "raw_udp_sockets.h"

/**
 * Old version of the FreeBSD in_cksum network checksum function, see (http://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/unpv12e/libfree/in_cksum.c)
 */
u16 in_cksum(u16 *addr, int len)
{
	int	nleft   = len;
	int	sum     = 0;
	u16	*w      = addr;
	u16	answer  = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			        /* add carry */
	answer = ~sum;				        /* truncate to 16 bits */
	return(answer);
}

/**
 * Wrapper for the above function to calculate the UDP checksum where the IP header
 * is defined as {
 *     u32 source_ip;
 *     u32 dest_ip;
 *     u8  placeholder;
 *     u8  protocol;
 *     u16 udp_length;
 * }
 * instead of the full IPv4 or v6 header
 */
u16 udp_cksum(u32 saddr, u32 daddr, struct udphdr* udp_header, u8* udp_data, int data_length) {
    pseudo_udp_packet* udp_psh = (pseudo_udp_packet*) malloc(UDP_PSEUDO_PACKET_LENGTH + data_length);
    udp_psh->pseudo_ip_header.source_ip = saddr;
    udp_psh->pseudo_ip_header.dest_ip = daddr;
    udp_psh->pseudo_ip_header.placeholder = 0;
    udp_psh->pseudo_ip_header.protocol = IPPROTO_UDP;
    udp_psh->pseudo_ip_header.udp_length = udp_header->len;
    udp_psh->udp_header = *udp_header;
    memcpy(udp_psh->data, udp_data, data_length);
    u16 checksum = in_cksum((u16*) udp_psh, UDP_PSEUDO_PACKET_LENGTH + data_length);
    free(udp_psh);
    return checksum;
}

/**
 * Sends a UDP Packet built on an IPv4 Datagram on an Ethernet Frame
 */
int raw_ethernet_ipv4_udp_send(int raw_socket, net_if interface, u32 source_ip, u16 source_port, u32 dest_ip, u16 dest_port, u8* data, int data_length) {
    udp_packet*         packet;
    struct sockaddr_ll  interface_ll_struct;
    int                 res;

    if(data_length > MAX_UDP_IPV4_DATA_LENGTH) {
        perror("Data too large");
        return -2;
    }
	/**
	 * Allocate for the UDP Packet
	 */
	packet = malloc(HEADER_LENGTH + data_length);
    /**
     * Set UDP Data
     */
    memcpy(packet->data, data, data_length);
    /**
     * Set UDP Headers
     */
    packet->udp_header.source = source_port;
    packet->udp_header.dest = dest_port;
    packet->udp_header.len = htons(UDP_HEADER_LENGTH + data_length);
    packet->udp_header.check = 0;
    packet->udp_header.check = udp_cksum(source_ip, dest_ip, &packet->udp_header, packet->data, data_length);
    /**
     * Set IP Header
     */
    // 5 32bit words, no options
    packet->ipv4_header.ihl = IPV4_HEADER_LENGTH / 4;
    packet->ipv4_header.version = 4;
    // Type of Service / DSCP
    packet->ipv4_header.tos = 0;
    packet->ipv4_header.tot_len = htons(IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH + data_length);
    // Filled in automatically
    packet->ipv4_header.id = 0;
    packet->ipv4_header.frag_off = 0;
    packet->ipv4_header.ttl = 64;
    // 17 for UDP : See (https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
    packet->ipv4_header.protocol = IPPROTO_UDP;
    // Filled in automatically
    packet->ipv4_header.check = 0;
    packet->ipv4_header.saddr = source_ip;
    packet->ipv4_header.daddr = dest_ip;
    packet->ipv4_header.check = in_cksum((u16*) &(packet->ipv4_header), sizeof(struct iphdr));
    /**
     *  Set Ethernet Header
     */
    memcpy(packet->ethernet_header.h_source, interface.hw_addr, MAC_ADDR_LEN);
    memset(packet->ethernet_header.h_dest, -1, MAC_ADDR_LEN);
    packet->ethernet_header.h_proto = htons(ETH_P_IP);
    // No Options
    /**
     * Create the interface Link Layer struct
     */
    memset(&interface_ll_struct, 0, sizeof(struct sockaddr_ll));
    interface_ll_struct.sll_ifindex = interface.index;
    /**
     * Send the packet
     */
    res = sendto(raw_socket, packet, HEADER_LENGTH + data_length, 0, (struct sockaddr*) &interface_ll_struct, sizeof(struct sockaddr_ll));
	free(packet);
	return res;
}

/**
 * Creates a raw UDP socket bound to a network interface
 */
int raw_ethernet_ipv4_udp_if_socket(net_if interface) {
    int raw_socket;
    int i;

    // Open the socket file descriptor
    if((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		#ifdef DEBUG
        perror("Failed to create socket");
		#endif
        return -1;
    }
    // Bind the socket to the interface
    i = 1;
    // Set socket to bind to a complete interface
    if(setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interface.name, strlen(interface.name)) < 0) {
		#ifdef DEBUG
        perror("Failed to set BINDTODEVICE");
		#endif
        return -2;
    }
    return raw_socket;
}

/**
 * Recieves a UDP Packet on an Ethernet interface and unpacks and verifies it
 */
int raw_ethernet_ipv4_udp_recv(int raw_socket, net_if interface, u32 source_ip, u16 source_port, u32 dest_ip, u16 dest_port, int max_length, raw_packet_ptr* raw_packet_ptr_ptr) {
    u8*                 packet;
    struct sockaddr_ll  interface_ll_struct;
    int                 sockaddr_ll_len;
    int                 read_length;
    u16                 checksum_cache;
    struct ethhdr*      ethernet_header;
    struct iphdr*       ipv4_header;
    struct udphdr*      udp_header;
    u16                 udp_length;
    u8*                 data;
    u16                 data_length;
    
    /**
     * Create the interface Link Layer struct
     */
    memset(&interface_ll_struct, 0, sizeof(struct sockaddr_ll));
    interface_ll_struct.sll_ifindex = interface.index;
    /**
     * Recieve the packet
     */
    packet = (u8*) malloc(max_length + 4);
    sockaddr_ll_len = sizeof(struct sockaddr_ll);
    read_length = recvfrom(raw_socket, packet, max_length, 0, (struct sockaddr*) &interface_ll_struct, &sockaddr_ll_len);
    if(read_length < 0) {
		#ifdef DEBUG
        perror("Read failed");
		#endif
        free(packet);
        return -1;
    }

    /**
     * Verify the ethernet header
     */
    ethernet_header = (struct ethhdr*) packet;
    if((memcmp(ethernet_header->h_dest, interface.hw_addr, 6) != 0) &&
       (memcmp(ethernet_header->h_dest, BROADCAST_MAC, 6) != 0)) {
		#ifdef DEBUG
        perror("[ETH] Packet not destined for us");
		#endif
        free(packet);
        return -2;
    }
    if(ethernet_header->h_proto != htons(ETH_P_IP)) {
		#ifdef DEBUG
        perror("[ETH] Wrong network layer protocol");
		#endif
        free(packet);
        return -2;
    }
    /**
     * Verify the ipv4 header
     */
    ipv4_header = (struct iphdr*) (packet + sizeof(struct ethhdr));
    if(ipv4_header->check) {
        checksum_cache = ipv4_header->check;
        ipv4_header->check = 0;
        ipv4_header->check = in_cksum((u16*) ipv4_header, sizeof(struct iphdr));
        if(ipv4_header->check != checksum_cache) {
			#ifdef DEBUG
            perror("[IPv4] Packet dropped for failing IP checksum");
			#endif
            free(packet);
            return -3;
        }
    }
    if(ipv4_header->version != 4) {
		#ifdef DEBUG
        perror("[IPv4] Not an ipv4 packet");
		#endif
        free(packet);
        return -3;
    }
    if(ipv4_header->protocol != IPPROTO_UDP) {
		#ifdef DEBUG
        perror("[IPv4] Not a udp packet");
		#endif
        free(packet);
        return -3;
    }
    if((source_ip != htonl(INADDR_ANY)) && (ipv4_header->saddr != source_ip)) {
		#ifdef DEBUG
        perror("[IPv4] Packet not from the right source for us");
		#endif
        free(packet);
        return -3;
    }
    if((dest_ip != htonl(INADDR_BROADCAST)) && (ipv4_header->daddr != dest_ip)) {
		#ifdef DEBUG
        perror("[IPv4] Packet not destined for us");
		#endif
        free(packet);
        return -3;
    }
    /**
     * Verify the udp header
     */
    udp_header = (struct udphdr*) (packet + sizeof(struct ethhdr) + (ipv4_header->ihl * 4));
    data = (u8*) (packet + sizeof(struct ethhdr) + (ipv4_header->ihl * 4) + UDP_HEADER_LENGTH);
    udp_length = ntohs(udp_header->len);
    data_length = udp_length - UDP_HEADER_LENGTH;
    checksum_cache = udp_header->check;
    udp_header->check = 0;
    udp_header->check = udp_cksum(ipv4_header->saddr, ipv4_header->daddr, udp_header, data, data_length);
    if(checksum_cache != udp_header->check) {
		#ifdef DEBUG
        perror("[UDP] Packet dropped for failing UDP checksum");
		#endif
        free(packet);
        return -4;
    }
    if(udp_header->dest != dest_port) {
		#ifdef DEBUG
        perror("[UDP] Packet not destined for us");
		#endif
        free(packet);
        return -4;
    }
    /**
     * Print packet details
     */
    printf("Recieved packet from\n\tmac address:\t");
    print_mac_address((u8*) ethernet_header->h_source);
    printf("\n\tsource:\t\t%s:%d", inet_ntoa((struct in_addr) { ipv4_header->saddr }), ntohs(udp_header->source));
    printf("\n\tdestination:\t%s:%d\n", inet_ntoa((struct in_addr) { ipv4_header->daddr }), ntohs(udp_header->dest));
    /**
     * Update the raw_packet_ptr result struct
     */
    raw_packet_ptr_ptr->ethernet_header_ptr = (u8*) ethernet_header;
    raw_packet_ptr_ptr->ipv4_header_ptr =  (u8*) ipv4_header;
    raw_packet_ptr_ptr->udp_header_ptr =  (u8*) udp_header;
    raw_packet_ptr_ptr->data_ptr =  (u8*) data;
    raw_packet_ptr_ptr->data_len = data_length;
    return 0;
}

/**
 * Free raw packet
 */
void close_raw_packet(raw_packet_ptr* raw_packet_ptr_ptr) {
    free(raw_packet_ptr_ptr->ethernet_header_ptr);
    memset(raw_packet_ptr_ptr, 0, sizeof(raw_packet_ptr));
}