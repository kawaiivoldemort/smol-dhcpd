#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include "net_if.h"
#include "types.h"

/**
 * UDP-IPv4-Ethernet Frame
 */
typedef struct __attribute__((__packed__)) udp_packet {
    struct ethhdr   ethernet_header;
    struct iphdr    ipv4_header;
    struct udphdr   udp_header;
    u8              data[0];
} udp_packet;

/**
 * Pseudo UDP Packet used for computation of the UDP checksum
 */
typedef struct __attribute__((__packed__)) pseudo_udp_packet {
    struct {
        u32 source_ip;
        u32 dest_ip;
        u8  placeholder;
        u8  protocol;
        u16 udp_length;
    }               pseudo_ip_header;
    struct udphdr   udp_header;
    u8              data[0];
} pseudo_udp_packet;

/**
 * Raw packet pointers to an existing heap bloack
 */
typedef struct raw_packet_ptr {
    u8* ethernet_header_ptr;
    u8* ipv4_header_ptr;
    u8* udp_header_ptr;
    u8* data_ptr;
    u16 data_len;
} raw_packet_ptr;

/**
 * Header sizes
 */
#define HEADER_LENGTH sizeof(struct udp_packet)
#define IPV4_HEADER_LENGTH sizeof(struct iphdr)
#define UDP_HEADER_LENGTH sizeof(struct udphdr)
#define UDP_PSEUDO_PACKET_LENGTH sizeof(struct pseudo_udp_packet)
#define IPV4_MAX_PACKET_LENGTH 65535
// Max IPv4 Frame = 65535, 8 bytes used in the UDP header, 20 in the IPv4 header and the remaining for data (notwithstanding options)
#define MAX_UDP_IPV4_DATA_LENGTH (IPV4_MAX_PACKET_LENGTH - IPV4_HEADER_LENGTH - UDP_HEADER_LENGTH)

// Broadcast MAC address
static const u8 BROADCAST_MAC[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * Function Declerations
 */
u16 in_cksum(u16 *addr, int len);
u16 udp_cksum(u32 saddr, u32 daddr, struct udphdr* udp_header, u8* udp_data, int data_length);
int raw_ethernet_ipv4_udp_send(int raw_socket, net_if interface, u32 source_ip, u16 source_port, u32 dest_ip, u16 dest_port, u8* data, int data_length);
int raw_ethernet_ipv4_udp_recv(int raw_socket, net_if interface, u32 source_ip, u16 source_port, u32 dest_ip, u16 dest_port, int max_length, raw_packet_ptr* raw_packet_ptr_ptr);
void close_raw_packet(raw_packet_ptr* raw_packet_ptr_ptr);
int raw_ethernet_ipv4_udp_if_socket(net_if interface);