#include "dhcp_client_daemon.h"

#define CURRENT_TIME (clock() * 1000.0 / (double) CLOCKS_PER_SEC)

/**
 * Only processes with an effective user ID of 0 or the CAP_NET_RAW capability are allowed
 * to open raw sockets so, please run as root
 * 
 * Error codes -
 * * -1 Not running as root
 * * -2 Failed to open a socket
 */
int dhcp_client_daemon(net_if interface) {
    /**
     * Initialize constants
     */
    // 0.0.0.0 and 255.255.255.255
    const u32 IN_ANY = htonl(INADDR_ANY);
    const u32 IN_BROADCAST = htonl(INADDR_BROADCAST);
    // port 67 and 68
    const u16 DHCP_SERVER_PT = htons(67);
    const u16 DHCP_CLIENT_PT = htons(68);

    /**
     * Local variables
     */
    // transaction id
    u32 txid;
    // listening socket and consuming socket
    int raw_socket_listening;
    int raw_socket_consuming;
    // user id and effective user id
    uid_t uid;
    uid_t euid;
    // timers
    double s_sec;
    double e_sec;
    clock_t recorded_time;
    // dhcp message
    dhcp_message msg;
    dhcp_raw_data* pkt;
    // dhcp offer data
    dhcp_offered_params* given_offer;
    dhcp_offered_params* accepted_offer;


    /**
     * Daemon
     */
    // Check if you are the root user
    uid = getuid();
    euid = geteuid();
    if((uid != 0) && (euid != 0)) {
        perror("Wrong permissions, run as root");
        return -1;
    }
    // Initialize transaction id
    txid = rand();
    // Initialize the socket
    if((raw_socket_listening = raw_ethernet_ipv4_udp_if_socket(interface)) < 0) {
        return -2;
    }
/**
 * Initializing State: Sending a DHCP Discover and waiting for offers
 */
init:
    // Send a DHCP Discover
    msg = dhcp_discover(interface, txid);
    encode_dhcp_packet(&msg);
    pkt = (dhcp_raw_data*) &msg;
    if(raw_ethernet_ipv4_udp_send(raw_socket_listening, interface, IN_ANY, DHCP_CLIENT_PT, IN_BROADCAST, DHCP_SERVER_PT, pkt->raw_data, pkt->packet_length) < 0) {
        perror("Failed to send the discover ... retrying");
        goto init;
    }
    puts("Discover sent\n");
    // Wait for a DHCP Offer
    s_sec = 0;
    e_sec = 5; // 5 seconds
    recorded_time = CURRENT_TIME;
    do {
        raw_packet_ptr rpp;

        // Receive a packet
        if(raw_ethernet_ipv4_udp_recv(raw_socket_listening, interface, IN_ANY, DHCP_SERVER_PT, IN_BROADCAST, DHCP_CLIENT_PT, HEADER_LENGTH + DHCP_MAX_PACKET_SIZE, &rpp) < 0) {
			#ifdef DEBUG
            perror("Failed to recieve a packet");
			#endif
        } else {
            // pkt points to the same memory location as msg to process data in place
            memcpy(pkt->raw_data, rpp.data_ptr, rpp.data_len);
            pkt->packet_length = rpp.data_len;
            decode_dhcp_packet(pkt);
            given_offer = unpack_dhcp_offer(interface, ((struct iphdr*) rpp.ipv4_header_ptr)->saddr, &msg, txid);
            if(given_offer != 0) {
                // dhcp offer recieved
                puts("Offer received\n");
                print_dhcp_offered_params(given_offer);
                close_raw_packet(&rpp);
                goto selecting_requesting;
            }
            // Close the packet data
            close_raw_packet(&rpp);
        }
        // Reset the time
        s_sec = CURRENT_TIME - recorded_time;
    } while(s_sec < e_sec);
    // Init timed out, restart
    puts("Init timed out ... retrying");
    goto init;
/**
 * Selecting state: Selecting the offer you want
 * Requesting state: requesting for a lease on the offered parameters
 * 
 * Not implemented: Check for AddressInUse via ARP and send DHCP Decline
 */
selecting_requesting:
    // Select offer and send a DHCP Request, then wait for an acknowledgement
    msg = dhcp_request(interface, given_offer, txid);
    encode_dhcp_packet(&msg);
    pkt = (dhcp_raw_data*) &msg;
    if(raw_ethernet_ipv4_udp_send(raw_socket_listening, interface, IN_ANY, DHCP_CLIENT_PT, IN_BROADCAST, DHCP_SERVER_PT, pkt->raw_data, pkt->packet_length) < 0) {
		#ifdef DEBUG
        perror("Failed to send the discover ... retrying");
		#endif
        goto selecting_requesting;
    }
    puts("Request sent\n");
    // Wait for a DHCP Offer
    s_sec = 0;
    e_sec = 5; // 5 seconds
    recorded_time = CURRENT_TIME;
    do {
        raw_packet_ptr rpp;

        // Receive a packet
        if(raw_ethernet_ipv4_udp_recv(raw_socket_listening, interface, IN_ANY, DHCP_SERVER_PT, IN_BROADCAST, DHCP_CLIENT_PT, HEADER_LENGTH + DHCP_MAX_PACKET_SIZE, &rpp) < 0) {
			#ifdef DEBUG
            perror("Failed to recieve a packet");
			#endif
        } else {
            // pkt points to the same memory location as msg to process data in place
            memcpy(pkt->raw_data, rpp.data_ptr, rpp.data_len);
            pkt->packet_length = rpp.data_len;
            decode_dhcp_packet(pkt);
            accepted_offer = unpack_dhcp_ack(interface, ((struct iphdr*) rpp.ipv4_header_ptr)->saddr, &msg, txid);
            if(accepted_offer != 0) {
                if(accepted_offer->ack == 1) {
                    // dhcp offer recieved
                    puts("Ack received\n");
                    print_dhcp_offered_params(accepted_offer);
                    close_dhcp_offered_params(given_offer);
                    close_raw_packet(&rpp);
                    goto bound;
                } else {
                    puts("Nack received\n");
                    goto init;
                }
            }
            // Close the packet data
            close_raw_packet(&rpp);
        }
        // Reset the time
        s_sec = CURRENT_TIME - recorded_time;
    } while(s_sec < e_sec);
    // Request timed out, restart
    puts("Request timed out ... retrying");
    goto selecting_requesting;
/**
 * Bound state: Recieve a DHCP Lease and wait for expiry, use the offered params in the meantime
 */
bound:
    // Send a DHCP Release
    msg = dhcp_release(interface, accepted_offer, txid);
    encode_dhcp_packet(&msg);
    pkt = (dhcp_raw_data*) &msg;
    close_dhcp_offered_params(accepted_offer);
    if(raw_ethernet_ipv4_udp_send(raw_socket_listening, interface, accepted_offer->ip.s_addr, DHCP_CLIENT_PT, accepted_offer->ss_ip.s_addr, DHCP_SERVER_PT, pkt->raw_data, pkt->packet_length) < 0) {
		#ifdef DEBUG
        perror("Failed to release");
		#endif
        return -5;
    }
}