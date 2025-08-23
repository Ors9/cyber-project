#ifndef PARSER_H
#define PARSER_H

#include <pcap/pcap.h>
#include "capture.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* ============================================================
 * IPv4 constants
 * ============================================================ */

/* ip_hl field in struct ip is measured in 32-bit words.
 * Multiply by IPV4_WORD_LEN to get header length in bytes. */
#define IPV4_WORD_LEN 4 

/* ============================================================
 * Ethernet constants and offsets
 * ============================================================ */

/* Fixed Ethernet header length (without VLAN tags) */
#define ETH_HDR_LEN 14       

/* Common EtherType values */
#define ETH_TYPE_IPv4 0x0800 /* IPv4 */
#define ETH_TYPE_ARP  0x0806 /* ARP  */
#define ETH_TYPE_IPv6 0x86DD /* IPv6 */

/* Byte offsets inside the Ethernet header */
#define ETH_DST_OFFSET  0   /* Destination MAC address (6 bytes) */
#define ETH_SRC_OFFSET  6   /* Source MAC address (6 bytes) */
#define ETH_TYPE_OFFSET 12  /* EtherType field (2 bytes, big-endian) */

/* ============================================================
 * IP protocol numbers (see IANA)
 * ============================================================ */
enum ip_protocol
{
    IP_PROTO_ICMP = 1,  /* Internet Control Message Protocol */
    IP_PROTO_TCP  = 6,  /* Transmission Control Protocol    */
    IP_PROTO_UDP  = 17  /* User Datagram Protocol           */
};

/* ============================================================
 * Function declarations
 * ============================================================ */
void parse_packet(Configuration *args,
                  const struct pcap_pkthdr *header,
                  const u_char *packet);

#endif /* PARSER_H */
