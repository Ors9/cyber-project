#ifndef PARSER_H
#define PARSER_H

#include <pcap/pcap.h>
#include "capture.h"
#include <stdint.h> /* uint8_t / uint16_t / uint32_t */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* ============================================================
 * IPv4 constants
 * ============================================================
 */

/*Constant for Mac size array of layer 2*/
#define MAC_SIZE 6


/* ip_hl in struct ip is measured in 32-bit words.
 * Multiply by IPV4_WORD_LEN to convert to bytes. */
#define IPV4_WORD_LEN 4

/* ============================================================
 * Ethernet constants and offsets
 * ============================================================
 */

/* Fixed Ethernet header length (without VLAN tag). */
#define ETH_HDR_LEN 14

/* Common EtherTypes (host order).
 * These identify which protocol is encapsulated in the Ethernet payload. */
#define ETH_TYPE_IPv4 0x0800 /* IPv4 */
#define ETH_TYPE_ARP 0x0806  /* ARP  */
#define ETH_TYPE_IPv6 0x86DD /* IPv6 */

/* Byte offsets inside the Ethernet header. */
#define ETH_DST_OFFSET 0   /* Destination MAC start (6 bytes) */
#define ETH_SRC_OFFSET 6   /* Source MAC start (6 bytes) */
#define ETH_TYPE_OFFSET 12 /* EtherType (2 bytes, big-endian) */

/* ============================================================
 * Parser status & anomaly flags
 * ============================================================
 */

/*
 * ParseStatus
 * -----------
 * Describes the outcome of packet parsing.
 */
typedef enum
{
    PARSE_OK = 0,    /* Parsing succeeded */
    PARSE_NON_IPV4,  /* Packet is not IPv4 (e.g., ARP/IPv6, not decoded further yet) */
    PARSE_TRUNC_ETH, /* Too short for full Ethernet header (14 bytes) */
    PARSE_TRUNC_IP,  /* Too short for full IPv4 header */
    PARSE_TRUNC_L4   /* Too short for TCP/UDP/ICMP header */
} ParseStatus;

/*
 * PFLAG_* bitmask flags
 * ---------------------
 * Mark anomalies or notable properties.
 * Multiple flags can be combined in ParsedPacket.flags.
 */
#define PFLAG_VLAN 1    /* VLAN tag present (802.1Q/802.1ad) */
#define PFLAG_TINY 2    /* Packet unusually small compared to expectations */
#define PFLAG_BADLEN 4  /* Length inconsistency (e.g., IP total vs. caplen) */
#define PFLAG_IP_FRAG 8 /* IPv4 fragmentation detected */

/* ============================================================
 * Layered parsed views
 * ============================================================
 */

/* L3 protocol tag for distinguishing IPv4/IPv6/ARP. */
typedef enum
{
    L3_UNKNOWN = 0,
    L3_IPV4,
    L3_IPV6,
    L3_ARP
} L3Protocol;



/* Layer 2 – Ethernet (host order fields). */
typedef struct
{
    uint8_t dst_mac[MAC_SIZE];
    uint8_t src_mac[MAC_SIZE];
    uint16_t ethertype; /* e.g. 0x0800 (IPv4) */
} FirstLayerParsed;

/* Layer 3 – IPv4 view (IPv4-specific fields).
 * For IPv6 support later:
 *  - define a parallel struct (e.g., SecondLayerIPv6), or
 *  - turn SecondLayerParsed into a union tagged by L3Protocol. */
typedef struct
{
    struct in_addr ip_src; /* Source IPv4 address */
    struct in_addr ip_dst; /* Destination IPv4 address */
    uint8_t proto;         /* 1=ICMP, 6=TCP, 17=UDP */
    uint8_t ttl;           /* Time To Live */
    uint16_t total_len;    /* Total length (host order) */
    uint16_t id;           /* Identification (host order) */
    uint16_t frag_off;     /* Fragment offset + flags (host order) */
} SecondLayerParsed;

/* Layer 4 – Transport layer (TCP/UDP/ICMP), host order. */
typedef struct
{
    uint16_t src_port; /* Source port (TCP/UDP) */
    uint16_t dst_port; /* Destination port (TCP/UDP) */
    uint8_t tcp_flags; /* If TCP: SYN/ACK/FIN/RST/PSH bits */
    uint8_t icmp_type; /* If ICMP/ICMPv6: type */
    uint8_t icmp_code; /* If ICMP/ICMPv6: subtype/code */
} ThirdLayerParsed;

/* Metadata from libpcap header.
 * Unlike a raw pointer to pcap_pkthdr, these values are safe to keep. */
typedef struct
{
    uint32_t wire_len; /* Original length of the packet on the wire */
    uint32_t cap_len;  /* Captured length (may be smaller than wire_len) */
    long ts_sec;       /* Capture timestamp (seconds) */
    long ts_usec;      /* Capture timestamp (microseconds) */
} CaptureMeta;

/* ============================================================
 * Packet wrapper
 * ============================================================
 */

/* ParsedPacket
 * ------------
 * Groups metadata + parsed views of Ethernet, IP, and Transport headers.
 */
typedef struct
{
    CaptureMeta hdr;      /* Safe copy of metadata */
    FirstLayerParsed l2;  /* Parsed Ethernet layer */
    SecondLayerParsed l3; /* Parsed network layer (currently IPv4) */
    ThirdLayerParsed l4;  /* Parsed transport layer */

    L3Protocol l3_proto; /* Which L3 protocol is actually parsed */
    ParseStatus status;  /* Parsing status result */
    uint32_t flags;      /* Anomaly flags (PFLAG_*) */
} ParsedPacket;

/* ============================================================
 * API
 * ============================================================
 */

/* Parse a captured packet into a ParsedPacket representation. */
void parse_packet(Configuration *args, const struct pcap_pkthdr *header, const u_char *packet , ParsedPacket * pp);
void parse_ethernet_l2(const u_char *packet, ParsedPacket *pp);

#endif /* PARSER_H */
