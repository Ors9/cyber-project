#ifndef PARSER_H
#define PARSER_H

/* =====================================================================
 * Packet Parser API — Layer-ordered: L2 ➜ L3 (IPv4) ➜ L4 (TCP/UDP/ICMP)
 * ===================================================================== */

/* ===== Includes ===== */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>      /* uint8_t/16/32 */
#include <pcap/pcap.h>   /* struct pcap_pkthdr */
#include <netinet/in.h>  /* in_addr, IPPROTO_* */
#include <netinet/ip.h>  /* struct ip (for field sizes/constants) */
#include <netinet/tcp.h> /* struct tcphdr (for flags bit positions) */
#include <netinet/udp.h> /* struct udphdr */
#include <arpa/inet.h>   /* ntohs/ntohl */
#include "config.h"      /* Configuration (capture options) */

/* =====================================================================
 * LAYER 2 — Ethernet
 * ===================================================================== */

/** Size of a MAC address in bytes. */
#define MAC_SIZE 6

/** Ethernet II header length (no VLAN tag). */
#define ETH_HDR_LEN 14

/** Offsets inside Ethernet header (bytes from frame start). */
#define ETH_DST_OFFSET 0   /* Destination MAC (6 bytes) */
#define ETH_SRC_OFFSET 6   /* Source MAC (6 bytes) */
#define ETH_TYPE_OFFSET 12 /* EtherType (2 bytes, big-endian on wire) */

/** Selected EtherType values (host order). */
typedef enum EtherType
{
    ETH_TYPE_UNKNOWN = 0,
    ETH_TYPE_IPv4 = 0x0800,
    ETH_TYPE_ARP = 0x0806,
    ETH_TYPE_IPv6 = 0x86DD
} EtherType;

/** Parsed view of Ethernet header (host order). */
typedef struct FirstLayerParsed
{
    uint8_t dst_mac[MAC_SIZE];
    uint8_t src_mac[MAC_SIZE];
    EtherType ethertype; /* e.g., 0x0800 for IPv4 */
} FirstLayerParsed;

/* =====================================================================
 * LAYER 3 — IPv4
 * ===================================================================== */

/** IPv4 fixeds & helpers */
#define IPV4_VERSION 4
#define IPV4_WORD_LEN 4       /* ip_hl is in 32-bit words; bytes = ip_hl*4 */
#define IPV4_MIN_HDR_BYTES 20 /* minimal IPv4 header (no options) */

/** IPv4 fragmentation masks/flags (apply after ntohs). */
#define IPV4_FLAG_DF 0x4000          /* Don't Fragment */
#define IPV4_FLAG_MF 0x2000          /* More Fragments */
#define IPV4_FRAG_OFFSET_MASK 0x1FFF /* offset in 8-byte units */

/** L3 protocol tag (for future IPv6/ARP support). */
typedef enum L3Protocol
{
    L3_UNKNOWN = 0,
    L3_IPV4,
    L3_IPV6,
    L3_ARP
} L3Protocol;

/** Parsed view of IPv4 header (host order where applicable). */
typedef struct SecondLayerParsed
{
    struct in_addr ip_src; /* use inet_ntop for printing */
    struct in_addr ip_dst; /* use inet_ntop for printing */
    uint8_t proto;         /* 1=ICMP, 6=TCP, 17=UDP */
    uint8_t ttl;           /* Time To Live */
    uint16_t total_len;    /* IP total length (host order) */
    uint16_t id;           /* Identification (host order) */
    uint16_t frag_off;     /* Flags + fragment offset (host order) */
} SecondLayerParsed;

/* =====================================================================
 * LAYER 4 — Transport (TCP/UDP/ICMP)
 * ===================================================================== */

/** Parsed view of transport header (host order). */
typedef struct ThirdLayerParsed
{
    /* TCP/UDP */
    uint16_t src_port; /* 0 if not TCP/UDP */
    uint16_t dst_port; /* 0 if not TCP/UDP */

    /* TCP only (optional: OR of flags bits, e.g., TH_SYN|TH_ACK) */
    uint8_t tcp_flags; /* 0 if not TCP */

    /* ICMP only */
    uint8_t icmp_type; /* 0 if not ICMP */
    uint8_t icmp_code; /* 0 if not ICMP */
} ThirdLayerParsed;

/* =====================================================================
 * CAPTURE METADATA (libpcap safe copy)
 * ===================================================================== */

typedef struct CaptureMeta
{
    uint32_t wire_len; /* Original length on the wire */
    uint32_t cap_len;  /* Captured length (could be < wire_len) */
    long ts_sec;       /* Timestamp seconds */
    long ts_usec;      /* Timestamp microseconds */
} CaptureMeta;

/* =====================================================================
 * PARSER STATUS & FLAGS
 * ===================================================================== */

typedef enum ParseStatus
{
    PARSE_OK = 0,    /* Parsing succeeded */
    PARSE_NON_IPV4,  /* Non-IPv4 (L3/L4 not decoded) */
    PARSE_TRUNC_ETH, /* Too short for Ethernet header */
    PARSE_TRUNC_IP,  /* Too short for full IPv4 header */
    PARSE_TRUNC_L4   /* Too short for TCP/UDP/ICMP header */
} ParseStatus;

/* Bitmask anomaly flags (combine in ParsedPacket.flags). */
#define PFLAG_VLAN 0x01    /* VLAN tag present (not yet decoded) */
#define PFLAG_TINY 0x02    /* Suspiciously small frame */
#define PFLAG_BADLEN 0x04  /* Length inconsistency (IP total vs caplen) */
#define PFLAG_IP_FRAG 0x08 /* IPv4 fragmentation detected */

/* Generic helper for functions that return an L4 start offset. */
#define PARSE_FAIL_OFFSET 0 /* size_t 0 ⇒ failure/no L4 */

/* =====================================================================
 * AGGREGATED PACKET VIEW
 * ===================================================================== */

typedef struct ParsedPacket
{
    CaptureMeta hdr;      /* libpcap metadata (copied) */
    FirstLayerParsed l2;  /* Ethernet */
    SecondLayerParsed l3; /* IPv4 view */
    ThirdLayerParsed l4;  /* Transport */

    L3Protocol l3_proto; /* Actual parsed L3 protocol */
    ParseStatus status;  /* Outcome */
    uint32_t flags;      /* PFLAG_* bitmask */
} ParsedPacket;

/* =====================================================================
 * PUBLIC API
 * ===================================================================== */

void parse_packet(Configuration *args, const struct pcap_pkthdr *header, const u_char *packet, ParsedPacket *pp);

#endif /* PARSER_H */
