#include "parser.h"


/* static prototypes (file-local) */
static void parse_ethernet_l2(const u_char *packet, ParsedPacket *pp);
static size_t parse_ipv4_l3(const u_char *packet, size_t caplen, ParsedPacket *pp);
static void parse_l4_transport(const u_char *packet, size_t caplen, size_t l4_off, ParsedPacket *pp);

/*
 * parse_packet
 * ------------
 * Parse and print a captured packet from libpcap.
 *
 * Parameters:
 *   args   - runtime configuration (currently unused).
 *   header - pcap-provided metadata (timestamp, caplen, len).
 *   packet - pointer to the raw packet bytes (at least header->caplen long).
 *
 * Behavior:
 *   - Validates minimum lengths before dereferencing headers.
 *   - Decodes Ethernet header (checks EtherType).
 *   - If IPv4, decodes IP header and dispatches based on protocol.
 *   - Supports ICMP, TCP, and UDP with printing of addresses and ports.
 *   - Other protocols are printed as numeric codes.
 *
 * Notes:
 *   - Safe for truncated captures: returns early if header is too short.
 *   - Relies on constants defined in parser.h to avoid magic numbers.
 */
void parse_packet(Configuration *args, const struct pcap_pkthdr *header, const u_char *packet, ParsedPacket *pp )
{
    
    (void)args;
    /* init */
    memset(pp, 0, sizeof(*pp));
    pp->status = PARSE_OK;
    pp->l3_proto = L3_UNKNOWN;
    pp->file = stdout;
    /* === Basic capture metadata === */
    pp->hdr.wire_len = header->len;
    pp->hdr.cap_len = header->caplen;     /* number of bytes actually captured */
    pp->hdr.ts_sec = header->ts.tv_sec;   /* timestamp: seconds */
    pp->hdr.ts_usec = header->ts.tv_usec; /* timestamp: microseconds */

    /* === Ethernet layer === */
    /* Must have enough bytes for Ethernet header (14 bytes). */
    if (pp->hdr.cap_len < ETH_HDR_LEN)
    {
        pp->status = PARSE_TRUNC_ETH;
        puts(" (short Ethernet header)");
        return;
    }
    parse_ethernet_l2(packet, pp);

    /* L3 dispatch by EtherType */
    size_t l4_off = 0;
    switch (pp->l2.ethertype)
    {
    case ETH_TYPE_IPv4:
        l4_off = parse_ipv4_l3(packet, pp->hdr.cap_len, pp);
        if (l4_off == PARSE_FAIL_OFFSET)
        {
            return; /* status already set */
        }

        parse_l4_transport(packet, pp->hdr.cap_len, l4_off, pp);
        break;

    case ETH_TYPE_ARP:
        pp->l3_proto = L3_ARP;
        pp->status = PARSE_NON_IPV4; /* TODO: add ARP parser */
        return;

    case ETH_TYPE_IPv6:
        pp->l3_proto = L3_IPV6;
        pp->status = PARSE_NON_IPV4; /* TODO: add IPv6 parser */
        return;

    default:
        pp->status = PARSE_NON_IPV4; /* לא מטופל כרגע */
        return;
    }
}

/*
 * parse_ethernet_l2
 * -----------------
 * Parse the Layer 2 (Ethernet) header from a raw packet.
 *
 * Parameters:
 *   packet - pointer to the raw packet bytes (starting at Ethernet header).
 *   pp     - pointer to ParsedPacket struct where results are stored.
 *
 * Behavior:
 *   - Copies the destination MAC (first 6 bytes) into pp->l2.dst_mac.
 *   - Copies the source MAC (next 6 bytes) into pp->l2.src_mac.
 *   - Extracts the EtherType field (bytes 12–13, big-endian) into pp->l2.ethertype.
 *
 * Notes:
 *   - The Ethernet header is assumed to be at least 14 bytes long.
 *   - EtherType identifies which protocol is encapsulated (IPv4, ARP, IPv6, etc.).
 */
static void parse_ethernet_l2(const u_char *packet, ParsedPacket *pp)
{
    /* Copy destination MAC (first 6 bytes) */
    memcpy(pp->l2.dst_mac, packet + ETH_DST_OFFSET, MAC_SIZE);

    /* Copy source MAC (next 6 bytes) */
    memcpy(pp->l2.src_mac, packet + ETH_SRC_OFFSET, MAC_SIZE);

    /* Extract EtherType (2 bytes, big-endian) */
    pp->l2.ethertype = ((unsigned int)packet[ETH_TYPE_OFFSET] << 8) | packet[ETH_TYPE_OFFSET + 1];
}

/*
 * parse_ipv4_l3
 * -------------
 * Parse the IPv4 (Layer 3) header from a raw Ethernet frame.
 *
 * Parameters:
 *   packet - pointer to the raw packet bytes (start of Ethernet header).
 *   caplen - number of bytes actually captured (header->caplen).
 *   pp     - pointer to ParsedPacket struct to fill with IPv4 info.
 *
 * Behavior:
 *   - Verifies that enough bytes exist for a minimal IPv4 header.
 *   - Confirms IP version == 4.
 *   - Extracts IHL (Internet Header Length) in bytes and checks validity.
 *   - Fills ParsedPacket.l3 fields: src/dst IP, protocol, TTL, total_len, id, frag_off.
 *   - Sets pp->l3_proto = L3_IPV4.
 *
 * Return value:
 *   >0  : Offset (in bytes) from packet start to the beginning of L4 header.
 *   0   : Error (pp->status is set accordingly: PARSE_TRUNC_IP or PARSE_NON_IPV4).
 *
 * Notes:
 *   - Caller should check return value. If 0, parsing failed and L4 cannot be processed.
 *   - Fragmentation is noted in pp->l3.frag_off; you may set PFLAG_IP_FRAG accordingly.
 */
static size_t parse_ipv4_l3(const u_char *packet, size_t caplen, ParsedPacket *pp)
{
    /* must have at least Ethernet + minimal IPv4 header */
    if (caplen < ETH_HDR_LEN + sizeof(struct ip))
    {
        pp->status = PARSE_TRUNC_IP;
        return PARSE_FAIL_OFFSET;
    }

    const struct ip *iph = (const struct ip *)(packet + ETH_HDR_LEN);

    /* verify version */
    if (iph->ip_v != IPV4_VERSION)
    {
        pp->status = PARSE_NON_IPV4;
        return PARSE_FAIL_OFFSET;
    }

    /* IHL in 32-bit words → bytes */
    size_t ihl_bytes = (size_t)iph->ip_hl * IPV4_WORD_LEN;

    // Check if the header length is valid and fully captured
    // Case 1: header smaller than 20 bytes → invalid
    // Case 2: not enough captured bytes for full IP header → truncated
    if (ihl_bytes < IPV4_MIN_HDR_BYTES || caplen < ETH_HDR_LEN + ihl_bytes)
    {
        pp->status = PARSE_TRUNC_IP;
        return PARSE_FAIL_OFFSET;
    }

    /* fill L3 */
    pp->l3_proto = L3_IPV4;
    pp->l3.ip_src = iph->ip_src;
    pp->l3.ip_dst = iph->ip_dst;
    pp->l3.proto = iph->ip_p; /* 1/6/17 */
    pp->l3.ttl = iph->ip_ttl;
    pp->l3.total_len = ntohs(iph->ip_len);
    pp->l3.id = ntohs(iph->ip_id);
    pp->l3.frag_off = ntohs(iph->ip_off);

    /* optional: fragmentation flags */
    /* if ((pp->l3.frag_off & IPV4_FRAG_OFFSET_MASK) || (pp->l3.frag_off & IPV4_FLAG_MF))
         pp->flags |= PFLAG_IP_FRAG; */

    /* return offset where L4 starts */
    return ETH_HDR_LEN + ihl_bytes;
}

static void parse_l4_transport(const u_char *packet, size_t caplen, size_t l4_off, ParsedPacket *pp)
{
    // If total captured length is less than or equal to the offset where L4 should begin
    // → there are no bytes left for the transport-layer header (TCP/UDP/ICMP)
    if (caplen <= l4_off)
    {
        pp->status = PARSE_TRUNC_L4;
        return;
    }

    switch (pp->l3.proto)
    {
    case IPPROTO_TCP:
    {
        if (caplen < l4_off + sizeof(struct tcphdr))
        {
            pp->status = PARSE_TRUNC_L4;
            return;
        }
        const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4_off);
        pp->l4.src_port = ntohs(tcp->th_sport);
        pp->l4.dst_port = ntohs(tcp->th_dport);
        pp->l4.tcp_flags = tcp->th_flags;
        break;
    }
    case IPPROTO_UDP:
    {
        if (caplen < l4_off + sizeof(struct udphdr))
        {
            pp->status = PARSE_TRUNC_L4;
            return;
        }
        const struct udphdr *udp = (const struct udphdr *)(packet + l4_off);
        pp->l4.src_port = ntohs(udp->uh_sport);
        pp->l4.dst_port = ntohs(udp->uh_dport);
        break;
    }
    case IPPROTO_ICMP:
    {
        if (caplen < l4_off + 2)
        {
            pp->status = PARSE_TRUNC_L4;
            return;
        }
        pp->l4.icmp_type = packet[l4_off + 0];
        pp->l4.icmp_code = packet[l4_off + 1];
        break;
    }
    default:
        /* unsupported L4 → leave pp->l4 zeros */
        break;
    }
}
