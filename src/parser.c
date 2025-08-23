#include "parser.h"
#include <stdio.h>
#include <string.h>

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
void parse_packet(Configuration *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args; /* not used yet */

    /* === Basic capture metadata === */
    size_t caplen = header->caplen; /* number of bytes actually captured */
    long sec = header->ts.tv_sec;   /* timestamp: seconds */
    long usec = header->ts.tv_usec; /* timestamp: microseconds */

    printf("[ts=%ld.%06ld caplen=%zu len=%u]", 
           sec, usec, caplen, (unsigned)header->len);

    /* === Ethernet layer === */
    /* Must have enough bytes for Ethernet header (14 bytes). */
    if (caplen < ETH_HDR_LEN) {
        puts(" (short Ethernet header)");
        return;
    }

    /* Extract EtherType field (bytes 12–13 of Ethernet header). */
    unsigned int ethertype = ((unsigned int)packet[ETH_TYPE_OFFSET] << 8) 
                           | packet[ETH_TYPE_OFFSET + 1];

    /* For now, only handle IPv4 (0x0800). Print ARP/IPv6 if seen. */
    if (ethertype != ETH_TYPE_IPv4) {
        if (ethertype == ETH_TYPE_ARP)
            puts(" PROTO=ARP");
        else if (ethertype == ETH_TYPE_IPv6)
            puts(" PROTO=IPv6");
        putchar('\n');
        return;
    }

    /* === IPv4 layer === */
    const struct ip *iph = (const struct ip *)(packet + ETH_HDR_LEN);
    size_t ip_hdr_len = (size_t)iph->ip_hl * IPV4_WORD_LEN; /* ip_hl is in 32-bit words */

    /* Ensure the full IPv4 header is captured. */
    if (caplen < ETH_HDR_LEN + ip_hdr_len) {
        puts(" (short IPv4 header)");
        return;
    }

    /* Convert source/destination IP addresses to strings. */
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src, sizeof src);
    inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof dst);

    /* Pointer to the Layer 4 (transport) header. */
    const u_char *l4 = packet + ETH_HDR_LEN + ip_hdr_len;

    /* Extract protocol field: 1=ICMP, 6=TCP, 17=UDP. */
    unsigned char proto = iph->ip_p;

    /* === Transport layer switch === */
    switch (proto) {
    case IP_PROTO_ICMP:
        printf(" SRC=%s → DST=%s PROTO=ICMP LEN=%u\n",
               src, dst, (unsigned)header->len);
        return;

    case IP_PROTO_TCP: {
        /* Validate minimum TCP header length. */
        if (caplen < ETH_HDR_LEN + ip_hdr_len + sizeof(struct tcphdr)) {
            puts(" (short TCP header)");
            return;
        }
        const struct tcphdr *tcph = (const struct tcphdr *)l4;
        unsigned sport = ntohs(tcph->source);
        unsigned dport = ntohs(tcph->dest);
        printf(" SRC=%s:%u → DST=%s:%u PROTO=TCP LEN=%u\n",
               src, sport, dst, dport, (unsigned)header->len);
        return;
    }

    case IP_PROTO_UDP: {
        /* Validate minimum UDP header length. */
        if (caplen < ETH_HDR_LEN + ip_hdr_len + sizeof(struct udphdr)) {
            puts(" (short UDP header)");
            return;
        }
        const struct udphdr *udph = (const struct udphdr *)l4;
        unsigned sport = ntohs(udph->source);
        unsigned dport = ntohs(udph->dest);
        printf(" SRC=%s:%u → DST=%s:%u PROTO=UDP LEN=%u\n",
               src, sport, dst, dport, (unsigned)header->len);
        return;
    }

    default:
        /* Unknown or unsupported protocol: print numeric code. */
        printf(" SRC=%s → DST=%s PROTO=%u LEN=%u\n",
               src, dst, (unsigned)proto, (unsigned)header->len);
        return;
    }
}
