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
void parse_packet(Configuration *args, const struct pcap_pkthdr *header, const u_char *packet, ParsedPacket *pp)
{
    (void)args; /* not used yet */

    /* === Basic capture metadata === */
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
    
    //here we need to do parse l3 but we need to do switch on the type !!

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
void parse_ethernet_l2(const u_char *packet, ParsedPacket *pp)
{
    /* Copy destination MAC (first 6 bytes) */
    memcpy(pp->l2.dst_mac, packet + ETH_DST_OFFSET, MAC_SIZE);

    /* Copy source MAC (next 6 bytes) */
    memcpy(pp->l2.src_mac, packet + ETH_SRC_OFFSET, MAC_SIZE);

    /* Extract EtherType (2 bytes, big-endian) */
    pp->l2.ethertype = ((unsigned int)packet[ETH_TYPE_OFFSET] << 8) | packet[ETH_TYPE_OFFSET + 1];
}
