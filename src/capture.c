#include "capture.h"
#include "parser.h"
#include <stdlib.h>

/**
 * lisening_to_network
 * -------------------
 * Entry point for starting live packet capture.
 *
 * Responsibilities:
 *   1. Open a live network interface using pcap_open_live().
 *   2. Begin a capture loop with pcap_loop(), which dispatches
 *      each packet to the callback function got_packet().
 *   3. (Future) Support clean shutdown: use pcap_breakloop()
 *      from a signal handler and call pcap_close() on 'descr'.
 *
 * Usage:
 *   Run the program with root privileges:
 *       sudo ./ids
 *
 *   In another terminal, generate traffic to see results:
 *       ping 8.8.8.8
 *       curl http://example.com
 */
void lisening_to_network()
{
    /* Example configuration array (placeholder).
     * In a real IDS, this could hold filters, thresholds, etc. */
    Configuration conf[2] = {
        {0, "foo"},
        {1, "bar"}
    };

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;

    /* Open the interface in promiscuous mode to capture all traffic.
     * INTERNET_INTERFACE, SNAP_LEN, PROMISC, TIMEOUT_MS come from capture.h */
    descr = pcap_open_live(INTERNET_INTERFACE, SNAP_LEN, PROMISC, TIMEOUT_MS, errbuf);
    if (descr == NULL)
    {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        exit(1);
    }

    /* Capture packets indefinitely.
     * NON_STOP_LOOP (-1) tells pcap_loop to never stop unless explicitly broken. */
    pcap_loop(descr, NON_STOP_LOOP, got_packet, (u_char *)conf);
}

/**
 * got_packet
 * ----------
 * Callback function invoked by libpcap for every captured packet.
 *
 * Parameters:
 *   @user   - Opaque user data pointer provided to pcap_loop().
 *             Here we cast it back to (Configuration *) to access runtime state.
 *   @header - Metadata for the captured packet:
 *               - ts: timestamp (seconds + microseconds)
 *               - caplen: number of bytes actually captured
 *               - len: original length of packet on the wire
 *   @packet - Pointer to raw packet data (starts with Ethernet header).
 *
 * Current behavior:
 *   - Forwards packet to parse_packet() for decoding and printing.
 *
 * Future behavior:
 *   - Maintain statistics (flows, byte counts, anomaly detection).
 *   - Implement IDS rules (e.g., detect floods, port scans).
 */
void got_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    Configuration *args = (Configuration *)user;
    ParsedPacket pp = NULL;
    /* Forward packet for parsing/printing. 
     * Unused variables are explicitly cast to void in parse_packet. */
    ParseStatus sp = parse_packet(args, header, packet , &pp);

    
}
