#include "capture.h"
#include "parser.h"
#include <stdlib.h>
#include "parser_log.h"

/* static prototypes (file-local) */
static void got_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

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
void lisening_to_network(LogMode logMode)
{
    /* Example configuration array (placeholder).
     * TODO: replace with real IDS configuration:
     *   - log mode (verbose/events/debug)
     *   - thresholds for alerts (e.g., SYN flood detection)
     *   - filters (e.g., ignore local traffic, whitelist hosts)
     *   - other runtime options
     *
     * Right now just holds dummy values "foo" and "bar"
     * so that got_packet() has a Configuration* to work with.
     */
    Configuration conf[1] = {{logMode, 1, "Or Test"}};

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
static void got_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    Configuration *args = (Configuration *)user;
    ParsedPacket pp;
    
    /* Forward packet for parsing/printing.
     * Unused variables are explicitly cast to void in parse_packet. */
    parse_packet(args, header, packet, &pp);
    
    /* Choose printing function based on mode */
    ParsedLinePrinter(stdout , &pp , args->logmode);

}
