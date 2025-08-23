#ifndef CAPTURE_H
#define CAPTURE_H
#include <pcap.h>
#include "config.h"

void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt);
void lisening_to_network();

#endif
