#ifndef CAPTURE_H
#define CAPTURE_H
#include <pcap.h>
#include "config.h"
#include "parser_log.h"

void lisening_to_network(LogMode logMode);

#endif
