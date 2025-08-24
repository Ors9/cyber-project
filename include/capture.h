#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "config.h"

/* forward declaration של enum LogMode */
enum LogMode;

/* capture API */
void lisening_to_network(LogMode logMode);

#endif /* CAPTURE_H */