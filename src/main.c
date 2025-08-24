#include <stdio.h>
#include <stdlib.h>
#include "string.h"
#include "capture.h"
#include "parser_log.h"

/**
 * ids - program entry point (main).
 *
 * Usage:
 *   sudo ./ids
 *       → Default (SUMMARY mode): print standard summaries for all packets.
 *
 *   sudo ./ids -E
 *       → EVENTS mode: print only major events (TCP SYN/FIN/RST, ICMP echo).
 *
 *   sudo ./ids -D
 *       → DEBUG mode: very detailed dump of all layers (developer debugging).
 */
int main(int argc, char **argv)
{
    LogMode logMode = LOGMODE_SUMMARY; /* default */

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-E") == 0)
        {
            logMode = LOGMODE_EVENTS;
            log_msg(LOG_INFO, "EVENTS mode enabled");
        }
        else if (strcmp(argv[i], "-D") == 0)
        {
            logMode = LOGMODE_DEBUG;
            log_msg(LOG_INFO, "DEBUG mode enabled");
        }
        else
        {
            logMode = LOGMODE_SUMMARY;
            log_msg(LOG_INFO, "SUMMARY mode enabled");
        }
    }

    /* start listening to network traffic (capture loop) */
    lisening_to_network(logMode);
    return 0;
}
