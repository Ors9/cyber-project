#include <stdio.h>
#include <stdlib.h>
#include "string.h"
#include "config.h"
#include "capture.h"
#include "parser_log.h"

/**
 * ids - entry point
 *
 *
 * Example runs:
 *   sudo ./ids
 *       Default (verbose) mode – full output for all packets.
 *
 *   sudo ./ids -E
 *       Events-only mode – prints only major TCP/ICMP events. (LOGMODE_EVENT_PRINT_ONLY_MAJOR)
 *
 */
int main(int argc, char **argv)
{

    for (int i = 1; i < argc; i++)
    {
        // if the argument equals to -E,
        // switch output mode from VERBOSE (default) to EVENTS to see full prints
        if (strcmp(argv[i], LOGMODE_EVENT_PRINT_ONLY_MAJOR) == 0)
        {
            log_msg(LOG_INFO, "EVENTS mode enabled");
            set_log_mode(LOGMODE_EVENTS);
        }
    }

    // start listening to network traffic (capture loop)
    lisening_to_network();

    return 0;
}
