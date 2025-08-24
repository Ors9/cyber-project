#ifndef PARSER_LOG_H
#define PARSER_LOG_H

#include <stdio.h>
#include "parser.h"

/**
 * Logging/printing utilities for parsed packets.
 * Modes:
 *  - VERBOSE: print all packets with details.
 *  - EVENTS : print only major events (SYN/SYN|ACK/FIN/RST, ICMP echo, short ARP).
 */

#define LOGMODE_EVENT_PRINT_ONLY_MAJOR "-E" /* Command-line argument to enable EVENTS mode */

/* Output modes for packet logging */
typedef enum LogMode
{
    LOGMODE_VERBOSE = 0, /* Full printing (all packets, default) */
    LOGMODE_EVENTS = 1   /* Only major events (reduced noise)    */
} LogMode;

/* Severity levels for generic logging */
typedef enum
{
    LOG_INFO = 0, /* Informational message */
    LOG_WARN = 1, /* Warning (non-critical) */
    LOG_ERR = 2   /* Error message */
} LogLevel;

/* Print a message with given severity (INFO/WARN/ERROR). */
void log_msg(LogLevel level, const char *msg);

/* Change the global log mode (default is VERBOSE). */
void set_log_mode(LogMode m);

/* Print a one-line packet summary (used in normal console/file logging). */
void pp_print_summary(FILE *out, const ParsedPacket *pp);

/* Print a detailed packet dump (all available L3/L4 fields). */
void pp_print_verbose(FILE *out, const ParsedPacket *pp);

/* Convert TCP flags to string (e.g., "SYN|ACK") into the provided buffer. */
const char *pp_tcp_flags_to_str(unsigned char flags, char *buf, size_t buflen);

#endif /* PARSER_LOG_H */
