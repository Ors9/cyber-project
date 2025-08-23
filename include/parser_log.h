#ifndef PARSER_LOG_H
#define PARSER_LOG_H

#include <stdio.h>
#include "parser.h"

/* Basic log levels */
typedef enum
{
    LOG_INFO = 0,
    LOG_WARN = 1,
    LOG_ERR = 2
} LogLevel;


/*Log message with level */
void log_msg(LogLevel level, const char *msg);

/* Print a one-line packet summary (suitable for console/file logging) */
void pp_print_summary(FILE *out, const ParsedPacket *pp);

/* Print a more detailed packet dump (including L3/L4 fields) */
void pp_print_verbose(FILE *out, const ParsedPacket *pp);

/* Helper: convert TCP flags to string (e.g., "SYN|ACK") into a provided buffer */
const char *pp_tcp_flags_to_str(unsigned char flags, char *buf, size_t buflen);

#endif /* PARSER_LOG_H */