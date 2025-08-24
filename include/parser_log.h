#ifndef PARSER_LOG_H
#define PARSER_LOG_H

#include <stdio.h>
#include "config.h"
#include <arpa/inet.h>   /* inet_ntop */
#include <netinet/in.h>  /* IPPROTO_* */
#include <netinet/tcp.h> /* TH_SYN, TH_ACK, ... */

/* Forward declaration only (avoid including parser.h here) */
struct ParsedPacket;

/* Severity levels for generic logging */
typedef enum
{
    LOG_INFO = 0, /* Informational message */
    LOG_WARN = 1, /* Warning (non-critical) */
    LOG_ERR = 2   /* Error message */
} LogLevel;

/* Print a message with given severity (INFO/WARN/ERROR). */
void log_msg(LogLevel level, const char *msg);

void ParsedLinePrinter(FILE *out, const struct ParsedPacket *pp, LogMode logMode);

/* Convert TCP flags to string (e.g., "SYN|ACK") into the provided buffer. */
const char *pp_tcp_flags_to_str(unsigned char flags, char *buf, size_t buflen);

#endif /* PARSER_LOG_H */
