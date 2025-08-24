#include "parser_log.h"
#include <string.h>
#include "parser.h"
#include <arpa/inet.h>   /* inet_ntop */
#include <netinet/in.h>  /* IPPROTO_* */
#include <netinet/tcp.h> /* TH_SYN, TH_ACK, ... */

/* ---- internal prototypes (static) ---- */
static const char *status_name(ParseStatus s);
static int tcp_event_should_print(unsigned char f, LogMode mode);
static void tcp_print_event(FILE *out, const char *src_ip, unsigned sport, const char *dst_ip, unsigned dport, unsigned char f);
static void pp_print_summary(FILE *out, const ParsedPacket *pp, LogMode mode);
static void pp_print_verbose(FILE *out, const ParsedPacket *pp);

/* Print a message with a severity prefix (INFO, WARN, ERROR). */
void log_msg(LogLevel level, const char *msg)
{
    switch (level)
    {
    case LOG_INFO:
        printf("[INFO] %s\n", msg);
        break;
    case LOG_WARN:
        printf("[WARN] %s\n", msg);
        break;
    case LOG_ERR:
        printf("[ERROR] %s\n", msg);
        break;
    }
}

/* Convert ParseStatus enum into a short human-readable string. */
static const char *status_name(ParseStatus s)
{
    switch (s)
    {
    case PARSE_OK:
        return "OK";
    case PARSE_NON_IPV4:
        return "NON_IPv4";
    case PARSE_TRUNC_ETH:
        return "TRUNC_ETH";
    case PARSE_TRUNC_IP:
        return "TRUNC_IP";
    case PARSE_TRUNC_L4:
        return "TRUNC_L4";
    default:
        return "UNKNOWN";
    }
}

/* Build a string like "SYN|ACK" from a TCP flags byte. */
const char *pp_tcp_flags_to_str(unsigned char f, char *buf, size_t n)
{
    /* Order: URG ACK PSH RST SYN FIN */
    buf[0] = '\0';
    int first = 1;
#define APPEND(flagname, cond)                 \
    do                                         \
    {                                          \
        if (cond)                              \
        {                                      \
            if (!first && strlen(buf) + 1 < n) \
                strncat(buf, "|", n - 1);      \
            if (strlen(buf) + 4 < n)           \
                strncat(buf, flagname, n - 1); \
            first = 0;                         \
        }                                      \
    } while (0)
    APPEND("URG", f & TH_URG);
    APPEND("ACK", f & TH_ACK);
    APPEND("PSH", f & TH_PUSH);
    APPEND("RST", f & TH_RST);
    APPEND("SYN", f & TH_SYN);
    APPEND("FIN", f & TH_FIN);
#undef APPEND
    if (buf[0] == '\0')
    {
        if (n >= 2)
            strcpy(buf, "-");
    }
    return buf;
}

/* === helpers for EVENTS mode ============================================== */

/* Decide if this TCP packet should be printed in EVENTS mode. */
static int tcp_event_should_print(unsigned char f, LogMode mode)
{
    if (mode == LOGMODE_SUMMARY)
        return 1; /* always show in summary */
    int syn = (f & TH_SYN) != 0;
    int ack = (f & TH_ACK) != 0;
    int fin = (f & TH_FIN) != 0;
    int rst = (f & TH_RST) != 0;
    if (syn && !ack)
        return 1; /* SYN      */
    if (syn && ack)
        return 1; /* SYN|ACK  */
    if (fin || rst)
        return 1; /* FIN/RST  */
    return 0;     /* drop noise in EVENTS */
}

/* Print a short one-line summary for major TCP events. */
static void tcp_print_event(FILE *out, const char *src_ip, unsigned sport,
                            const char *dst_ip, unsigned dport, unsigned char f)
{
    int syn = (f & TH_SYN) != 0;
    int ack = (f & TH_ACK) != 0;
    int fin = (f & TH_FIN) != 0;
    int rst = (f & TH_RST) != 0;

    if (syn && !ack)
    {
        fprintf(out, "[TCP OPEN ] %s:%u -> %s:%u (SYN)\n",
                src_ip, sport, dst_ip, dport);
    }
    else if (syn && ack)
    {
        fprintf(out, "[TCP OPEN ] %s:%u -> %s:%u (SYN|ACK)\n",
                src_ip, sport, dst_ip, dport);
    }
    else if (fin)
    {
        fprintf(out, "[TCP CLOSE] %s:%u -> %s:%u (FIN)\n",
                src_ip, sport, dst_ip, dport);
    }
    else if (rst)
    {
        fprintf(out, "[TCP CLOSE] %s:%u -> %s:%u (RST)\n",
                src_ip, sport, dst_ip, dport);
    }
    else
    {
        /* Should not normally happen in EVENTS mode. */
        char fbuf[32];
        pp_tcp_flags_to_str(f, fbuf, sizeof(fbuf));
        fprintf(out, "[OK] TCP %s:%u -> %s:%u (%s)\n",
                src_ip, sport, dst_ip, dport, fbuf);
    }
}

/*Send to the right print function based on the log mode*/
void ParsedLinePrinter(FILE *out, const struct ParsedPacket *pp, LogMode logMode)
{
    switch (logMode)
    {
    case LOGMODE_SUMMARY:
        pp_print_summary(out, pp, LOGMODE_SUMMARY); /* מצב תקציר רגיל */
        break;

    case LOGMODE_EVENTS:
        pp_print_summary(out, pp, LOGMODE_EVENTS); /* מצב אירועים בלבד */
        break;

    case LOGMODE_DEBUG:
        pp_print_verbose(out, pp); /* מצב דיבוג מפורט */
        break;
    default:
        break;
    }
}

/* ========================================================================== */

/* Print a short summary line for each packet (depends on mode). */
static void pp_print_summary(FILE *out, const struct ParsedPacket *pp, LogMode mode)
{
    if (!out || !pp)
        return;

    char src_ip[INET6_ADDRSTRLEN] = {0};
    char dst_ip[INET6_ADDRSTRLEN] = {0};

    if (pp->l3_proto == L3_IPV4)
    {
        inet_ntop(AF_INET, &pp->l3.ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &pp->l3.ip_dst, dst_ip, sizeof(dst_ip));
    }

    /* status prefix only in SUMMARY mode */
    if (mode == LOGMODE_SUMMARY)
    {
        fprintf(out, "[%s] ", status_name(pp->status));
    }

    if (pp->l3_proto == L3_IPV4 && pp->status == PARSE_OK)
    {
        switch (pp->l3.proto)
        {
        case IPPROTO_TCP:
        {
            if (!tcp_event_should_print(pp->l4.tcp_flags, mode))
                return;

            if (mode == LOGMODE_EVENTS)
            {
                tcp_print_event(out, src_ip, (unsigned)pp->l4.src_port,
                                dst_ip, (unsigned)pp->l4.dst_port, pp->l4.tcp_flags);
            }
            else
            {
                char fbuf[32];
                pp_tcp_flags_to_str(pp->l4.tcp_flags, fbuf, sizeof(fbuf));
                fprintf(out, "TCP %s:%u -> %s:%u (%s)\n",
                        src_ip, (unsigned)pp->l4.src_port,
                        dst_ip, (unsigned)pp->l4.dst_port, fbuf);
            }
            break;
        }
        case IPPROTO_UDP:
            if (mode == LOGMODE_EVENTS)
            {
                fprintf(out, "[UDP ] %s:%u -> %s:%u\n",
                        src_ip, (unsigned)pp->l4.src_port,
                        dst_ip, (unsigned)pp->l4.dst_port);
            }
            else
            {
                fprintf(out, "UDP %s:%u -> %s:%u\n",
                        src_ip, (unsigned)pp->l4.src_port,
                        dst_ip, (unsigned)pp->l4.dst_port);
            }
            break;
        case IPPROTO_ICMP:
            if (mode == LOGMODE_EVENTS)
            {
                if (pp->l4.icmp_type == 8 && pp->l4.icmp_code == 0)
                {
                    fprintf(out, "[ICMP] Echo request %s -> %s\n", src_ip, dst_ip);
                }
                else if (pp->l4.icmp_type == 0 && pp->l4.icmp_code == 0)
                {
                    fprintf(out, "[ICMP] Echo reply   %s -> %s\n", src_ip, dst_ip);
                }
            }
            else
            {
                fprintf(out, "ICMP %s -> %s (type=%u code=%u)\n",
                        src_ip, dst_ip,
                        (unsigned)pp->l4.icmp_type, (unsigned)pp->l4.icmp_code);
            }
            break;
        default:
            if (mode == LOGMODE_SUMMARY)
            {
                fprintf(out, "IP proto=%u %s -> %s\n",
                        (unsigned)pp->l3.proto, src_ip, dst_ip);
            }
            break; /* EVENTS: skip unhandled protocols */
        }
    }
    else if (pp->l3_proto == L3_ARP)
    {
        if (mode == LOGMODE_EVENTS)
            fprintf(out, "[ARP]\n");
        else
            fprintf(out, "ARP frame\n");
    }
    else if (pp->l3_proto == L3_IPV6)
    {
        if (mode == LOGMODE_SUMMARY)
            fprintf(out, "IPv6 (not parsed yet)\n");
    }
    else
    {
        if (mode == LOGMODE_SUMMARY)
            fprintf(out, "Non-IPv4 or truncated\n");
    }
}

/* Print a very detailed dump of the packet (for debugging). */
static void pp_print_verbose(FILE *out, const struct ParsedPacket *pp)
{
    if (!out || !pp)
        return;

    fprintf(out, "=== Packet ===\n");
    fprintf(out, "meta: wire=%u cap=%u ts=%ld.%06ld status=%s flags=0x%X\n",
            (unsigned)pp->hdr.wire_len, (unsigned)pp->hdr.cap_len,
            pp->hdr.ts_sec, pp->hdr.ts_usec,
            status_name(pp->status), (unsigned)pp->flags);

    fprintf(out, "L2: ethertype=0x%04X src=%02X:%02X:%02X:%02X:%02X:%02X dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
            (unsigned)pp->l2.ethertype,
            pp->l2.src_mac[0], pp->l2.src_mac[1], pp->l2.src_mac[2],
            pp->l2.src_mac[3], pp->l2.src_mac[4], pp->l2.src_mac[5],
            pp->l2.dst_mac[0], pp->l2.dst_mac[1], pp->l2.dst_mac[2],
            pp->l2.dst_mac[3], pp->l2.dst_mac[4], pp->l2.dst_mac[5]);

    if (pp->l3_proto == L3_IPV4)
    {
        char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pp->l3.ip_src, s, sizeof(s));
        inet_ntop(AF_INET, &pp->l3.ip_dst, d, sizeof(d));
        fprintf(out, "L3: IPv4 src=%s dst=%s proto=%u ttl=%u totlen=%u id=%u frag=0x%04X\n",
                s, d,
                (unsigned)pp->l3.proto, (unsigned)pp->l3.ttl,
                (unsigned)pp->l3.total_len, (unsigned)pp->l3.id,
                (unsigned)pp->l3.frag_off);

        switch (pp->l3.proto)
        {
        case IPPROTO_TCP:
        {
            char f[32];
            pp_tcp_flags_to_str(pp->l4.tcp_flags, f, sizeof(f));
            fprintf(out, "L4: TCP sport=%u dport=%u flags=%s\n",
                    (unsigned)pp->l4.src_port, (unsigned)pp->l4.dst_port, f);
            break;
        }
        case IPPROTO_UDP:
            fprintf(out, "L4: UDP sport=%u dport=%u\n",
                    (unsigned)pp->l4.src_port, (unsigned)pp->l4.dst_port);
            break;
        case IPPROTO_ICMP:
            fprintf(out, "L4: ICMP type=%u code=%u\n",
                    (unsigned)pp->l4.icmp_type, (unsigned)pp->l4.icmp_code);
            break;
        default:
            fprintf(out, "L4: proto=%u (not decoded)\n", (unsigned)pp->l3.proto);
            break;
        }
    }
    else if (pp->l3_proto == L3_ARP)
    {
        fprintf(out, "L3: ARP (not decoded yet)\n");
    }
    else if (pp->l3_proto == L3_IPV6)
    {
        fprintf(out, "L3: IPv6 (not decoded yet)\n");
    }
}
