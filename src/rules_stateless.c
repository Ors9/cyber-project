#include "rules_stateless.h"
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>   /* inet_ntop */
#include <netinet/in.h>  /* IPPROTO_* */
#include <netinet/tcp.h> /* TH_* דגלי TCP */

static void print_alert(const ParsedPacket *pp, const Configuration *cfg, const char *rule, const char *severity)
{
    FILE *out = (cfg && cfg->alerts_file) ? cfg->alerts_file : stdout;

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pp->l3.ip_src, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &pp->l3.ip_dst, dst_str, sizeof(dst_str));

    fprintf(out,
            "%ld.%06ld,%s,%s,%u,%u,%u,%s,%s\n",
            pp->hdr.ts_sec, pp->hdr.ts_usec,
            src_str, dst_str,
            pp->l3.proto,
            (unsigned)pp->l4.src_port,
            (unsigned)pp->l4.dst_port,
            rule,
            severity);

    fflush(out);
}

void eval_stateless_rules(const ParsedPacket *pp, const Configuration *cfg)
{
    if (pp->l3_proto != L3_IPV4)
        return;
    if (pp->l3.proto != IPPROTO_TCP)
        return;

    uint8_t f = pp->l4.tcp_flags;

    if ((f & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG))
    {
        print_alert(pp, cfg, "TCP_XMAS", "WARN");
    }
    else if ((f & TH_FIN) && !(f & (TH_SYN | TH_ACK)))
    {
        print_alert(pp, cfg, "TCP_FIN", "WARN");
    }
    else if (f == 0)
    {
        print_alert(pp, cfg, "TCP_NULL", "INFO");
    }
}
