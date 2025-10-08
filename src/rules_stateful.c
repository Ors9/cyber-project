// rules_stateful.c
#include "rules_stateful.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>  // IPPROTO_*

/* --- פרמטרים פנימיים (אפשר לכוונן) --- */
#define MAX_FLOWS           4096
#define MAX_PORTS_TRACKED    128     /* כמה פורטים ייחודיים נשמור לכל מקור */
#define FLOW_EXPIRE_SEC      300     /* למחיקת רשומה לא פעילה (housekeeping) */

/* ----- רשומת stateful בסיסית לכל מקור (src_ip) ----- */
typedef struct {
    uint32_t src_ip;                  /* host-order (ntohl) ; 0 = פנוי */
    time_t   first_seen;              /* תחילת חלון הפעילות הנוכחי */
    time_t   last_seen;               /* חבילה אחרונה שנראתה */
    time_t   last_alert_time;         /* למניעת הצפה (cooldown) */
    uint32_t total_packets;           /* חבילות שנצברו בחלון */
    uint16_t unique_ports;            /* כמה פורטי יעד שונים */
    uint16_t ports[MAX_PORTS_TRACKED];/* רשימת פורטי יעד שנצפו (למניעת כפילויות) */
} FlowEntry;

static FlowEntry g_flows[MAX_FLOWS];

/* ========================= Utilities ========================= */

static inline void reset_window(FlowEntry *e, time_t now) {
    e->first_seen    = now;
    e->last_seen     = now;
    e->total_packets = 0;
    e->unique_ports  = 0;
    memset(e->ports, 0, sizeof(e->ports));
}

static FlowEntry* find_flow(uint32_t src_host_order) {
    for (int i = 0; i < MAX_FLOWS; ++i) {
        if (g_flows[i].src_ip == src_host_order)
            return &g_flows[i];
    }
    return NULL;
}

static FlowEntry* create_flow(uint32_t src_host_order, time_t now) {
    for (int i = 0; i < MAX_FLOWS; ++i) {
        if (g_flows[i].src_ip == 0) {
            g_flows[i].src_ip = src_host_order;
            g_flows[i].last_alert_time = 0;
            reset_window(&g_flows[i], now);
            return &g_flows[i];
        }
    }
    return NULL; /* טבלה מלאה – ל-MVP פשוט מתעלמים */
}

static int port_seen(const FlowEntry *e, uint16_t port) {
    for (int i = 0; i < e->unique_ports; ++i) {
        if (e->ports[i] == port) return 1;
    }
    return 0;
}

static void add_port_if_new(FlowEntry *e, uint16_t port) {
    if (port == 0) return; /* לא עוזר לנו לייחודיות */
    if (port_seen(e, port)) return;
    if (e->unique_ports < MAX_PORTS_TRACKED) {
        e->ports[e->unique_ports++] = port;
    }
}

/* פלט ALERT ל־packets_with_alert.csv (אותו פורמט כמו ה-Stateless: מוסיף severity) */
static void emit_portscan_alert(const ParsedPacket *pp, const Configuration *cfg,
                                const FlowEntry *fe) {
    FILE *out = (cfg && cfg->alerts_file) ? cfg->alerts_file : stdout;

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pp->l3.ip_src, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &pp->l3.ip_dst, dst_str, sizeof(dst_str));

    /* שמרנו תאימות ל־7 העמודות הראשונות, ואז rule,severity */
    fprintf(out,
            "%ld.%06ld,%s,%s,%u,%u,%u,%s,%s\n",
            pp->hdr.ts_sec, pp->hdr.ts_usec,
            src_str, dst_str,
            pp->l3.proto,
            (unsigned)pp->l4.src_port,
            (unsigned)pp->l4.dst_port,
            "PORT_SCAN_SUSPECT",
            "ALERT");
    fflush(out);

    (void)fe; /* כרגע לא מדפיסים counters; אפשר להוסיף בהמשך לעמודות נוספות */
}

/* ========================= API ========================= */

void stateful_init(void) {
    memset(g_flows, 0, sizeof(g_flows));
}

void stateful_on_packet(const ParsedPacket* pp, const Configuration* cfg) {
    if (!pp) return;

    /* מסתכלים רק על IPv4 ועל TCP/UDP/ICMP (לפי מה שסיכמנו) */
    if (pp->l3_proto != L3_IPV4) return;
    if (pp->l3.proto != IPPROTO_TCP && pp->l3.proto != IPPROTO_UDP && pp->l3.proto != IPPROTO_ICMP)
        return;

    time_t  now = (time_t)pp->hdr.ts_sec;
    uint32_t src = ntohl(pp->l3.ip_src.s_addr);
    uint16_t dport = pp->l4.dst_port;

    FlowEntry *e = find_flow(src);
    if (!e) {
        e = create_flow(src, now);
        if (!e) return; /* אין מקום – ל-MVP פשוט נוותר */
    }

    /* חלון זמן (מחזיקים 60 שניות עדכניים) */
    if ((now - e->first_seen) > FLOW_WINDOW_SEC) {
        reset_window(e, now);
    }

    /* עדכוני מונים */
    e->total_packets++;
    add_port_if_new(e, dport);
    e->last_seen = now;

    /* בדיקת ספים בתוך החלון + cooldown */
    if (e->total_packets >= PACKET_THRESHOLD && e->unique_ports >= PORT_THRESHOLD) {
        if ((now - e->last_alert_time) >= ALERT_COOLDOWN_SEC) {
            emit_portscan_alert(pp, cfg, e);
            e->last_alert_time = now;

            /* כדי לא להציף מחדש מיד – פותחים חלון חדש */
            reset_window(e, now);
        }
    }
}

void stateful_housekeeping(time_t now) {
    for (int i = 0; i < MAX_FLOWS; ++i) {
        if (g_flows[i].src_ip == 0) continue;
        if ((now - g_flows[i].last_seen) > FLOW_EXPIRE_SEC) {
            /* שחרור הרשומה: סימון כ-"פנויה" */
            g_flows[i].src_ip = 0;
            /* שאר השדות כבר לא מעניינים; אפשר לאפס למען הסדר */
            g_flows[i].first_seen = g_flows[i].last_seen = g_flows[i].last_alert_time = 0;
            g_flows[i].total_packets = 0;
            g_flows[i].unique_ports  = 0;
            memset(g_flows[i].ports, 0, sizeof(g_flows[i].ports));
        }
    }
}
