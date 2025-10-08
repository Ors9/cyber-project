#ifndef CONFIG_H
#define CONFIG_H

#include <pcap.h>


/* Capture configuration (tune as needed) */
#define NON_STOP_LOOP -1          /* Run until interrupted (Ctrl+C or pcap_breakloop) */
#define INTERNET_INTERFACE "eth0" /* Network interface to listen on */
#define SNAP_LEN 65535            /* Max bytes per packet to capture (entire frame) */
#define PROMISC 1                 /* 1 = promiscuous mode, 0 = non-promiscuous */
#define TIMEOUT_MS 1000           /* Read timeout for pcap in milliseconds */

/* Output modes for packet logging */
typedef enum LogMode
{
    LOGMODE_SUMMARY = 0, /* תקציר רגיל של כל חבילה (ברירת מחדל) */
    LOGMODE_EVENTS  = 1, /* להציג רק אירועים חשובים (פחות רעש) */
    LOGMODE_DEBUG   = 2,  /* פירוט מלא לצורכי ניפוי שגיאות */
    LOGMODE_CSV = 3
} LogMode;


/**
 * Configuration - carries user-defined state into the packet callback.
 * Fields:
 *   id    - Numeric identifier (example field).
 *   title - Human-readable label (example field).
 *
 * Note:
 *   This struct is passed via the 'user' pointer of pcap_loop()
 *   so the callback can access global/runtime configuration without globals.
 */
typedef struct
{
    LogMode logmode;
    int id;
    FILE * file;
    FILE *alerts_file;
    char title[255];
} Configuration;

#endif /* CONFIG_H */
