
#include "parser.h"
#include "config.h"

/* פרמטרים — תשאיר כברירת מחדל ותכוון אח"כ */
#define FLOW_WINDOW_SEC      60     /* גודל חלון בדיקה */
#define PORT_THRESHOLD       10     /* כמה פורטים שונים כדי לחשוד */
#define PACKET_THRESHOLD     10     /* כמה חבילות מינימום */
#define ALERT_COOLDOWN_SEC   120    /* לא להציף אלרטים מאותו מקור */

void stateful_init(void);
/* לקרוא פעם אחת בתחילת ריצה (לפני capture) */

void stateful_on_packet(const ParsedPacket* pp, const Configuration* cfg);
/* לקרוא על כל חבילה אחרי parse (אפשר לפני/אחרי stateless) */

void stateful_housekeeping(time_t now);
/* ניקוי רשומות ישנות; לקרוא מדי פעם (אופציונלי, למשל כל N חבילות) */
