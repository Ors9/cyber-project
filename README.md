# Lightweight IDS — libpcap + C

**Lightweight Intrusion Detection System** implemented in C.  
Capture live traffic with `libpcap`, parse Ethernet/IPv4/TCP/UDP/ICMP, apply simple stateless rules and a compact stateful flow detector (port-scan). Logs alerts and parsed packets to CSV for easy inspection and integration.

---

## Project goals
- Small, educational IDS demonstrating core concepts:
  - live packet capture (libpcap)
  - packet parsing (L2 → L3 → L4)
  - stateless signature rules (per-packet)
  - stateful flow-based detection (sliding window)
  - CSV logging for both traffic and alerts
- Clean, modular code suitable for interview/demo and incremental extension.

---

## Usement Examples:
TCP_FIN example:
<img width="865" height="507" alt="image" src="https://github.com/user-attachments/assets/0d53d64e-3153-4da8-be63-dd1a3a4d5f63" />
Xmax Packet:
<img width="865" height="507" alt="image" src="https://github.com/user-attachments/assets/b27ae845-8c02-4c37-b821-745936e4f706" />
Null Packet:
<img width="865" height="511" alt="image" src="https://github.com/user-attachments/assets/70ff978b-096b-447b-a8d8-d38fe6409970" />
Port Scan Suspect:
<img width="1393" height="831" alt="image" src="https://github.com/user-attachments/assets/4d99a1d7-47a9-493a-9aaf-c1aff586f708" />

Regular Packets without any suspicios:
<img width="2839" height="1693" alt="image" src="https://github.com/user-attachments/assets/a0e1b594-6711-4340-980c-684473b59ed9" />

