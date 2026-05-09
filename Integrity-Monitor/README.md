# Cyber-Toolbox-c
A modular suite of cybersecurity tools written in C.

## Modules
### 1. Integrity Monitor
- **File:** `Integrity-Monitor/fast_scanner_lpthread.c`
- **Logic:** Uses `pthread` for multi-threaded file system monitoring.
- **Function:** Detects unauthorized modifications to sensitive files using `stat` system calls.
