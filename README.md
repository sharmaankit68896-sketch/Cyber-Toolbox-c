# Cyber-Toolbox-C 🛡️
A professional collection of networking and security tools written in C.

## 🚀 Tools Included
1. **Pinger.c**: An ICMP-based connectivity tester. It uses system-level integration to verify if a target host is active.
2. **Scanner.c**: A TCP Port Scanner. It bridges C with PowerShell's `Test-NetConnection` to audit open services on a target IP.

## 🛠️ How to Compile
Use `gcc` (GNU Compiler Collection):
```bash
gcc pinger.c -o pinger
gcc scanner.c -o scanner

