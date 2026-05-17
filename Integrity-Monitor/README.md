# Cyber-Toolbox-c: Host-Security Suite

An automated Host-Based Intrusion Detection System (HIDS) utility written in C. This security suite automates file system auditing by combining cryptographic integrity verification with multi-threaded directory traversal and persistent, tamper-resistant forensics.

## Core Architecture

The suite consists of three tightly coupled modules orchestrated via an automated build configuration:

1. **The Sentinel (`sentinel.c`)**: A state-based file integrity monitor. It captures an initial baseline of a critical file (Size, Modification Time, and SHA-256 Hash) and flags multi-factor mismatches during subsequent audits.
2. **Directory Auditor (`dir_auditor.c`)**: Leverages `<dirent.h>` and `<sys/stat.h>` to map and inspect hidden, system, and regular files across targeted directories.
3. **Fast Scanner (`fast_scanner.c`)**: A multi-threaded engine optimized using POSIX threads (`pthread`) for concurrent, low-latency system exploration.

## Security Hardening Features

* **Forensic Persistence**: Execution results and high-priority cryptographic mismatch alerts are streamed to an isolated append-only file ledger (`sentinel.log`).
* **Defense Evasion Resistance**: Hardened against administrative or malicious deletion using file system attribute masking (`chattr +a`).

---

## Deployment & Build Automation

Compilation and linking are fully automated via the included `Makefile`. Dependencies include `libssl-dev` for cryptographic hashing and the POSIX thread library.

### 1. Environment Setup
```bash
sudo apt-get update
sudo apt-get install gcc make libssl-dev

