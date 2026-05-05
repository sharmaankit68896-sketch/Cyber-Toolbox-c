## 🚀 High-Performance Port Auditing (v2.0)
The scanner has been upgraded from a linear execution model to a multi-threaded architecture.

### Features:
- **Parallel Execution:** Utilizes `pthread.h` to launch multiple concurrent scanning threads.
- **Dynamic Memory:** Implements `malloc` and `free` for thread-safe argument passing.
- **Mutex Implementation:** Uses `pthread_mutex_t` to prevent race conditions during console output.
- **WSL2 Compatibility:** Configured for internal loopback auditing ($127.0.0.1$) within Linux subsystems.

### Technical Breakthrough:
Managed to bridge the Windows-to-Linux virtual network gap by implementing local listener/scanner synchronization.
