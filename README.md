## 📖 Overview

**cnginMasterHost** is an experimental HTTP/2 server built from scratch for educational purposes. It implements modern Linux kernel features like **kTLS** (Kernel TLS) and **io_uring** to explore high-performance networking concepts.

> **Disclaimer**: This is a learning project, not production-ready software. Built by an 18-year-old hobby programmer to understand the internals of web servers and Linux networking.

##  Features

### Core Protocols
- **HTTP/2** - Full frame parsing (HEADERS, DATA, SETTINGS, PING, GOAWAY, WINDOW_UPDATE)
- **HPACK** - Header compression implementation (static table, literal encoding)
- **kTLS** - Kernel-space TLS encryption (when available)
- **TCP Fast Open** - Reduced connection latency

### Performance Optimizations
- **io_uring** - Modern asynchronous I/O interface
- **SO_REUSEPORT** - Kernel-level load balancing across threads
- **Thread pinning** - Bind workers to specific CPU cores
- **Epoll edge-triggered** - Efficient event notification
- **TCP optimizations** - NODELAY, DEFER_ACCEPT, QUICKACK, large socket buffers

### Architecture
- Multi-threaded design with 8 worker threads
- Non-blocking I/O with epoll
- Connection pooling and stream management
- Real-time client IP capture and logging

## Technical Deep Dive

### What I Learned Building This

#### 1. **HTTP/2 Protocol Internals**
- Binary framing layer vs HTTP/1.1 text protocol
- Stream multiplexing and prioritization
- Flow control with WINDOW_UPDATE frames
- HPACK header compression algorithm
- Frame types and their purposes

#### 2. **Linux Kernel Networking**
- How kTLS moves encryption to kernel space (zero-copy!!)
- TCP ULP (Upper Layer Protocol) mechanism
- Socket options for performance tuning
- The magic of SO_REUSEPORT for multi-threading

#### 3. **Modern Linux I/O**
- io_uring vs old epoll model
- Submission/Completion queues
- Async operations without syscall overhead

## Getting Started

### Deps

```bash
# Linux kernel 5.1+ for io_uring
# Linux kernel 4.13+ for kTLS
# liburing development libraries

# On Ubuntu/Debian:
sudo apt-get update
sudo apt-get install liburing-dev gcc make

# On Arch (Like i did):
sudo pacman -S liburing gcc
