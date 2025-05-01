## 🔒 Dynamic TCP Packet Dropper using Rust & eBPF

This project demonstrates how to **persistently monitor and dynamically block TCP traffic** using [eBPF](https://ebpf.io/) and [Rust](https://www.rust-lang.org/). It is designed to intercept packets at the kernel level (via XDP) and drop those targeting specific ports or IP addresses. The system reads allowed or blocked IPs/ports from files at runtime and logs events in `application.log`.

---

## ⚖️ Comparison: eBPF vs Traditional Tools like iptables

| Feature                      | Traditional (iptables)                 | This Project (eBPF + Rust)                     |
|-----------------------------|----------------------------------------|------------------------------------------------|
| **Performance**             | Context switches to/from kernel space | Runs entirely in kernel with XDP (high-speed)  |
| **Dynamic Rules**           | Manual updates, less automation       | Reads updated rules from files at runtime      |
| **Flexibility**             | Static rules                           | Fully programmable in Rust                     |
| **Logging**                 | Limited                                | Custom logs in `application.log`               |
| **Deployment**              | System-wide (may affect all apps)     | Dockerized, scoped to container if needed      |
| **Extensibility**           | Low                                    | High – written in Rust and extendable          |

---

## 🧰 Features
  
✅ Dynamically **blocks IPs and ports from files** `ipblock` and `portblock`  
✅ Logs every block event into `application.log`  
✅ Persistent monitoring through XDP (eBPF hook)  
✅ Modular design: kernel (eBPF) + user space (Rust CLI)  
✅ Dockerized for easy deployment

---

## 🏗️ Architecture Overview

```
+------------------------+         ipblock / portblock
| Rust Userspace Program| <-----------------------------+
|                        |                               |
| - Monitors files       |                               |
| - Logs activity        |                               |
| - Controls eBPF logic  |                               |
+-----------+------------+                               |
            |                                            |
            v                                            |
+------------------------+         +---------------------+
|    eBPF Kernel Program | <------ |  Network Interface  |
| (attached via XDP hook)|         +---------------------+
| - Parses packet headers|
| - Drops packet on match|
+------------------------+
```

---

## 📦 Prerequisites

```bash
rustup install stable
rustup install nightly
cargo install bpf-linker
```

> ⚠️ Linux kernel 5.x+ required for eBPF and XDP support.

---

## 🐳 Dockerized Environment

```bash
docker pull rmg0070/dynamictcppacketdropper
sudo docker run --privileged -it -p 80:80 --name ebpf rmg0070/dynamictcppacketdropper:v4 /bin/bash
```

---

## ▶️ Running the Application

Inside the Docker container:

```bash
# Start nginx server for traffic testing
service nginx start

# Build eBPF and user space components
cargo task build-ebpf
cargo build

# Run the app (starts monitoring)
cargo task run
```

The application will now continuously monitor:

- `ipblock` — list of IPs to block
- `portblock` — list of ports to block

Any matching TCP packets will be dropped in real-time, and events will be logged to `application.log`.

---

## 📂 File Format Examples

### `ipblock` file
```
192.168.1.100
10.0.0.55
```

### `portblock` file
```
80
443
```

---

## 🧪 Runtime CLI Commands

| Command               | Description                         | Example                     |
|----------------------|-------------------------------------|-----------------------------|
| `blockip <IP>`       | Dynamically block an IP             | `blockip 192.168.1.10`      |
| `unblockip <IP>`     | Remove a blocked IP                 | `unblockip 192.168.1.10`    |
| `blockport <PORT>`   | Block TCP traffic on a port         | `blockport 8080`            |
| `unblockport <PORT>` | Unblock TCP traffic on a port       | `unblockport 8080`          |
| `exit`               | Terminate the application           |                             |

All changes are **reflected immediately** and logged.

---

## 📜 Logs

Every block/unblock action and dropped packet is logged in:

```bash
application.log
```

Useful for monitoring, auditing, or debugging purposes.

---

## 🛠️ Development & Testing

```bash
# Build eBPF code
cargo task build-ebpf

# Build user-space controller
cargo build

# Run full stack (controller + eBPF)
cargo task run

# Unit tests
cargo test

# Fuzz tests
cargo fuzz run filter_ip_port
```

---

## 📎 Summary

This project is a modern, **eBPF-powered packet filtering engine** that replaces legacy approaches (like iptables) with:

- **Lower latency**
- **Better observability**
- **Runtime configurability**
- **Containerized isolation**

Ideal for **firewalling, security research, or network-level observability** – all using safe and modern Rust.
