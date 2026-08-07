# PinkProxy

A modern, fast, and robust local DPI-bypass tool for Android. PinkProxy uses advanced packet fragmentation, SNI mangling, and other heuristics to bypass Deep Packet Inspection systems locally on the device.

## Architecture

PinkProxy implements a full transparent proxying architecture using Android's `VpnService` and a high-performance `tun2socks` engine.
- **Traffic Capture:** `VpnService` captures all device traffic (IPv4 and IPv6) and routes it through a TUN interface.
- **Tun2Socks Engine:** The `engine.Engine` library (Go-based) converts TUN packets into SOCKS5 requests.
- **Local Bypass Server:** A custom SOCKS5-to-Target bridge (`PinkProxyServer.kt`) performs the actual DPI-bypass maneuvers (fragmentation, SNI splitting, etc.) on the outgoing TCP streams.
- **Robust DNS:** `RobustResolver.kt` provides multiple DNS-over-HTTPS (DoH) backends with automatic failover and warmup, preventing DNS hijacking and poisoning.
- **Autonomous Optimization:** `BypassConfig` monitors connection success rates and RTT to dynamically adjust bypass strategies (e.g., switching from SNI split to fake packets if censorship intensifies).

## Key Features

- **Transparent Proxying:** Works for all apps, not just those respecting system proxy settings.
- **Per-App Routing:** Allow or exclude specific applications from the VPN tunnel.
- **Dynamic Strategies:** Real-time adaptation to network conditions and censorship level.
- **Diagnostic Mode:** Detailed logging and recovery mechanisms for self-healing connections.
- **Edge-to-Edge Design:** Modern Material 3 interface with dark mode support.

## Permissions & Policy

- **Package Visibility**: Uses the `<queries>` element to list installed applications for the per-app routing feature, ensuring compatibility with modern Android privacy standards without requesting broad query permissions.
- **VPN Service**: Utilizes the standard Android `VpnService` API.
- **FOREGROUND_SERVICE_SPECIAL_USE**: Used to maintain the VPN connection reliably in the background, categorized under the "specialUse" type as per Android 14 requirements.
- **IPv6 Dual-Stack**: Full support for IPv6 traffic with dual-stack DNS resolution (A + AAAA parallel racing).
- **Fault Tolerance**: Comprehensive exception handling and diagnostic logging across all core components (TCP/UDP transports, DNS resolver, optimization engine).

## Compilation

Standard Gradle build. Ensure you have the `tun2socks` native library dependency in your `libs.versions.toml`.
