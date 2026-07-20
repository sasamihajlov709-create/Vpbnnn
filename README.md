# PinkProxy

A modern, fast, and robust local DPI-bypass tool for Android. PinkProxy uses advanced packet fragmentation, SNI mangling, and other heuristics to bypass Deep Packet Inspection systems locally on the device, without relying on external proxy servers for the connection itself.

## Architecture

PinkProxy uses Android's `VpnService` to capture traffic. Rather than a full `tun2socks` implementation, it uses the `setHttpProxy` feature of `VpnService` to direct HTTP/HTTPS traffic to a local proxy server running on the device.
- **Core bypass logic:** Implemented in `PinkProxyServer.kt`, which mangles traffic according to dynamic strategies.
- **Local DNS over HTTPS (DoH):** Provided by `RobustResolver.kt`, which ensures DNS queries cannot be hijacked.
- **Service Checking:** `ServiceChecker.kt` proactively monitors the health of the connection.

## Current Limitations

- **Proxy-Based Approach**: Since the bypass relies on `setHttpProxy`, only apps and protocols that respect system proxies (mostly HTTP/HTTPS) are supported. Native apps ignoring the proxy, QUIC, and non-HTTP UDP traffic will either fall back to normal routing or drop depending on the network stack configuration.
- **Boot Startup Restrictions**: On Android 12+, attempting to autostart the VPN service on boot may fail if the system restricts foreground service starts from the background. The user may need to manually launch the app.
- **Permissions**: The app uses `QUERY_ALL_PACKAGES` to allow users to select which apps should bypass the VPN. If publishing to Google Play, this permission requires proper declaration and policy compliance.

## Compilation

Standard `./gradlew assembleDebug` is supported if Gradle wrapper is present, otherwise use your preferred IDE or CI to build the project.
