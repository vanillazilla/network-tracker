# Network Tracker

A desktop tool (Kotlin + Swing/FlatLaf) that monitors your connection and works out **where** a
problem is: this PC's link to the router, the router itself, the router's connection to your ISP,
the wider Internet, DNS, or the remote host you're trying to reach.

## Run

Requires a JDK (built and tested with Java 25). No admin rights needed.

```bash
./gradlew run
```

Or build a single runnable jar:

```bash
./gradlew fatJar
java --enable-native-access=ALL-UNNAMED -jar build/libs/network-tracker-1.0.0-all.jar
```

## How it works

On start it auto-detects your **default gateway** (router), the **ISP edge router** (first router
beyond your network that answers ping, found by traceroute), your **DNS server**, and uses
**1.1.1.1** and **8.8.8.8** as Internet anchors. Add any IP or hostname in the toolbar to monitor it too.

Every round, all targets are probed **at the same moment**. That's the key to attribution:

| Router | ISP edge | Internet | Your target | Conclusion |
|---|---|---|---|---|
| lost | lost | lost | lost | Local: Wi-Fi/cable between PC and router, or the router |
| ok | lost | lost | lost | Router ↔ ISP: modem, line, or ISP equipment |
| ok | ok | lost | lost | ISP network / upstream |
| ok | ok | ok | lost | The remote host or its network |

The same comparison is applied to latency spikes, and the Events log attributes each outage and
spike to where it started.

## Features

- **Dashboard**: path health (PC → Router → ISP → Internet → DNS → Targets), live latency chart,
  loss/latency timeline (red that lines up vertically shows where a drop started), per-target
  statistics (loss, min/avg/max, jitter) and a plain-English diagnosis with suggested fixes.
- **Traceroute**: continuous MTR-style trace with per-hop loss/latency and automatic analysis that
  ignores harmless ICMP rate-limiting at intermediate hops.
- **Events**: outages, recoveries, latency spikes, Wi-Fi roaming and weak-signal warnings.
- **Network Info**: adapter, gateway, DNS, and Wi-Fi details (signal, band, channel, link rate)
  with signal history.
- **Traffic**: see what's happening on your network.
  - *Packets*: live packet list with a plain-English explanation of each packet, a full
    field-by-field decode (Ethernet, ARP, IPv4/6, ICMP, TCP, UDP, DNS/mDNS/LLMNR, DHCP, TLS with
    site names, QUIC, HTTP, SSDP, NTP, STUN, NetBIOS, LLDP…) and a hex view that highlights the
    selected field. TCP analysis flags retransmissions, lost segments, duplicate ACKs, resets and
    zero windows.
  - *Conversations*, *Applications* (traffic per program), *Devices* (what's on your LAN),
    *Protocols* (hierarchy breakdown), and *Connections* (every open socket and its program).
  - Filter with plain words or `proto:dns app:chrome host:google port:443 dir:out len>1000 problems`,
    right-click anything to filter by it, follow a stream, and open/save `.pcap` files for Wireshark.
  - Packet capture needs [Npcap](https://npcap.com) on Windows (free; install with default
    options). Connections, bandwidth and opening capture files work without it.
- **Export**: text diagnostic report (to send to your ISP) and raw CSV of every measurement.
- Light/dark theme; settings and custom targets are remembered.

On Windows, pings use the native ICMP API (via JNA) for precise timing and TTL control. Other
platforms fall back to the system `ping` command. DNS is tested with raw queries sent straight to the
server, which bypasses the OS cache.

## Privacy

Everything stays on your machine. The app sends no telemetry, and only contacts the hosts it
monitors (your router, ISP edge, DNS server, 1.1.1.1, 8.8.8.8 and targets you add); the Traffic tab
also does reverse-DNS lookups to show host names. Exported reports, CSVs and especially saved
`.pcap` captures contain your network details and traffic, so review them before sharing.

## License

[MIT](LICENSE)
