package com.networktracker.net

import com.sun.jna.Memory
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.util.concurrent.TimeUnit

data class WifiInfo(
    val ssid: String?,
    val bssid: String?,
    val signalPercent: Int?,
    val channel: String?,
    val band: String?,
    val radioType: String?,
    val receiveMbps: Double?,
    val transmitMbps: Double?,
    val state: String?,
    val description: String?,
) {
    /** Approximate RSSI; Windows maps -100 dBm..-50 dBm linearly onto 0..100 %. */
    val approxDbm: Int? get() = signalPercent?.let { it / 2 - 100 }
}

data class AdapterInfo(
    val name: String,
    val displayName: String,
    val localAddress: String,
    val prefixLength: Int?,
    val mac: String?,
    val mtu: Int?,
    val isWireless: Boolean,
)

object NetInfo {

    /** IPv4 default gateway (next hop for Internet traffic), or null if none. */
    fun defaultGateway(): String? = runCatching {
        if (Platform.isWindows()) windowsGateway() else unixGateway()
    }.getOrNull()

    private fun windowsGateway(): String? {
        val api = IpHlpApi.INSTANCE
        val row = Memory(64).apply { clear() }
        val dest = InetAddress.getByName("8.8.8.8") as Inet4Address
        if (api.GetBestRoute(IpHlpApi.toIpAddr(dest), 0, row) != 0) return routePrintGateway()
        val nextHop = row.getInt(12) // MIB_IPFORWARDROW.dwForwardNextHop
        return if (nextHop == 0) null else IpHlpApi.fromIpAddr(nextHop)
    }

    private fun routePrintGateway(): String? {
        val out = run("route", "print", "-4", "0.0.0.0") ?: return null
        return out.lines().map { it.trim().split(Regex("\\s+")) }
            .filter { it.size >= 5 && it[0] == "0.0.0.0" && it[1] == "0.0.0.0" }
            .minByOrNull { it[4].toIntOrNull() ?: Int.MAX_VALUE }?.get(2)
    }

    private fun unixGateway(): String? {
        if (Platform.isMac()) {
            val out = run("route", "-n", "get", "default") ?: return null
            return Regex("""gateway:\s*(\S+)""").find(out)?.groupValues?.get(1)
        }
        val out = run("ip", "-4", "route", "show", "default") ?: return null
        return Regex("""default via (\S+)""").find(out)?.groupValues?.get(1)
    }

    /** DNS servers configured on this machine. */
    fun dnsServers(): List<String> = runCatching {
        if (Platform.isWindows()) windowsDnsServers()
        else java.io.File("/etc/resolv.conf").readLines()
            .mapNotNull { Regex("""^\s*nameserver\s+(\S+)""").find(it)?.groupValues?.get(1) }
    }.getOrDefault(emptyList()).distinct()

    private fun windowsDnsServers(): List<String> {
        val api = IpHlpApi.INSTANCE
        val size = IntByReference(0)
        api.GetNetworkParams(null, size)
        if (size.value <= 0) return emptyList()
        val buf = Memory(size.value.toLong())
        if (api.GetNetworkParams(buf, size) != 0) return emptyList()
        // FIXED_INFO: HostName[132], DomainName[132], CurrentDnsServer*, DnsServerList (IP_ADDR_STRING)
        val ptr = com.sun.jna.Native.POINTER_SIZE.toLong()
        val listOffset = align(264L, ptr) + ptr
        val result = mutableListOf<String>()
        var node: Pointer? = buf.share(listOffset)
        var guard = 0
        while (node != null && guard++ < 16) {
            val ip = node.getString(ptr, "US-ASCII").trim()
            if (ip.isNotEmpty() && ip != "0.0.0.0") result += ip
            node = node.getPointer(0)
        }
        return result
    }

    private fun align(v: Long, a: Long) = (v + a - 1) / a * a

    /** The adapter used to reach the Internet (determined without sending any traffic). */
    fun primaryAdapter(wifi: WifiInfo? = null): AdapterInfo? = runCatching {
        val local = DatagramSocket().use { s ->
            s.connect(InetSocketAddress("8.8.8.8", 53))
            s.localAddress
        }
        if (local.isAnyLocalAddress) return null
        val nif = NetworkInterface.getByInetAddress(local) ?: return null
        val ifAddr = nif.interfaceAddresses.firstOrNull { it.address == local }
        val display = nif.displayName ?: nif.name
        val wireless = Regex("wi-?fi|wireless|wlan|802\\.11", RegexOption.IGNORE_CASE).containsMatchIn(display) ||
            (wifi?.description != null && display.contains(wifi.description, ignoreCase = true))
        AdapterInfo(
            name = nif.name,
            displayName = display,
            localAddress = local.hostAddress,
            prefixLength = ifAddr?.networkPrefixLength?.toInt(),
            mac = nif.hardwareAddress?.joinToString(":") { "%02X".format(it) },
            mtu = runCatching { nif.mtu }.getOrNull(),
            isWireless = wireless,
        )
    }.getOrNull()

    /** Wi-Fi link details (Windows only, via `netsh`). Null when not on Wi-Fi. */
    fun wifi(): WifiInfo? {
        if (!Platform.isWindows()) return null
        val out = run("netsh", "wlan", "show", "interfaces") ?: return null
        val map = LinkedHashMap<String, String>()
        for (line in out.lines()) {
            val idx = line.indexOf(" : ").takeIf { it > 0 } ?: continue
            val key = line.substring(0, idx).trim().lowercase()
            if (key !in map) map[key] = line.substring(idx + 3).trim()
        }
        fun find(vararg keys: String) = keys.firstNotNullOfOrNull { map[it] }
        val state = find("state")
        val signal = find("signal")?.filter { it.isDigit() }?.toIntOrNull()
        if (signal == null && state?.contains("connected", true) != true) return null
        if (state != null && state.contains("disconnected", true)) return null
        return WifiInfo(
            ssid = find("ssid"),
            bssid = find("bssid", "ap bssid"),
            signalPercent = signal,
            channel = find("channel"),
            band = find("band"),
            radioType = find("radio type"),
            receiveMbps = find("receive rate (mbps)")?.replace(',', '.')?.toDoubleOrNull(),
            transmitMbps = find("transmit rate (mbps)")?.replace(',', '.')?.toDoubleOrNull(),
            state = state,
            description = find("description"),
        )
    }

    /**
     * True for home-network style addresses (RFC 1918, loopback, link-local). Carrier-grade NAT
     * (100.64.0.0/10) is only included when [includeCgnat] is set, since those addresses belong to the ISP.
     */
    fun isPrivate(ip: String, includeCgnat: Boolean = true): Boolean {
        val addr = runCatching { InetAddress.getByName(ip) }.getOrNull() ?: return false
        if (addr.isSiteLocalAddress || addr.isLoopbackAddress || addr.isLinkLocalAddress) return true
        if (!includeCgnat) return false
        val b = addr.address
        // 100.64.0.0/10 carrier-grade NAT
        return b.size == 4 && (b[0].toInt() and 0xFF) == 100 && (b[1].toInt() and 0xC0) == 64
    }

    private fun run(vararg cmd: String): String? = runCatching {
        val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
        val text = p.inputStream.bufferedReader().readText()
        p.waitFor(5, TimeUnit.SECONDS)
        text
    }.getOrNull()
}
