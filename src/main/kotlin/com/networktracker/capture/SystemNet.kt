package com.networktracker.capture

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.Tlhelp32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.ptr.IntByReference
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.TimeUnit

@Suppress("FunctionName")
private interface IpHelper : Library {
    fun GetExtendedTcpTable(table: Pointer?, size: IntByReference, order: Boolean, af: Int, tableClass: Int, reserved: Int): Int
    fun GetExtendedUdpTable(table: Pointer?, size: IntByReference, order: Boolean, af: Int, tableClass: Int, reserved: Int): Int
    fun GetIpNetTable(table: Pointer?, size: IntByReference, order: Boolean): Int
    fun GetIfEntry(row: Pointer): Int
    fun GetBestInterface(destAddr: Int, bestIfIndex: IntByReference): Int

    companion object {
        val INSTANCE: IpHelper by lazy { Native.load("Iphlpapi", IpHelper::class.java) }
    }
}

enum class TcpState(val label: String) {
    CLOSED("Closed"), LISTEN("Listening"), SYN_SENT("Connecting"), SYN_RCVD("Syn received"),
    ESTABLISHED("Established"), FIN_WAIT1("Closing"), FIN_WAIT2("Closing"), CLOSE_WAIT("Close wait"),
    CLOSING("Closing"), LAST_ACK("Last ack"), TIME_WAIT("Time wait"), DELETE_TCB("Deleted"), NONE("—");

    companion object {
        fun of(v: Int) = entries.getOrElse(v - 1) { NONE }
    }
}

/** A socket from the OS connection table, with the process that owns it. */
data class SocketEntry(
    val protocol: String,      // "TCP" or "UDP"
    val localAddress: String,
    val localPort: Int,
    val remoteAddress: String?,
    val remotePort: Int,
    val state: TcpState,
    val pid: Int,
) {
    val key get() = "$protocol|$localAddress|$localPort|$remoteAddress|$remotePort"
    val isListening get() = state == TcpState.LISTEN || (protocol == "UDP")
}

data class ArpEntry(val ip: String, val mac: String, val dynamic: Boolean)

data class IfCounters(val inOctets: Long, val outOctets: Long, val inErrors: Long, val outErrors: Long,
                      val inDiscards: Long, val outDiscards: Long, val speedBps: Long)

/**
 * Operating-system network information that needs no capture driver: sockets per process,
 * process names, the ARP neighbour table, interface counters, and the DNS client cache.
 */
object SystemNet {
    private val windows = Platform.isWindows()

    fun sockets(): List<SocketEntry> = if (!windows) emptyList() else runCatching {
        tcp4() + tcp6() + udp4() + udp6()
    }.getOrDefault(emptyList())

    private fun fetch(call: (Pointer?, IntByReference) -> Int): Memory? {
        val size = IntByReference(0)
        call(null, size)
        repeat(3) {
            if (size.value <= 0) return null
            val m = Memory(size.value.toLong() + 4096)
            size.value = m.size().toInt()
            if (call(m, size) == 0) return m
        }
        return null
    }

    private fun port(v: Int) = ((v and 0xFF) shl 8) or ((v shr 8) and 0xFF)
    private fun ip4(v: Int) = InetAddress.getByAddress(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()).hostAddress
    private fun ip6(m: Pointer, off: Long) = InetAddress.getByAddress(m.getByteArray(off, 16)).hostAddress.let(::compactV6)

    private fun tcp4(): List<SocketEntry> {
        val m = fetch { p, s -> IpHelper.INSTANCE.GetExtendedTcpTable(p, s, true, 2, 5, 0) } ?: return emptyList()
        val n = m.getInt(0)
        return (0 until n).map { i ->
            val o = 4L + i * 24
            SocketEntry("TCP", ip4(m.getInt(o + 4)), port(m.getInt(o + 8)), ip4(m.getInt(o + 12)), port(m.getInt(o + 16)),
                TcpState.of(m.getInt(o)), m.getInt(o + 20))
        }
    }

    private fun tcp6(): List<SocketEntry> {
        val m = fetch { p, s -> IpHelper.INSTANCE.GetExtendedTcpTable(p, s, true, 23, 5, 0) } ?: return emptyList()
        val n = m.getInt(0)
        return (0 until n).map { i ->
            val o = 4L + i * 56
            SocketEntry("TCP", ip6(m, o), port(m.getInt(o + 20)), ip6(m, o + 24), port(m.getInt(o + 44)),
                TcpState.of(m.getInt(o + 48)), m.getInt(o + 52))
        }
    }

    private fun udp4(): List<SocketEntry> {
        val m = fetch { p, s -> IpHelper.INSTANCE.GetExtendedUdpTable(p, s, true, 2, 1, 0) } ?: return emptyList()
        val n = m.getInt(0)
        return (0 until n).map { i ->
            val o = 4L + i * 12
            SocketEntry("UDP", ip4(m.getInt(o)), port(m.getInt(o + 4)), null, 0, TcpState.NONE, m.getInt(o + 8))
        }
    }

    private fun udp6(): List<SocketEntry> {
        val m = fetch { p, s -> IpHelper.INSTANCE.GetExtendedUdpTable(p, s, true, 23, 1, 0) } ?: return emptyList()
        val n = m.getInt(0)
        return (0 until n).map { i ->
            val o = 4L + i * 28
            SocketEntry("UDP", ip6(m, o), port(m.getInt(o + 20)), null, 0, TcpState.NONE, m.getInt(o + 24))
        }
    }

    /** PID → executable name for every running process (Toolhelp snapshot; no admin needed). */
    fun processNames(): Map<Int, String> {
        if (!windows) return ProcessHandle.allProcesses().toList().associate { p ->
            p.pid().toInt() to (p.info().command().orElse("").substringAfterLast('/').ifEmpty { "pid ${p.pid()}" })
        }
        val k = Kernel32.INSTANCE
        val snap = k.CreateToolhelp32Snapshot(Tlhelp32.TH32CS_SNAPPROCESS, WinDef.DWORD(0))
        val out = HashMap<Int, String>()
        try {
            val e = Tlhelp32.PROCESSENTRY32.ByReference()
            if (k.Process32First(snap, e)) do {
                out[e.th32ProcessID.toInt()] = Native.toString(e.szExeFile)
            } while (k.Process32Next(snap, e))
        } finally {
            k.CloseHandle(snap)
        }
        out[0] = "System Idle"
        out[4] = "System"
        return out
    }

    fun arpTable(): List<ArpEntry> {
        if (!windows) return emptyList()
        val m = fetch { p, s -> IpHelper.INSTANCE.GetIpNetTable(p, s, true) } ?: return emptyList()
        val n = m.getInt(0)
        return (0 until n).mapNotNull { i ->
            val o = 4L + i * 24
            val len = m.getInt(o + 4).coerceIn(0, 8)
            val type = m.getInt(o + 20)
            if (type == 2 || len == 0) return@mapNotNull null // invalid
            val mac = m.getByteArray(o + 8, len).joinToString(":") { "%02x".format(it) }
            if (mac == "00:00:00:00:00:00") null else ArpEntry(ip4(m.getInt(o + 16)), mac, type == 3)
        }
    }

    private var ifIndex: Int? = null

    /** Byte and error counters of the adapter that carries Internet traffic. */
    fun interfaceCounters(): IfCounters? {
        if (!windows) return null
        return runCatching {
            val idx = ifIndex ?: IntByReference().let { r ->
                val dest = InetAddress.getByName("8.8.8.8") as Inet4Address
                val v = ByteBuffer.wrap(dest.address).order(ByteOrder.LITTLE_ENDIAN).int
                if (IpHelper.INSTANCE.GetBestInterface(v, r) != 0) return null
                r.value.also { ifIndex = it }
            }
            val row = Memory(860).apply { clear() }
            row.setInt(512, idx)
            if (IpHelper.INSTANCE.GetIfEntry(row) != 0) { ifIndex = null; return null }
            fun u(o: Long) = row.getInt(o).toLong() and 0xFFFFFFFFL
            IfCounters(u(552), u(576), u(568), u(592), u(564), u(588), u(524))
        }.getOrNull()
    }

    fun resetInterface() { ifIndex = null }

    /** IP → host name pairs from the Windows DNS client cache (`ipconfig /displaydns`). */
    fun dnsCache(): List<Pair<String, String>> {
        if (!windows) return emptyList()
        val text = runCatching {
            val p = ProcessBuilder("ipconfig", "/displaydns").redirectErrorStream(true).start()
            val t = p.inputStream.bufferedReader().readText()
            p.waitFor(10, TimeUnit.SECONDS)
            t
        }.getOrNull() ?: return emptyList()
        val out = mutableListOf<Pair<String, String>>()
        var name: String? = null
        val ipRegex = Regex("""^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$""")
        val hostRegex = Regex("""^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+\.?$""")
        for (line in text.lines()) {
            val idx = line.indexOf(" : ").takeIf { it > 0 } ?: continue
            val value = line.substring(idx + 3).trim()
            when {
                ipRegex.matches(value) && name != null -> out += compactV6(value) to name
                hostRegex.matches(value) && !value.all { it.isDigit() || it == '.' } -> if (name == null || line.contains("Record Name", true) || line.contains("Eintragsname", true)) name = value.trimEnd('.')
            }
            if (line.isBlank()) name = null
        }
        return out
    }

    fun compactV6(s: String): String = if (!s.contains(':')) s else runCatching {
        // Normalise "0:0:0:0:0:0:0:1" to "::1" etc. (longest zero run → ::)
        val parts = s.substringBefore('%').split(':').let { p -> if (p.size == 8) p else return s.substringBefore('%') }
            .map { it.trimStart('0').ifEmpty { "0" } }
        var bestStart = -1; var bestLen = 0; var i = 0
        while (i < 8) {
            if (parts[i] == "0") {
                var j = i; while (j < 8 && parts[j] == "0") j++
                if (j - i > bestLen && j - i > 1) { bestStart = i; bestLen = j - i }
                i = j
            } else i++
        }
        if (bestStart < 0) parts.joinToString(":")
        else parts.subList(0, bestStart).joinToString(":") + "::" + parts.subList(bestStart + bestLen, 8).joinToString(":")
    }.getOrDefault(s)
}
