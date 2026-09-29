package com.networktracker.capture

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Minimal JNA bindings for libpcap / Npcap's wpcap.dll. */
@Suppress("FunctionName")
internal interface PcapLib : Library {
    fun pcap_findalldevs(alldevs: PointerByReference, errbuf: ByteArray): Int
    fun pcap_freealldevs(alldevs: Pointer)
    fun pcap_open_live(device: String, snaplen: Int, promisc: Int, toMs: Int, errbuf: ByteArray): Pointer?
    fun pcap_next_ex(p: Pointer, header: PointerByReference, data: PointerByReference): Int
    fun pcap_datalink(p: Pointer): Int
    fun pcap_compile(p: Pointer, program: Pointer, filter: String, optimize: Int, netmask: Int): Int
    fun pcap_setfilter(p: Pointer, program: Pointer): Int
    fun pcap_freecode(program: Pointer)
    fun pcap_geterr(p: Pointer): String?
    fun pcap_stats(p: Pointer, stats: Pointer): Int
    fun pcap_breakloop(p: Pointer)
    fun pcap_close(p: Pointer)
    fun pcap_lib_version(): String
}

data class CaptureDevice(
    val name: String,
    val description: String,
    val addresses: List<String>,
    val loopback: Boolean,
) {
    override fun toString(): String {
        val addr = addresses.firstOrNull { !it.contains(':') } ?: addresses.firstOrNull()
        return description.ifBlank { name } + (addr?.let { "  —  $it" } ?: "")
    }
}

/** One raw frame straight from the driver. */
class RawPacket(val timeMicros: Long, val data: ByteArray, val originalLength: Int)

object Pcap {
    const val DLT_NULL = 0
    const val DLT_EN10MB = 1
    const val DLT_RAW = 12
    const val DLT_RAW_ALT = 101
    const val DLT_LINUX_SLL = 113
    const val DLT_IPV4 = 228
    const val DLT_IPV6 = 229

    private var loaded = false
    private var libCache: PcapLib? = null
    private val lib: PcapLib? get() {
        if (!loaded) { libCache = load(); loaded = true }
        return libCache
    }
    var loadError: String? = null; private set

    /** Try loading the capture library again (e.g. after the user installed Npcap). */
    fun reload(): Boolean {
        if (libCache == null) { loaded = false; loadError = null }
        return available
    }

    val available get() = lib != null
    val version: String? get() = runCatching { lib?.pcap_lib_version() }.getOrNull()

    private fun load(): PcapLib? {
        return try {
            if (Platform.isWindows()) {
                val dir = File(System.getenv("SystemRoot") ?: "C:\\Windows", "System32\\Npcap")
                if (!File(dir, "wpcap.dll").exists()) {
                    loadError = "Npcap is not installed"
                    return null
                }
                NativeLibrary.addSearchPath("wpcap", dir.absolutePath)
                Native.load(File(dir, "wpcap.dll").absolutePath, PcapLib::class.java)
            } else {
                Native.load("pcap", PcapLib::class.java)
            }
        } catch (e: Throwable) {
            loadError = e.message ?: e.javaClass.simpleName
            null
        }
    }

    fun devices(): List<CaptureDevice> {
        val l = lib ?: return emptyList()
        val ref = PointerByReference()
        val err = ByteArray(512)
        if (l.pcap_findalldevs(ref, err) != 0) return emptyList()
        val head = ref.value ?: return emptyList()
        val ptr = Native.POINTER_SIZE.toLong()
        val result = mutableListOf<CaptureDevice>()
        try {
            var dev: Pointer? = head
            while (dev != null) {
                // pcap_if_t { next*, name*, description*, addresses*, flags }
                val name = dev.getPointer(ptr)?.getString(0) ?: ""
                val desc = dev.getPointer(ptr * 2)?.getString(0) ?: ""
                val flags = dev.getInt(ptr * 4)
                val addrs = mutableListOf<String>()
                var a: Pointer? = dev.getPointer(ptr * 3)
                while (a != null) {
                    // pcap_addr { next*, addr*, netmask*, broadaddr*, dstaddr* }
                    sockaddr(a.getPointer(ptr))?.let { addrs += it }
                    a = a.getPointer(0)
                }
                result += CaptureDevice(name, desc, addrs, (flags and 1) != 0)
                dev = dev.getPointer(0)
            }
        } finally {
            l.pcap_freealldevs(head)
        }
        return result
    }

    private fun sockaddr(p: Pointer?): String? {
        p ?: return null
        val family = p.getShort(0).toInt() and 0xFFFF
        return when (family) {
            2 -> InetAddress.getByAddress(p.getByteArray(4, 4)).hostAddress
            23, 10, 30 -> InetAddress.getByAddress(p.getByteArray(8, 16)).hostAddress
            else -> null
        }
    }

    /** An open capture handle; [next] blocks for at most the read timeout. */
    class Handle internal constructor(private val l: PcapLib, private val p: Pointer) : AutoCloseable {
        val linkType = l.pcap_datalink(p)
        private val hdr = PointerByReference()
        private val data = PointerByReference()
        @Volatile private var closed = false

        /** Returns a packet, null on timeout, or throws on error. */
        fun next(): RawPacket? {
            if (closed) return null
            return when (val rc = l.pcap_next_ex(p, hdr, data)) {
                1 -> {
                    val h = hdr.value
                    // struct pcap_pkthdr { timeval ts; bpf_u_int32 caplen; bpf_u_int32 len; }
                    // Windows' timeval uses 32-bit longs; 64-bit Unix uses 64-bit.
                    val wide = !Platform.isWindows() && Native.LONG_SIZE == 8
                    val sec = if (wide) h.getLong(0) else h.getInt(0).toLong() and 0xFFFFFFFFL
                    val usec = if (wide) h.getLong(8) else h.getInt(4).toLong()
                    val off = if (wide) 16L else 8L
                    val caplen = h.getInt(off)
                    val len = h.getInt(off + 4)
                    RawPacket(sec * 1_000_000 + usec, data.value.getByteArray(0, caplen), len)
                }
                0 -> null
                -2 -> null
                else -> error(l.pcap_geterr(p) ?: "capture error $rc")
            }
        }

        fun setFilter(expr: String) {
            val prog = Memory(16).apply { clear() }
            if (l.pcap_compile(p, prog, expr, 1, 0xFFFFFFFF.toInt()) != 0) error(l.pcap_geterr(p) ?: "invalid filter")
            try {
                if (l.pcap_setfilter(p, prog) != 0) error(l.pcap_geterr(p) ?: "could not set filter")
            } finally {
                l.pcap_freecode(prog)
            }
        }

        /** (received, dropped by kernel, dropped by interface) */
        fun stats(): Triple<Long, Long, Long>? {
            val m = Memory(16).apply { clear() }
            if (closed || l.pcap_stats(p, m) != 0) return null
            fun u(o: Long) = m.getInt(o).toLong() and 0xFFFFFFFFL
            return Triple(u(0), u(4), u(8))
        }

        fun breakLoop() { if (!closed) l.pcap_breakloop(p) }

        override fun close() {
            if (closed) return
            closed = true
            l.pcap_close(p)
        }
    }

    fun open(device: String, snaplen: Int = 65535, promiscuous: Boolean = false, timeoutMs: Int = 200): Handle {
        val l = lib ?: error(loadError ?: "packet capture library not available")
        val err = ByteArray(512)
        val p = l.pcap_open_live(device, snaplen, if (promiscuous) 1 else 0, timeoutMs, err)
            ?: error(String(err).trimEnd('\u0000').ifBlank { "could not open $device" })
        return Handle(l, p)
    }

    /** Writes packets in the classic .pcap format that Wireshark and tcpdump read. */
    fun writePcapFile(file: File, linkType: Int, packets: List<RawPacket>) {
        DataOutputStream(FileOutputStream(file).buffered()).use { out ->
            fun le32(v: Int) = out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array())
            fun le16(v: Int) = out.write(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(v.toShort()).array())
            le32(0xA1B2C3D4.toInt()); le16(2); le16(4); le32(0); le32(0); le32(65535); le32(linkType)
            for (p in packets) {
                le32((p.timeMicros / 1_000_000).toInt()); le32((p.timeMicros % 1_000_000).toInt())
                le32(p.data.size); le32(p.originalLength)
                out.write(p.data)
            }
        }
    }
}
