package com.networktracker.net

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.TimeUnit

enum class PingStatus { OK, TIMEOUT, TTL_EXPIRED, UNREACHABLE, ERROR }

data class PingResult(
    val status: PingStatus,
    /** Round-trip time in milliseconds; only meaningful for OK and TTL_EXPIRED. */
    val rttMs: Double = Double.NaN,
    /** The address that answered (the destination, or the router whose TTL expired). */
    val from: String? = null,
) {
    val isReply get() = status == PingStatus.OK
}

interface Pinger {
    fun ping(address: InetAddress, timeoutMs: Int, ttl: Int = 128): PingResult

    companion object {
        /** Best pinger for this platform: native ICMP on Windows, system `ping` elsewhere. */
        val default: Pinger by lazy {
            if (Platform.isWindows()) {
                runCatching { WindowsIcmpPinger() }.getOrElse { SystemPinger() }
            } else SystemPinger()
        }
    }
}

/** JNA bindings for the parts of iphlpapi.dll we use. */
@Suppress("FunctionName")
internal interface IpHlpApi : Library {
    fun IcmpCreateFile(): Pointer?
    fun IcmpCloseHandle(handle: Pointer): Boolean
    fun IcmpSendEcho(
        handle: Pointer, destAddr: Int, requestData: Pointer, requestSize: Short,
        requestOptions: Pointer?, replyBuffer: Pointer, replySize: Int, timeout: Int,
    ): Int
    fun GetBestRoute(destAddr: Int, sourceAddr: Int, bestRoute: Pointer): Int
    fun GetNetworkParams(buffer: Pointer?, size: IntByReference): Int

    companion object {
        val INSTANCE: IpHlpApi by lazy { Native.load("Iphlpapi", IpHlpApi::class.java) }

        /** IPv4 address as the network-byte-order DWORD Windows expects. */
        fun toIpAddr(address: Inet4Address): Int =
            ByteBuffer.wrap(address.address).order(ByteOrder.LITTLE_ENDIAN).int

        fun fromIpAddr(value: Int): String {
            val b = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
            return b.joinToString(".") { (it.toInt() and 0xFF).toString() }
        }
    }
}

/**
 * Sends ICMP echo requests through the Windows ICMP API. No admin rights required,
 * supports custom TTL (used for traceroute) and has sub-millisecond timing.
 */
class WindowsIcmpPinger : Pinger {
    private val api = IpHlpApi.INSTANCE
    private val fallback by lazy { SystemPinger() }

    init {
        // Fail fast if the API isn't usable so the caller can fall back.
        val h = api.IcmpCreateFile() ?: error("IcmpCreateFile failed")
        api.IcmpCloseHandle(h)
    }

    override fun ping(address: InetAddress, timeoutMs: Int, ttl: Int): PingResult {
        if (address !is Inet4Address) return fallback.ping(address, timeoutMs, ttl)
        val handle = api.IcmpCreateFile() ?: return PingResult(PingStatus.ERROR)
        try {
            val payload = Memory(PAYLOAD_SIZE.toLong()).apply {
                for (i in 0 until PAYLOAD_SIZE) setByte(i.toLong(), ('a' + i % 23).code.toByte())
            }
            val options = Memory(16).apply {
                clear()
                setByte(0, ttl.coerceIn(1, 255).toByte())
            }
            val replySize = 256
            val reply = Memory(replySize.toLong()).apply { clear() }

            val start = System.nanoTime()
            val count = api.IcmpSendEcho(
                handle, IpHlpApi.toIpAddr(address), payload, PAYLOAD_SIZE.toShort(),
                options, reply, replySize, timeoutMs,
            )
            val elapsedMs = (System.nanoTime() - start) / 1_000_000.0

            if (count == 0) {
                return when (Native.getLastError()) {
                    IP_REQ_TIMED_OUT -> PingResult(PingStatus.TIMEOUT)
                    IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE -> PingResult(PingStatus.UNREACHABLE)
                    IP_TTL_EXPIRED_TRANSIT -> PingResult(PingStatus.TTL_EXPIRED, elapsedMs)
                    else -> PingResult(PingStatus.TIMEOUT)
                }
            }
            val from = IpHlpApi.fromIpAddr(reply.getInt(0))
            val status = reply.getInt(4)
            val apiRtt = reply.getInt(8).toDouble()
            // The API reports whole milliseconds; wall-clock timing is more precise but
            // never let it be wildly off from what the OS measured.
            val rtt = if (elapsedMs - apiRtt in -1.0..2.0) elapsedMs else apiRtt
            return when (status) {
                IP_SUCCESS -> PingResult(PingStatus.OK, rtt, from)
                IP_TTL_EXPIRED_TRANSIT, IP_TTL_EXPIRED_REASSEM -> PingResult(PingStatus.TTL_EXPIRED, rtt, from)
                IP_REQ_TIMED_OUT -> PingResult(PingStatus.TIMEOUT)
                IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE,
                IP_DEST_PROT_UNREACHABLE -> PingResult(PingStatus.UNREACHABLE, from = from)
                else -> PingResult(PingStatus.ERROR, from = from)
            }
        } finally {
            api.IcmpCloseHandle(handle)
        }
    }

    private companion object {
        const val PAYLOAD_SIZE = 32
        const val IP_SUCCESS = 0
        const val IP_DEST_NET_UNREACHABLE = 11002
        const val IP_DEST_HOST_UNREACHABLE = 11003
        const val IP_DEST_PROT_UNREACHABLE = 11004
        const val IP_DEST_PORT_UNREACHABLE = 11005
        const val IP_REQ_TIMED_OUT = 11010
        const val IP_TTL_EXPIRED_TRANSIT = 11013
        const val IP_TTL_EXPIRED_REASSEM = 11014
    }
}

/** Fallback that shells out to the operating system's `ping` command. */
class SystemPinger : Pinger {
    private val rttRegex = Regex("""[=<]\s*([\d.,]+)\s*ms""", RegexOption.IGNORE_CASE)
    private val fromRegex = Regex("""(?:from|von|de|da)\s+([0-9a-fA-F:.]+)""", RegexOption.IGNORE_CASE)
    private val ttlExceededRegex = Regex("""TTL|time to live|hop limit""", RegexOption.IGNORE_CASE)
    private val exceededRegex = Regex("""expired|exceeded|überschritten|expiré""", RegexOption.IGNORE_CASE)

    override fun ping(address: InetAddress, timeoutMs: Int, ttl: Int): PingResult {
        val host = address.hostAddress
        val cmd = when {
            Platform.isWindows() -> listOf("ping", "-n", "1", "-w", "$timeoutMs", "-i", "$ttl", host)
            Platform.isMac() -> listOf("ping", "-c", "1", "-W", "$timeoutMs", "-m", "$ttl", host)
            else -> listOf("ping", "-c", "1", "-W", "${(timeoutMs + 999) / 1000}", "-t", "$ttl", host)
        }
        return try {
            val start = System.nanoTime()
            val proc = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = proc.inputStream.bufferedReader().readText()
            proc.waitFor(timeoutMs + 3000L, TimeUnit.MILLISECONDS)
            val elapsed = (System.nanoTime() - start) / 1_000_000.0
            val replyLine = out.lines().firstOrNull { rttRegex.containsMatchIn(it) && it.contains(host) }
            when {
                replyLine != null -> {
                    val rtt = rttRegex.find(replyLine)!!.groupValues[1].replace(',', '.').toDoubleOrNull() ?: elapsed
                    PingResult(PingStatus.OK, rtt, host)
                }
                ttlExceededRegex.containsMatchIn(out) && exceededRegex.containsMatchIn(out) -> {
                    val from = fromRegex.find(out)?.groupValues?.get(1)?.trimEnd(':', '.')
                    PingResult(PingStatus.TTL_EXPIRED, elapsed, from)
                }
                out.contains("unreachable", ignoreCase = true) -> PingResult(PingStatus.UNREACHABLE)
                else -> PingResult(PingStatus.TIMEOUT)
            }
        } catch (e: Exception) {
            PingResult(PingStatus.ERROR)
        }
    }
}
