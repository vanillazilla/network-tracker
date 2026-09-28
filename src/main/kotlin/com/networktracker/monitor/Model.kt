package com.networktracker.monitor

import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

enum class TargetRole(val label: String, val order: Int) {
    GATEWAY("Router", 0),
    ISP("ISP Edge", 1),
    INTERNET("Internet", 2),
    DNS("DNS", 3),
    CUSTOM("Target", 4),
}

enum class ProbeKind { ICMP, DNS }

enum class Health { GOOD, WARN, BAD, UNKNOWN }

/** One probe result. [rtt] is NaN when the probe was lost. [tick] ties together probes sent in the same round. */
class Sample(val tick: Long, val time: Long, val rtt: Float) {
    val lost get() = rtt.isNaN()
}

data class Summary(
    val sent: Int,
    val received: Int,
    val last: Double,
    val min: Double,
    val avg: Double,
    val max: Double,
    val jitter: Double,
    val p95: Double,
) {
    val lost get() = sent - received
    val lossPercent get() = if (sent == 0) 0.0 else lost * 100.0 / sent

    companion object {
        val EMPTY = Summary(0, 0, Double.NaN, Double.NaN, Double.NaN, Double.NaN, Double.NaN, Double.NaN)
    }
}

class Target(
    val role: TargetRole,
    val name: String,
    val host: String,
    val kind: ProbeKind = ProbeKind.ICMP,
    /** For DNS probes: the name to look up. */
    val dnsQuery: String = "www.google.com",
) {
    val id = nextId.incrementAndGet()
    @Volatile var address: InetAddress? = null
    @Volatile var resolveError: String? = null
    var visible = true
    var colorIndex = 0

    val samples = ArrayList<Sample>()
    var consecutiveLost = 0
    var outageStart: Long? = null
    var inSpike = false
    /** Exponential moving average of RTT, used as the "normal" baseline for spike detection. */
    var ema = Double.NaN

    val displayAddress get() = address?.hostAddress ?: host

    fun add(sample: Sample) {
        samples += sample
        if (samples.size > MAX_SAMPLES) samples.subList(0, samples.size - MAX_SAMPLES).clear()
    }

    /** Index of the first sample at or after [time] (binary search; samples are time-ordered). */
    fun indexFrom(time: Long): Int {
        var lo = 0; var hi = samples.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (samples[mid].time < time) lo = mid + 1 else hi = mid
        }
        return lo
    }

    fun summary(fromTime: Long = 0L): Summary {
        val start = indexFrom(fromTime)
        if (start >= samples.size) return Summary.EMPTY
        var received = 0
        var min = Double.MAX_VALUE; var max = -1.0; var sum = 0.0
        var jitterSum = 0.0; var jitterN = 0
        var prev = Double.NaN
        val values = DoubleArray(samples.size - start)
        for (i in start until samples.size) {
            val r = samples[i].rtt.toDouble()
            if (r.isNaN()) continue
            values[received++] = r
            sum += r
            if (r < min) min = r
            if (r > max) max = r
            if (!prev.isNaN()) { jitterSum += kotlin.math.abs(r - prev); jitterN++ }
            prev = r
        }
        val sent = samples.size - start
        if (received == 0) return Summary.EMPTY.copy(sent = sent, received = 0)
        val sorted = values.copyOf(received).also { it.sort() }
        return Summary(
            sent = sent,
            received = received,
            last = samples.last().rtt.toDouble(),
            min = min, avg = sum / received, max = max,
            jitter = if (jitterN == 0) 0.0 else jitterSum / jitterN,
            p95 = sorted[((received - 1) * 0.95).toInt()],
        )
    }

    /** Ticks in the window where this target's probe was lost. */
    fun lostTicks(fromTime: Long): Set<Long> {
        val out = HashSet<Long>()
        for (i in indexFrom(fromTime) until samples.size) if (samples[i].lost) out += samples[i].tick
        return out
    }

    fun ticks(fromTime: Long): Set<Long> {
        val out = HashSet<Long>()
        for (i in indexFrom(fromTime) until samples.size) out += samples[i].tick
        return out
    }

    companion object {
        private val nextId = AtomicInteger()
        const val MAX_SAMPLES = 172_800 // 48 h at 1 probe/s
    }
}

enum class Severity { INFO, WARNING, ERROR, SUCCESS }

data class NetEvent(val time: Long, val severity: Severity, val source: String, val message: String)

/** One Wi-Fi signal reading, for the signal history chart. */
data class WifiSample(val time: Long, val signal: Int, val bssid: String?)
