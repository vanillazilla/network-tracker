package com.networktracker.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.InetAddress

/** Running statistics for one hop of an MTR-style trace. */
class HopStats(val ttl: Int) {
    var address: String? = null
    var hostname: String? = null
    var sent = 0; private set
    var received = 0; private set
    var last = Double.NaN; private set
    var best = Double.NaN; private set
    var worst = Double.NaN; private set
    private var sum = 0.0
    private var jitterSum = 0.0
    private var jitterCount = 0

    val lossPercent get() = if (sent == 0) 0.0 else (sent - received) * 100.0 / sent
    val average get() = if (received == 0) Double.NaN else sum / received
    val jitter get() = if (jitterCount == 0) Double.NaN else jitterSum / jitterCount

    fun record(result: PingResult) {
        sent++
        if (result.status == PingStatus.OK || result.status == PingStatus.TTL_EXPIRED) {
            if (result.from != null) address = result.from
            val rtt = result.rttMs
            if (!last.isNaN()) { jitterSum += kotlin.math.abs(rtt - last); jitterCount++ }
            received++
            last = rtt
            sum += rtt
            best = if (best.isNaN()) rtt else minOf(best, rtt)
            worst = if (worst.isNaN()) rtt else maxOf(worst, rtt)
        }
    }
}

/**
 * MTR-style trace: discovers the route with TTL-limited echo requests, then keeps probing
 * every hop so loss and latency can be pinned to the point in the path where they begin.
 */
class TraceSession(val destination: InetAddress, private val pinger: Pinger = Pinger.default) {
    val hops = mutableListOf<HopStats>()
    var reachedDestination = false; private set

    /** Discover the path. Probes all TTLs in parallel so this takes about one timeout. */
    suspend fun discover(maxHops: Int = 30, timeoutMs: Int = 1500) {
        val results = probeAll(1..maxHops, timeoutMs)
        val destIp = destination.hostAddress
        val lastTtl = results.indexOfFirst { it.status == PingStatus.OK || it.from == destIp }
        reachedDestination = lastTtl >= 0
        // If the destination never answered, trim trailing silent hops.
        val count = if (lastTtl >= 0) lastTtl + 1
        else (results.indexOfLast { it.from != null } + 2).coerceIn(1, maxHops)
        hops.clear()
        for (i in 0 until count) hops += HopStats(i + 1).also { it.record(results[i]) }
    }

    /** One probe to every hop; returns after all replies or timeouts. */
    suspend fun round(timeoutMs: Int = 1500) {
        val results = probeAll(1..hops.size, timeoutMs)
        results.forEachIndexed { i, r -> hops[i].record(r) }
        if (results.lastOrNull()?.status == PingStatus.OK) reachedDestination = true
    }

    private suspend fun probeAll(ttls: IntRange, timeoutMs: Int): List<PingResult> = coroutineScope {
        ttls.map { ttl -> async(Dispatchers.IO) { pinger.ping(destination, timeoutMs, ttl) } }.awaitAll()
    }

    suspend fun resolveNames() = withContext(Dispatchers.IO) {
        for (hop in hops.toList()) {
            val ip = hop.address ?: continue
            if (hop.hostname != null) continue
            hop.hostname = runCatching { InetAddress.getByName(ip).canonicalHostName }
                .getOrNull()?.takeIf { it != ip } ?: ""
        }
    }

    /**
     * Interprets the trace the way an engineer would: loss at an intermediate hop that does not
     * carry through to later hops is just that router rate-limiting ICMP, not real packet loss.
     */
    fun analyze(): String {
        if (hops.isEmpty() || hops.all { it.sent == 0 }) return "Collecting data…"
        val final = hops.last()
        if (!reachedDestination) {
            val lastAnswering = hops.lastOrNull { it.received > 0 }
            return if (lastAnswering == null) "No hops responded. ICMP may be blocked by your firewall or network."
            else "The destination did not respond. The trace stops after hop ${lastAnswering.ttl} " +
                "(${lastAnswering.address}). The host may be down, or it may block ping."
        }
        if (final.sent < 5) return "Collecting data… (${final.sent} rounds)"
        val finalLoss = final.lossPercent
        if (finalLoss < 1.0) {
            val noisy = hops.dropLast(1).filter { it.lossPercent >= 10 }
            return buildString {
                append("No loss to the destination. Path looks healthy.")
                if (noisy.isNotEmpty()) append(" Loss shown at hop ${noisy.joinToString { it.ttl.toString() }} " +
                    "does not continue to later hops, so it is ICMP rate-limiting by those routers and can be ignored.")
            }
        }
        // Find the first hop from which loss persists all the way to the destination.
        var origin = final
        for (hop in hops.reversed()) {
            if (hop.lossPercent >= finalLoss * 0.6 && hop.lossPercent >= 1.0) origin = hop else break
        }
        val where = when (origin.ttl) {
            1 -> "at hop 1 (your router). The problem is between this computer and your router, or the router itself."
            2, 3 -> "at hop ${origin.ttl} (${origin.address ?: "?"}), right after your router: your modem, " +
                "the line to your ISP, or the ISP's first router."
            final.ttl -> "only at the destination. The remote host (or its firewall) is dropping packets."
            else -> "at hop ${origin.ttl} (${origin.address ?: "?"}) and continues to the destination. " +
                "The problem is in a network beyond your ISP's edge."
        }
        return "%.1f%% loss to the destination, starting %s".format(finalLoss, where)
    }
}
