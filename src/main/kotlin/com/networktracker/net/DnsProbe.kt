package com.networktracker.net

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import kotlin.random.Random

data class DnsResult(val ok: Boolean, val rttMs: Double = Double.NaN, val error: String? = null)

/**
 * Sends a raw DNS "A" query directly to a DNS server over UDP, bypassing the OS resolver cache,
 * so we measure the real availability and response time of the server itself.
 */
object DnsProbe {
    fun query(server: InetAddress, name: String, timeoutMs: Int): DnsResult {
        val id = Random.nextInt(0, 0xFFFF)
        val request = buildQuery(id, name)
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                val start = System.nanoTime()
                socket.send(DatagramPacket(request, request.size, server, 53))
                val buf = ByteArray(1500)
                val deadline = start + timeoutMs * 1_000_000L
                while (true) {
                    val packet = DatagramPacket(buf, buf.size)
                    socket.receive(packet)
                    val rtt = (System.nanoTime() - start) / 1_000_000.0
                    if (packet.length < 12) continue
                    val respId = ((buf[0].toInt() and 0xFF) shl 8) or (buf[1].toInt() and 0xFF)
                    if (respId != id) {
                        if (System.nanoTime() > deadline) throw SocketTimeoutException()
                        continue
                    }
                    val rcode = buf[3].toInt() and 0x0F
                    return if (rcode == 0 || rcode == 3) DnsResult(true, rtt)
                    else DnsResult(false, rtt, "Server returned error code $rcode")
                }
                @Suppress("UNREACHABLE_CODE")
                DnsResult(false)
            }
        } catch (_: SocketTimeoutException) {
            DnsResult(false, error = "Timed out")
        } catch (e: Exception) {
            DnsResult(false, error = e.message ?: e.javaClass.simpleName)
        }
    }

    private fun buildQuery(id: Int, name: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(id shr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00)           // standard query, recursion desired
        out.write(0); out.write(1)                  // QDCOUNT = 1
        repeat(6) { out.write(0) }                  // ANCOUNT, NSCOUNT, ARCOUNT
        for (label in name.trim('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size); out.write(bytes)
        }
        out.write(0)
        out.write(0); out.write(1)                  // QTYPE A
        out.write(0); out.write(1)                  // QCLASS IN
        return out.toByteArray()
    }
}
