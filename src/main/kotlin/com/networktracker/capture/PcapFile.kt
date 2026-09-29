package com.networktracker.capture

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Reads classic .pcap and .pcapng capture files. */
object PcapFile {
    class Contents(val linkType: Int, val packets: List<RawPacket>)

    fun read(file: File, limit: Int = 2_000_000): Contents {
        val bytes = file.readBytes()
        require(bytes.size >= 24) { "File is too small to be a capture file" }
        val magic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.BIG_ENDIAN).int
        return when (magic) {
            0x0A0D0D0A -> readPcapNg(bytes, limit)
            0xA1B2C3D4.toInt(), 0xD4C3B2A1.toInt(), 0xA1B23C4D.toInt(), 0x4D3CB2A1.toInt() -> readPcap(bytes, magic, limit)
            else -> error("Not a pcap or pcapng file")
        }
    }

    private fun readPcap(bytes: ByteArray, magic: Int, limit: Int): Contents {
        val order = if (magic == 0xA1B2C3D4.toInt() || magic == 0xA1B23C4D.toInt()) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val nanos = magic == 0xA1B23C4D.toInt() || magic == 0x4D3CB2A1.toInt()
        val bb = ByteBuffer.wrap(bytes).order(order)
        val linkType = bb.getInt(20) and 0x0FFFFFFF
        var pos = 24
        val out = ArrayList<RawPacket>()
        while (pos + 16 <= bytes.size && out.size < limit) {
            val sec = bb.getInt(pos).toLong() and 0xFFFFFFFFL
            val frac = bb.getInt(pos + 4).toLong() and 0xFFFFFFFFL
            val incl = bb.getInt(pos + 8)
            val orig = bb.getInt(pos + 12)
            pos += 16
            if (incl < 0 || pos + incl > bytes.size) break
            out += RawPacket(sec * 1_000_000 + if (nanos) frac / 1000 else frac, bytes.copyOfRange(pos, pos + incl), orig)
            pos += incl
        }
        return Contents(linkType, out)
    }

    private fun readPcapNg(bytes: ByteArray, limit: Int): Contents {
        var order = ByteOrder.LITTLE_ENDIAN
        val ifLink = mutableListOf<Int>()
        val ifDiv = mutableListOf<Long>() // timestamp units per second
        val out = ArrayList<RawPacket>()
        var pos = 0
        while (pos + 12 <= bytes.size && out.size < limit) {
            if (ByteBuffer.wrap(bytes, pos, 4).order(ByteOrder.BIG_ENDIAN).int == 0x0A0D0D0A) {
                val bom = ByteBuffer.wrap(bytes, pos + 8, 4).order(ByteOrder.LITTLE_ENDIAN).int
                order = if (bom == 0x1A2B3C4D) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
                ifLink.clear(); ifDiv.clear()
            }
            val bb = ByteBuffer.wrap(bytes).order(order)
            val type = bb.getInt(pos)
            val len = bb.getInt(pos + 4)
            if (len < 12 || pos + len > bytes.size) break
            when (type) {
                1 -> { // Interface Description Block
                    ifLink += bb.getShort(pos + 8).toInt() and 0xFFFF
                    var div = 1_000_000L
                    var o = pos + 16
                    while (o + 4 <= pos + len - 4) {
                        val code = bb.getShort(o).toInt() and 0xFFFF
                        val olen = bb.getShort(o + 2).toInt() and 0xFFFF
                        if (code == 0) break
                        if (code == 9 && olen >= 1) {
                            val r = bytes[o + 4].toInt() and 0xFF
                            div = if (r and 0x80 != 0) 1L shl (r and 0x7F) else Math.pow(10.0, r.toDouble()).toLong()
                        }
                        o += 4 + (olen + 3) / 4 * 4
                    }
                    ifDiv += div
                }
                6 -> { // Enhanced Packet Block
                    val iface = bb.getInt(pos + 8)
                    val ts = (bb.getInt(pos + 12).toLong() shl 32) or (bb.getInt(pos + 16).toLong() and 0xFFFFFFFFL)
                    val cap = bb.getInt(pos + 20)
                    val orig = bb.getInt(pos + 24)
                    val div = ifDiv.getOrElse(iface) { 1_000_000L }
                    val micros = if (div == 1_000_000L) ts else (ts.toDouble() * 1_000_000 / div).toLong()
                    if (cap >= 0 && pos + 28 + cap <= bytes.size)
                        out += RawPacket(micros, bytes.copyOfRange(pos + 28, pos + 28 + cap), orig)
                }
                3 -> { // Simple Packet Block
                    val orig = bb.getInt(pos + 8)
                    val cap = minOf(orig, len - 16)
                    out += RawPacket(0, bytes.copyOfRange(pos + 12, pos + 12 + cap), orig)
                }
            }
            pos += len
        }
        return Contents(ifLink.firstOrNull() ?: Pcap.DLT_EN10MB, out)
    }
}
