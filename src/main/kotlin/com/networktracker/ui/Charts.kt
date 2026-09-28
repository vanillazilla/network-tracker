package com.networktracker.ui

import com.networktracker.monitor.MonitorEngine
import com.networktracker.monitor.Target
import com.networktracker.monitor.TargetRole
import java.awt.BasicStroke
import java.awt.Dimension
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.geom.Line2D
import java.awt.geom.Path2D
import java.awt.geom.RoundRectangle2D
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.JComponent
import kotlin.math.log10
import kotlin.math.pow

/** Time range and selection shared by the latency chart and the timeline strip. */
class ChartState(private val engine: MonitorEngine) {
    /** Visible window in ms; null means the whole session. */
    var windowMs: Long? = 5 * 60_000L
    var selectedId: Int? = null
    var hoverTime: Long? = null
    val listeners = mutableListOf<() -> Unit>()
    fun changed() = listeners.forEach { it() }

    fun range(): Pair<Long, Long> {
        val lastSample = engine.targets.mapNotNull { it.samples.lastOrNull()?.time }.maxOrNull()
        val end = if (engine.running) System.currentTimeMillis() else (lastSample ?: System.currentTimeMillis())
        val w = windowMs
        val start = if (w != null) end - w
        else engine.targets.mapNotNull { it.samples.firstOrNull()?.time }.minOrNull()?.coerceAtMost(end - 30_000) ?: (end - 60_000)
        return start to end
    }

    /** Start of the window used for statistics and diagnosis. */
    fun statsFrom(): Long = windowMs?.let { System.currentTimeMillis() - it } ?: 0L

    companion object {
        const val LEFT = 150      // shared gutter so chart and timeline x axes line up
        const val RIGHT = 14
    }
}

private val timeFmt = SimpleDateFormat("HH:mm:ss")
private val shortFmt = SimpleDateFormat("HH:mm")

/** Per-pixel-column aggregation of a target's samples, so long sessions render quickly. */
private class Columns(n: Int) {
    val avg = DoubleArray(n) { Double.NaN }
    val max = DoubleArray(n) { Double.NaN }
    val lost = BooleanArray(n)
    val has = BooleanArray(n)
}

private fun aggregate(t: Target, start: Long, end: Long, cols: Int): Columns {
    val c = Columns(cols)
    if (cols <= 0 || end <= start) return c
    val sum = DoubleArray(cols); val cnt = IntArray(cols)
    val span = (end - start).toDouble()
    for (i in t.indexFrom(start) until t.samples.size) {
        val s = t.samples[i]
        if (s.time > end) break
        val x = (((s.time - start) / span) * (cols - 1)).toInt().coerceIn(0, cols - 1)
        c.has[x] = true
        if (s.lost) { c.lost[x] = true; continue }
        val r = s.rtt.toDouble()
        sum[x] += r; cnt[x]++
        if (c.max[x].isNaN() || r > c.max[x]) c.max[x] = r
    }
    for (x in 0 until cols) if (cnt[x] > 0) c.avg[x] = sum[x] / cnt[x]
    return c
}

private fun niceCeil(v: Double): Double {
    if (v <= 0) return 10.0
    val mag = 10.0.pow(kotlin.math.floor(log10(v)))
    val n = v / mag
    val nice = when { n <= 1 -> 1.0; n <= 2 -> 2.0; n <= 2.5 -> 2.5; n <= 5 -> 5.0; else -> 10.0 }
    return nice * mag
}

class LatencyChart(private val engine: MonitorEngine, private val state: ChartState) : JComponent() {
    private var mouseX: Int? = null

    init {
        preferredSize = Dimension(600, 260)
        val ma = object : MouseAdapter() {
            override fun mouseMoved(e: MouseEvent) { mouseX = e.x; updateHover() }
            override fun mouseDragged(e: MouseEvent) { mouseX = e.x; updateHover() }
            override fun mouseExited(e: MouseEvent) { mouseX = null; updateHover() }
            override fun mouseClicked(e: MouseEvent) {
                // Clicking a legend entry toggles that series.
                if (e.x < ChartState.LEFT - 50) {
                    val idx = (e.y - TOP) / LEGEND_ROW
                    visibleLegend().getOrNull(idx)?.let { it.visible = !it.visible; state.changed() }
                }
            }
        }
        addMouseListener(ma); addMouseMotionListener(ma)
    }

    private fun visibleLegend() = engine.targets.toList()

    private fun updateHover() {
        val x = mouseX
        val plotW = width - ChartState.LEFT - ChartState.RIGHT
        state.hoverTime = if (x == null || x < ChartState.LEFT || x > width - ChartState.RIGHT || plotW <= 0) null else {
            val (start, end) = state.range()
            start + ((x - ChartState.LEFT).toDouble() / plotW * (end - start)).toLong()
        }
        state.changed()
    }

    override fun paintComponent(g: Graphics) {
        val g2 = Theme.smooth(g)
        val left = ChartState.LEFT; val right = width - ChartState.RIGHT
        val top = TOP; val bottom = height - 24
        val plotW = right - left; val plotH = bottom - top
        if (plotW < 20 || plotH < 20) { g2.dispose(); return }
        val (start, end) = state.range()
        val targets = engine.targets.toList()
        val shown = targets.filter { it.visible }
        val cols = plotW
        val data = shown.associateWith { aggregate(it, start, end, cols) }

        // Y scale: fit the 98th percentile so a single huge spike doesn't flatten everything.
        val values = data.values.flatMap { c -> c.max.filter { !it.isNaN() } }.sorted()
        val p98 = if (values.isEmpty()) 10.0 else values[((values.size - 1) * 0.98).toInt()]
        val yMax = niceCeil(maxOf(p98 * 1.2, 4.0))
        fun y(v: Double) = bottom - (minOf(v, yMax) / yMax) * plotH
        fun x(col: Int) = left + col.toDouble()

        // Grid + Y labels
        g2.font = Theme.font(Font.PLAIN, -1.5f)
        val fm = g2.fontMetrics
        for (i in 0..4) {
            val v = yMax * i / 4
            val yy = y(v)
            g2.color = Theme.grid
            g2.draw(Line2D.Double(left.toDouble(), yy, right.toDouble(), yy))
            g2.color = Theme.muted
            val label = if (v >= 10 || v == 0.0) "${v.toInt()} ms" else "%.1f ms".format(v)
            g2.drawString(label, left - 8 - fm.stringWidth(label), (yy + fm.ascent / 2.5).toInt())
        }
        // X labels
        val span = end - start
        val ticks = 6
        for (i in 0..ticks) {
            val t = start + span * i / ticks
            val label = (if (span > 3 * 3600_000) shortFmt else timeFmt).format(Date(t))
            val xx = left + plotW * i / ticks
            val w = fm.stringWidth(label)
            g2.color = Theme.muted
            g2.drawString(label, (xx - w / 2).coerceIn(left - 10, right - w), bottom + fm.ascent + 6)
        }

        // Loss bands: faint red column wherever any shown series lost a probe.
        g2.color = Theme.alpha(Theme.bad, if (Theme.isDark) 0.22 else 0.14)
        for (col in 0 until cols) if (data.values.any { it.lost[col] }) g2.fillRect(left + col, top, 1, plotH)

        // Series
        val sel = state.selectedId
        val ordered = shown.sortedBy { if (it.id == sel) 1 else 0 }
        for (t in ordered) {
            val c = data[t] ?: continue
            val color = Theme.series(t.colorIndex)
            val dim = sel != null && t.id != sel
            g2.color = if (dim) Theme.alpha(color, 0.3) else color
            g2.stroke = BasicStroke(if (t.id == sel) 2.2f else 1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            val path = Path2D.Double()
            var penDown = false
            var gap = 0
            for (col in 0 until cols) {
                val v = c.avg[col]
                if (v.isNaN()) {
                    if (c.lost[col] || (c.has[col])) { penDown = false; gap = 0 }
                    else if (++gap > 6) penDown = false
                    continue
                }
                gap = 0
                if (penDown) path.lineTo(x(col), y(v)) else path.moveTo(x(col), y(v))
                penDown = true
            }
            g2.draw(path)
            // Mark single points (isolated samples) so they don't disappear.
            if (shown.size <= 4 || t.id == sel) for (col in 0 until cols) {
                if (!c.avg[col].isNaN() && (col == 0 || c.avg[col - 1].isNaN()) && (col == cols - 1 || c.avg[col + 1].isNaN()))
                    g2.fillOval(col + left - 2, y(c.avg[col]).toInt() - 2, 4, 4)
            }
        }

        // Legend in the left gutter
        g2.font = Theme.font(Font.PLAIN, -1f)
        val lfm = g2.fontMetrics
        targets.forEachIndexed { i, t ->
            val ly = top + i * LEGEND_ROW
            if (ly + LEGEND_ROW > bottom + 20) return@forEachIndexed
            val color = Theme.series(t.colorIndex)
            g2.color = if (t.visible) color else Theme.alpha(color, 0.25)
            g2.fill(RoundRectangle2D.Double(4.0, ly + 3.0, 12.0, 4.0, 4.0, 4.0))
            g2.color = if (t.visible) Theme.foreground else Theme.muted
            var name = t.name
            val maxW = left - 72
            while (lfm.stringWidth(name) > maxW && name.length > 3) name = name.dropLast(2) + "…"
            if (name.endsWith("……")) name = name.dropLast(1)
            g2.drawString(name, 22, ly + lfm.ascent - 3)
        }

        // Hover crosshair + tooltip
        val ht = state.hoverTime
        if (ht != null && ht in start..end) {
            val hx = left + ((ht - start).toDouble() / span * plotW)
            g2.color = Theme.alpha(Theme.foreground, 0.35)
            g2.stroke = BasicStroke(1f)
            g2.draw(Line2D.Double(hx, top.toDouble(), hx, bottom.toDouble()))
            val rows = shown.mapNotNull { t ->
                val i = t.indexFrom(ht - engine.intervalMs / 2)
                val s = t.samples.getOrNull(i) ?: return@mapNotNull null
                if (kotlin.math.abs(s.time - ht) > engine.intervalMs * 2) return@mapNotNull null
                t to (if (s.lost) "lost" else "%.1f ms".format(s.rtt))
            }
            drawTooltip(g2, hx.toInt(), top + 6, timeFmt.format(Date(ht)), rows, left, right)
        }

        if (targets.all { it.samples.isEmpty() }) {
            g2.font = Theme.font(Font.PLAIN, 1f)
            g2.color = Theme.muted
            val msg = if (engine.running) "Waiting for first results…" else "Press Start to begin monitoring"
            val w = g2.fontMetrics.stringWidth(msg)
            g2.drawString(msg, left + (plotW - w) / 2, top + plotH / 2)
        }
        g2.dispose()
    }

    private fun drawTooltip(g2: Graphics2D, x: Int, y: Int, title: String, rows: List<Pair<Target, String>>, minX: Int, maxX: Int) {
        if (rows.isEmpty()) return
        g2.font = Theme.font(Font.PLAIN, -1f)
        val fm = g2.fontMetrics
        val lineH = fm.height + 2
        val w = maxOf(fm.stringWidth(title), rows.maxOf { fm.stringWidth(it.first.name) + fm.stringWidth(it.second) + 28 }) + 20
        val h = lineH * (rows.size + 1) + 12
        var bx = x + 12
        if (bx + w > maxX) bx = x - 12 - w
        bx = bx.coerceAtLeast(minX)
        val shape = RoundRectangle2D.Double(bx.toDouble(), y.toDouble(), w.toDouble(), h.toDouble(), 10.0, 10.0)
        g2.color = Theme.alpha(Theme.blend(Theme.card, Theme.foreground, 0.06), 0.97)
        g2.fill(shape)
        g2.color = Theme.border
        g2.draw(shape)
        g2.font = Theme.font(Font.BOLD, -1f)
        g2.color = Theme.foreground
        g2.drawString(title, bx + 10, y + 6 + fm.ascent)
        g2.font = Theme.font(Font.PLAIN, -1f)
        rows.forEachIndexed { i, (t, v) ->
            val ly = y + 6 + lineH * (i + 1)
            g2.color = Theme.series(t.colorIndex)
            g2.fillOval(bx + 10, ly + fm.ascent / 2 - 2, 8, 8)
            g2.color = Theme.foreground
            g2.drawString(t.name, bx + 24, ly + fm.ascent)
            g2.color = if (v == "lost") Theme.bad else Theme.foreground
            g2.drawString(v, bx + w - 10 - fm.stringWidth(v), ly + fm.ascent)
        }
    }

    companion object {
        const val TOP = 10
        const val LEGEND_ROW = 20
    }
}

/**
 * One row per target, one cell per time slice: green = replied, amber = slow, red = lost.
 * Losses that line up vertically across rows are the key visual clue: if the router row is red at
 * the same moment as everything below it, the problem is local.
 */
class TimelineStrip(private val engine: MonitorEngine, private val state: ChartState) : JComponent() {
    init {
        val ma = object : MouseAdapter() {
            override fun mouseMoved(e: MouseEvent) = hover(e.x)
            override fun mouseExited(e: MouseEvent) { state.hoverTime = null; state.changed() }
        }
        addMouseListener(ma); addMouseMotionListener(ma)
    }

    private fun hover(x: Int) {
        val plotW = width - ChartState.LEFT - ChartState.RIGHT
        val (start, end) = state.range()
        state.hoverTime = if (x < ChartState.LEFT || plotW <= 0) null
        else start + ((x - ChartState.LEFT).toDouble() / plotW * (end - start)).toLong()
        state.changed()
    }

    override fun getPreferredSize(): Dimension = Dimension(600, 8 + engine.targets.size.coerceAtLeast(1) * ROW)

    private fun slowThreshold(t: Target): Double = when (t.role) {
        TargetRole.GATEWAY -> 30.0
        TargetRole.ISP -> 80.0
        TargetRole.DNS -> 250.0
        else -> maxOf(150.0, if (t.ema.isNaN()) 0.0 else t.ema * 2.5)
    }

    override fun paintComponent(g: Graphics) {
        val g2 = Theme.smooth(g)
        val left = ChartState.LEFT; val right = width - ChartState.RIGHT
        val plotW = right - left
        val (start, end) = state.range()
        g2.font = Theme.font(Font.PLAIN, -1.5f)
        val fm = g2.fontMetrics
        val targets = engine.targets.toList()
        targets.forEachIndexed { i, t ->
            val y = 4 + i * ROW
            val h = ROW - 5
            g2.color = if (state.selectedId == t.id) Theme.foreground else Theme.muted
            var name = t.name
            while (fm.stringWidth(name) > left - 24 && name.length > 3) name = name.dropLast(2) + "…"
            g2.drawString(name, 22, y + h / 2 + fm.ascent / 2 - 1)
            g2.color = Theme.series(t.colorIndex)
            g2.fillOval(6, y + h / 2 - 4, 8, 8)
            g2.color = Theme.track
            g2.fill(RoundRectangle2D.Double(left.toDouble(), y.toDouble(), plotW.toDouble(), h.toDouble(), 6.0, 6.0))
            if (plotW <= 0) return@forEachIndexed
            val c = aggregate(t, start, end, plotW)
            val slow = slowThreshold(t)
            val good = Theme.alpha(Theme.good, 0.75)
            val warn = Theme.warn
            val bad = Theme.bad
            // Each sample fills the space up to the next one, so the strip reads as a continuous bar.
            val pxPerProbe = plotW.toDouble() * engine.intervalMs / (end - start).coerceAtLeast(1)
            val fill = kotlin.math.ceil(pxPerProbe).toInt().coerceIn(1, 40)
            for (col in 0 until plotW) {
                if (!c.has[col]) continue
                var next = col + 1
                while (next < plotW && next - col < fill && !c.has[next]) next++
                g2.color = when {
                    c.lost[col] -> bad
                    !c.max[col].isNaN() && c.max[col] > slow -> warn
                    else -> good
                }
                // Widen single-pixel loss events slightly so they remain visible.
                val extra = if (c.lost[col] && next - col < 3) 1 else 0
                g2.fillRect(left + col - extra, y, next - col + extra * 2, h)
            }
        }
        state.hoverTime?.let { ht ->
            if (ht in start..end && end > start) {
                val hx = left + ((ht - start).toDouble() / (end - start) * plotW)
                g2.color = Theme.alpha(Theme.foreground, 0.35)
                g2.draw(Line2D.Double(hx, 0.0, hx, height.toDouble()))
            }
        }
        g2.dispose()
    }

    companion object { const val ROW = 20 }
}

/** Small area chart of Wi-Fi signal strength over time. */
class SignalChart(private val engine: MonitorEngine) : JComponent() {
    init { preferredSize = Dimension(400, 140) }

    override fun paintComponent(g: Graphics) {
        val g2 = Theme.smooth(g)
        val left = 40; val right = width - 10; val top = 8; val bottom = height - 20
        val plotW = right - left; val plotH = bottom - top
        g2.font = Theme.font(Font.PLAIN, -1.5f)
        val fm = g2.fontMetrics
        for (v in listOf(0, 25, 50, 75, 100)) {
            val y = bottom - v / 100.0 * plotH
            g2.color = Theme.grid
            g2.draw(Line2D.Double(left.toDouble(), y, right.toDouble(), y))
            g2.color = Theme.muted
            g2.drawString("$v%", left - 6 - fm.stringWidth("$v%"), (y + fm.ascent / 2.5).toInt())
        }
        val hist = engine.wifiHistory.toList()
        if (hist.size < 2 || plotW <= 0) {
            g2.color = Theme.muted
            val msg = if (engine.wifi == null) "Not connected via Wi-Fi" else "Signal history appears while monitoring"
            g2.drawString(msg, left + (plotW - fm.stringWidth(msg)) / 2, top + plotH / 2)
            g2.dispose(); return
        }
        val start = hist.first().time; val end = maxOf(hist.last().time, start + 1)
        fun x(t: Long) = left + (t - start).toDouble() / (end - start) * plotW
        fun y(v: Int) = bottom - v / 100.0 * plotH
        val line = Path2D.Double()
        val area = Path2D.Double()
        area.moveTo(x(hist.first().time), bottom.toDouble())
        hist.forEachIndexed { i, s ->
            if (i == 0) line.moveTo(x(s.time), y(s.signal)) else line.lineTo(x(s.time), y(s.signal))
            area.lineTo(x(s.time), y(s.signal))
        }
        area.lineTo(x(hist.last().time), bottom.toDouble()); area.closePath()
        val color = Theme.series(0)
        g2.paint = java.awt.GradientPaint(0f, top.toFloat(), Theme.alpha(color, 0.35), 0f, bottom.toFloat(), Theme.alpha(color, 0.02))
        g2.fill(area)
        g2.color = color
        g2.stroke = BasicStroke(1.8f)
        g2.draw(line)
        // Roaming events
        g2.color = Theme.warn
        for (i in 1 until hist.size) if (hist[i].bssid != hist[i - 1].bssid) {
            val xx = x(hist[i].time)
            g2.draw(Line2D.Double(xx, top.toDouble(), xx, bottom.toDouble()))
        }
        g2.color = Theme.muted
        g2.drawString(timeFmt.format(Date(start)), left, bottom + fm.ascent + 4)
        val e = timeFmt.format(Date(end))
        g2.drawString(e, right - fm.stringWidth(e), bottom + fm.ascent + 4)
        g2.dispose()
    }

}
