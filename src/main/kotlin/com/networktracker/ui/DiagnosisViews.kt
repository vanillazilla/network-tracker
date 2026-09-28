package com.networktracker.ui

import com.networktracker.monitor.Diagnosis
import com.networktracker.monitor.Health
import com.networktracker.monitor.TierStatus
import java.awt.BasicStroke
import java.awt.Dimension
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Point
import java.awt.geom.Line2D
import java.awt.geom.Path2D
import java.awt.geom.RoundRectangle2D
import javax.swing.BorderFactory
import javax.swing.JComponent
import javax.swing.JEditorPane
import javax.swing.JScrollPane
import javax.swing.SwingUtilities

/** "This PC → Router → ISP → Internet → …" with each stage coloured by its health. */
class PathDiagram : JComponent() {
    var tiers: List<TierStatus> = emptyList()
        set(value) { field = value; repaint() }

    init { preferredSize = Dimension(800, 96) }

    override fun paintComponent(g: Graphics) {
        val g2 = Theme.smooth(g)
        val n = tiers.size
        if (n == 0) { g2.dispose(); return }
        val gap = 30
        val w = ((width - gap * (n - 1)) / n).coerceAtLeast(60)
        val h = height - 4
        tiers.forEachIndexed { i, tier ->
            val x = i * (w + gap)
            drawNode(g2, tier, x, 2, w, h)
            if (i < n - 1) {
                val next = tiers[i + 1]
                val dashed = next.title == "DNS" || next.title == "Your Targets"
                drawArrow(g2, x + w + 4, 2 + h / 2, x + w + gap - 4, Theme.health(next.health), dashed)
            }
        }
        g2.dispose()
    }

    private fun drawNode(g2: Graphics2D, t: TierStatus, x: Int, y: Int, w: Int, h: Int) {
        val color = Theme.health(t.health)
        val shape = RoundRectangle2D.Double(x + 0.5, y + 0.5, w - 1.0, h - 1.0, 14.0, 14.0)
        g2.color = Theme.card
        g2.fill(shape)
        g2.color = Theme.alpha(color, if (t.health == Health.UNKNOWN) 0.35 else 0.75)
        g2.stroke = BasicStroke(1.3f)
        g2.draw(shape)
        // Health accent bar across the top
        val clip = g2.clip
        g2.clip(shape)
        g2.color = color
        g2.fillRect(x, y, w, 4)
        g2.clip = clip

        val pad = 12
        var ty = y + 12
        g2.font = Theme.font(Font.BOLD, 0.5f)
        var fm = g2.fontMetrics
        g2.color = Theme.foreground
        ty += fm.ascent
        g2.drawString(fit(t.title, fm, w - pad * 2 - 16), x + pad, ty)
        g2.color = color
        g2.fillOval(x + w - pad - 9, ty - fm.ascent / 2 - 5, 10, 10)

        g2.font = Theme.font(Font.PLAIN, -1.5f)
        fm = g2.fontMetrics
        g2.color = Theme.muted
        ty += fm.height + 1
        g2.drawString(fit(t.subtitle, fm, w - pad * 2), x + pad, ty)

        g2.font = Theme.font(Font.BOLD, 1.5f)
        fm = g2.fontMetrics
        ty += fm.height + 2
        g2.color = if (t.health == Health.UNKNOWN) Theme.muted else color
        g2.drawString(fit(t.primary, fm, w - pad * 2), x + pad, ty)
        g2.font = Theme.font(Font.PLAIN, -1.5f)
        val pw = fm.stringWidth(fit(t.primary, fm, w - pad * 2))
        val fm2 = g2.fontMetrics
        g2.color = Theme.muted
        val rest = w - pad * 2 - pw - 8
        if (rest > 30) g2.drawString(fit(t.secondary, fm2, rest), x + pad + pw + 8, ty)
    }

    private fun drawArrow(g2: Graphics2D, x1: Int, y: Int, x2: Int, color: java.awt.Color, dashed: Boolean) {
        g2.color = Theme.alpha(color, 0.8)
        g2.stroke = if (dashed) BasicStroke(1.6f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 1f, floatArrayOf(3f, 4f), 0f)
        else BasicStroke(1.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
        g2.draw(Line2D.Double(x1.toDouble(), y.toDouble(), x2 - 3.0, y.toDouble()))
        val head = Path2D.Double()
        head.moveTo(x2.toDouble(), y.toDouble()); head.lineTo(x2 - 7.0, y - 4.5); head.lineTo(x2 - 7.0, y + 4.5); head.closePath()
        g2.fill(head)
    }

    private fun fit(s: String, fm: java.awt.FontMetrics, maxW: Int): String {
        if (fm.stringWidth(s) <= maxW) return s
        var t = s
        while (t.isNotEmpty() && fm.stringWidth("$t…") > maxW) t = t.dropLast(1)
        return "$t…"
    }
}

/** Human-readable verdict, findings and recommendations. */
class DiagnosisView : JScrollPane() {
    private val pane = JEditorPane().apply {
        isEditable = false
        contentType = "text/html"
        putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true)
        isOpaque = false
    }
    private var lastHtml = ""

    init {
        setViewportView(pane)
        applyStyle()
        horizontalScrollBarPolicy = HORIZONTAL_SCROLLBAR_NEVER
        verticalScrollBar.unitIncrement = 16
    }

    fun show(d: Diagnosis) {
        val html = render(d)
        if (html == lastHtml) return
        lastHtml = html
        val pos = viewport.viewPosition
        pane.text = html
        SwingUtilities.invokeLater { viewport.viewPosition = Point(pos) }
    }

    override fun updateUI() {
        super.updateUI()
        @Suppress("SENSELESS_COMPARISON")
        if (pane != null) {
            lastHtml = "" // force re-render with the new theme colours
            applyStyle()
        }
    }

    // Non-null, non-UIResource borders so a theme switch doesn't reinstall the default ones.
    private fun applyStyle() {
        border = BorderFactory.createEmptyBorder()
        viewportBorder = BorderFactory.createEmptyBorder()
        isOpaque = false
        viewport.isOpaque = false
    }

    private fun render(d: Diagnosis): String {
        val c = Theme.health(d.health)
        val fg = Theme.hex(Theme.foreground)
        val muted = Theme.hex(Theme.muted)
        val font = Theme.font()
        val icon = when (d.health) { Health.GOOD -> "✔"; Health.WARN -> "!"; Health.BAD -> "✖"; Health.UNKNOWN -> "…" }
        val badge = when (d.health) { Health.GOOD -> "HEALTHY"; Health.WARN -> "DEGRADED"; Health.BAD -> "PROBLEM FOUND"; Health.UNKNOWN -> "ANALYSING" }
        return buildString {
            append("<html><body style='font-family:\"${font.family}\"; font-size:${font.size}pt; color:$fg; margin:0'>")
            append("<div style='color:${Theme.hex(c)}; font-size:${font.size - 2}pt; font-weight:bold'>$icon&nbsp; $badge</div>")
            append("<div style='font-size:${font.size + 4}pt; font-weight:bold; margin-top:4px'>${esc(d.headline)}</div>")
            append("<div style='margin-top:6px'>${esc(d.explanation)}</div>")
            if (d.recommendations.isNotEmpty()) {
                append("<div style='margin-top:14px; font-weight:bold'>What to try</div>")
                append("<ol style='margin-top:4px; margin-left:18px'>")
                d.recommendations.forEach { append("<li style='margin-bottom:3px'>${esc(it)}</li>") }
                append("</ol>")
            }
            if (d.findings.isNotEmpty()) {
                append("<div style='margin-top:12px; font-weight:bold'>Measurements</div>")
                append("<table cellpadding='2' cellspacing='0' style='margin-top:4px'>")
                d.findings.forEach {
                    append("<tr><td valign='top' style='color:${Theme.hex(Theme.health(it.health))}'>●</td>")
                    append("<td style='color:${if (it.health == Health.UNKNOWN) muted else fg}'>${esc(it.text)}</td></tr>")
                }
                append("</table>")
            }
            append("</body></html>")
        }
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}
