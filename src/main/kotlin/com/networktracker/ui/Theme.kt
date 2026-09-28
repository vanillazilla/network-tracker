package com.networktracker.ui

import com.formdev.flatlaf.FlatLaf
import com.networktracker.monitor.Health
import com.networktracker.monitor.Severity
import java.awt.BasicStroke
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Image
import java.awt.RenderingHints
import java.awt.geom.Path2D
import java.awt.geom.RoundRectangle2D
import java.awt.image.BufferedImage
import javax.swing.BorderFactory
import javax.swing.Icon
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.UIManager

object Theme {
    val isDark get() = FlatLaf.isLafDark()

    private val seriesDark = listOf(
        0x5B9BFF, 0x2EC4B6, 0xB18CFF, 0xFFA94D, 0xFF6B9A, 0xA3D65C, 0x3BC9DB, 0xFFD43B, 0xE599F7, 0x94D82D,
    ).map(::Color)
    private val seriesLight = listOf(
        0x1F6FEB, 0x0E9F8E, 0x7C4DDB, 0xE8590C, 0xD6336C, 0x5C940D, 0x1098AD, 0xC08A00, 0xAE3EC9, 0x2B8A3E,
    ).map(::Color)

    fun series(i: Int): Color = (if (isDark) seriesDark else seriesLight)[i % seriesDark.size]

    val good get() = if (isDark) Color(0x34C77B) else Color(0x1A9F5A)
    val warn get() = if (isDark) Color(0xF5A524) else Color(0xD08700)
    val bad get() = if (isDark) Color(0xF4544C) else Color(0xD92D20)
    val unknown get() = if (isDark) Color(0x6E7681) else Color(0x98A2B3)
    val accent get() = if (isDark) Color(0x3B82F6) else Color(0x2563EB)

    fun health(h: Health) = when (h) {
        Health.GOOD -> good; Health.WARN -> warn; Health.BAD -> bad; Health.UNKNOWN -> unknown
    }

    fun severity(s: Severity) = when (s) {
        Severity.INFO -> accent; Severity.SUCCESS -> good; Severity.WARNING -> warn; Severity.ERROR -> bad
    }

    val background: Color get() = UIManager.getColor("Panel.background")
    val card: Color get() = if (isDark) blend(background, Color.WHITE, 0.035) else Color.WHITE
    val foreground: Color get() = UIManager.getColor("Label.foreground")
    val muted: Color get() = UIManager.getColor("Label.disabledForeground") ?: blend(foreground, background, 0.45)
    val border: Color get() = if (isDark) blend(background, Color.WHITE, 0.10) else blend(background, Color.BLACK, 0.10)
    val grid: Color get() = if (isDark) blend(card, Color.WHITE, 0.07) else blend(card, Color.BLACK, 0.07)
    val track: Color get() = if (isDark) blend(card, Color.WHITE, 0.05) else blend(card, Color.BLACK, 0.045)

    fun blend(a: Color, b: Color, t: Double): Color = Color(
        (a.red + (b.red - a.red) * t).toInt().coerceIn(0, 255),
        (a.green + (b.green - a.green) * t).toInt().coerceIn(0, 255),
        (a.blue + (b.blue - a.blue) * t).toInt().coerceIn(0, 255),
    )

    fun alpha(c: Color, a: Double) = Color(c.red, c.green, c.blue, (a * 255).toInt().coerceIn(0, 255))

    fun hex(c: Color) = "#%02x%02x%02x".format(c.red, c.green, c.blue)

    fun font(style: Int = Font.PLAIN, delta: Float = 0f): Font {
        val base = UIManager.getFont("Label.font")
        return base.deriveFont(style, base.size2D + delta)
    }

    fun smooth(g: Graphics): Graphics2D = (g.create() as Graphics2D).apply {
        setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB)
        setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)
        setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
    }

    /** Application icon: a rounded tile with a pulse line. */
    fun appIcons(): List<Image> = listOf(16, 24, 32, 48, 64, 128, 256).map { size ->
        BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB).also { img ->
            val g = smooth(img.graphics)
            val s = size.toFloat()
            g.paint = java.awt.GradientPaint(0f, 0f, Color(0x3B82F6), s, s, Color(0x2EC4B6))
            g.fill(RoundRectangle2D.Float(0f, 0f, s, s, s * 0.45f, s * 0.45f))
            g.color = Color.WHITE
            g.stroke = BasicStroke(maxOf(1.5f, s * 0.08f), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            val p = Path2D.Float()
            p.moveTo(s * 0.14, s * 0.55); p.lineTo(s * 0.34, s * 0.55); p.lineTo(s * 0.44, s * 0.28)
            p.lineTo(s * 0.57, s * 0.76); p.lineTo(s * 0.67, s * 0.50); p.lineTo(s * 0.86, s * 0.50)
            g.draw(p)
            g.dispose()
        }
    }
}

/** Small filled circle, used as a status indicator in labels and tables. */
class DotIcon(private val color: () -> Color, private val size: Int = 9) : Icon {
    override fun paintIcon(c: Component?, g: Graphics, x: Int, y: Int) {
        val g2 = Theme.smooth(g)
        g2.color = color()
        g2.fillOval(x, y, size, size)
        g2.dispose()
    }
    override fun getIconWidth() = size
    override fun getIconHeight() = size
}

/** Rounded surface with an optional header row (title on the left, custom actions on the right). */
open class Card(title: String? = null, content: JComponent? = null, actions: JComponent? = null) : JPanel(BorderLayout()) {
    val titleLabel = JLabel(title ?: "")

    init {
        isOpaque = false
        border = BorderFactory.createEmptyBorder(12, 14, 12, 14)
        if (title != null || actions != null) {
            val header = JPanel(BorderLayout()).apply {
                isOpaque = false
                border = BorderFactory.createEmptyBorder(0, 0, 8, 0)
                titleLabel.font = Theme.font(Font.BOLD, 1f)
                add(titleLabel, BorderLayout.WEST)
                if (actions != null) add(actions, BorderLayout.EAST)
            }
            add(header, BorderLayout.NORTH)
        }
        if (content != null) add(content, BorderLayout.CENTER)
    }

    override fun updateUI() {
        super.updateUI()
        @Suppress("SENSELESS_COMPARISON")
        if (titleLabel != null) titleLabel.font = Theme.font(Font.BOLD, 1f)
    }

    override fun paintComponent(g: Graphics) {
        val g2 = Theme.smooth(g)
        val shape = RoundRectangle2D.Float(0.5f, 0.5f, width - 1f, height - 1f, 14f, 14f)
        g2.color = Theme.card
        g2.fill(shape)
        g2.color = Theme.border
        g2.draw(shape)
        g2.dispose()
    }
}
