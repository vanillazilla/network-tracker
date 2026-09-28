package com.networktracker

import com.formdev.flatlaf.themes.FlatMacDarkLaf
import com.formdev.flatlaf.themes.FlatMacLightLaf
import com.networktracker.monitor.MonitorEngine
import com.networktracker.ui.MainWindow
import com.networktracker.ui.Settings
import java.security.Security
import javax.swing.UIManager

fun main() {
    // Always resolve host names fresh so DNS changes are picked up while monitoring.
    Security.setProperty("networkaddress.cache.ttl", "30")
    Security.setProperty("networkaddress.cache.negative.ttl", "5")

    UIManager.put("Component.arc", 10)
    UIManager.put("Button.arc", 10)
    UIManager.put("TextComponent.arc", 10)
    UIManager.put("ScrollBar.thumbArc", 999)
    UIManager.put("ScrollBar.thumbInsets", java.awt.Insets(2, 2, 2, 2))
    UIManager.put("ScrollBar.width", 12)
    UIManager.put("Table.showHorizontalLines", true)
    UIManager.put("Table.intercellSpacing", java.awt.Dimension(0, 1))
    UIManager.put("TableHeader.height", 30)
    UIManager.put("TabbedPane.tabHeight", 38)
    UIManager.put("TabbedPane.selectedBackground", null)
    UIManager.put("SplitPaneDivider.style", "plain")
    UIManager.put("TitlePane.unifiedBackground", true)

    if (Settings.dark) FlatMacDarkLaf.setup() else FlatMacLightLaf.setup()

    MainWindow.launch(MonitorEngine())
}
