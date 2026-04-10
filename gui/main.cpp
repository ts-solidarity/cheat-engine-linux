#include "gui/mainwindow.hpp"
#include <QApplication>

static const char* darkStyleSheet = R"(
    QWidget { background-color: #1e1e2e; color: #cdd6f4; }
    QMenuBar { background-color: #181825; color: #cdd6f4; }
    QMenuBar::item:selected { background-color: #313244; }
    QMenu { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a; }
    QMenu::item:selected { background-color: #313244; }
    QPushButton { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                  padding: 4px 12px; border-radius: 4px; }
    QPushButton:hover { background-color: #45475a; }
    QPushButton:pressed { background-color: #585b70; }
    QPushButton:disabled { color: #585b70; }
    QLineEdit, QSpinBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                          padding: 3px; border-radius: 3px; }
    QComboBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                padding: 3px; border-radius: 3px; }
    QComboBox QAbstractItemView { background-color: #1e1e2e; color: #cdd6f4; selection-background-color: #313244; }
    QComboBox::drop-down { border: none; }
    QTableView, QListWidget, QTableWidget { background-color: #181825; color: #cdd6f4;
        gridline-color: #313244; selection-background-color: #313244; alternate-background-color: #1e1e2e; }
    QHeaderView::section { background-color: #181825; color: #a6adc8; border: 1px solid #313244; padding: 4px; }
    QSplitter::handle { background-color: #313244; }
    QGroupBox { color: #a6adc8; border: 1px solid #45475a; border-radius: 4px; margin-top: 8px; padding-top: 8px; }
    QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
    QCheckBox { color: #cdd6f4; }
    QLabel { color: #cdd6f4; }
    QProgressBar { background-color: #313244; border: 1px solid #45475a; border-radius: 3px; text-align: center; }
    QProgressBar::chunk { background-color: #89b4fa; border-radius: 3px; }
    QToolBar { background-color: #181825; border: none; spacing: 4px; }
    QTabWidget::pane { border: 1px solid #45475a; }
    QTabBar::tab { background-color: #181825; color: #a6adc8; padding: 6px 12px; border: 1px solid #45475a; }
    QTabBar::tab:selected { background-color: #313244; color: #cdd6f4; }
    QPlainTextEdit, QTextEdit { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a; }
    QScrollBar:vertical { background: #181825; width: 10px; }
    QScrollBar::handle:vertical { background: #45475a; border-radius: 5px; min-height: 20px; }
    QScrollBar:horizontal { background: #181825; height: 10px; }
    QScrollBar::handle:horizontal { background: #45475a; border-radius: 5px; min-width: 20px; }
    QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
)";

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("Cheat Engine");
    app.setOrganizationName("cecore");
    app.setStyleSheet(darkStyleSheet);

    ce::gui::MainWindow w;
    w.show();

    return app.exec();
}
