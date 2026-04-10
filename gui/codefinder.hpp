#pragma once
#include "debug/code_finder.hpp"
#include <QMainWindow>
#include <QTableWidget>
#include <QLabel>
#include <QPushButton>
#include <QTimer>

namespace ce::gui {

class CodeFinderWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit CodeFinderWindow(ce::CodeFinder* finder, const QString& title, QWidget* parent = nullptr);

private slots:
    void refresh();
    void onStop();

private:
    ce::CodeFinder* finder_;
    QTableWidget* table_;
    QLabel* statusLabel_;
    QPushButton* stopBtn_;
    QTimer* refreshTimer_;
};

} // namespace ce::gui
