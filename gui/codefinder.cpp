#include "gui/codefinder.hpp"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QFont>

namespace ce::gui {

CodeFinderWindow::CodeFinderWindow(CodeFinder* finder, const QString& title, QWidget* parent)
    : QMainWindow(parent), finder_(finder) {
    setWindowTitle(title);
    resize(700, 400);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    statusLabel_ = new QLabel("Monitoring...");
    layout->addWidget(statusLabel_);

    table_ = new QTableWidget;
    table_->setColumnCount(3);
    table_->setHorizontalHeaderLabels({"Address", "Instruction", "Hits"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setFont(QFont("Monospace", 9));
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table_);

    stopBtn_ = new QPushButton("Stop");
    connect(stopBtn_, &QPushButton::clicked, this, &CodeFinderWindow::onStop);
    layout->addWidget(stopBtn_);

    setCentralWidget(central);

    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &CodeFinderWindow::refresh);
    refreshTimer_->start(500);
}

void CodeFinderWindow::refresh() {
    auto results = finder_->results();
    statusLabel_->setText(finder_->running()
        ? QString("Monitoring... %1 unique instructions found").arg(results.size())
        : QString("Stopped. %1 unique instructions found").arg(results.size()));

    table_->setRowCount(results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        auto& r = results[i];
        table_->setItem(i, 0, new QTableWidgetItem(QString("0x%1").arg(r.instructionAddress, 0, 16)));
        table_->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(r.instructionText)));
        table_->setItem(i, 2, new QTableWidgetItem(QString::number(r.hitCount)));
    }
}

void CodeFinderWindow::onStop() {
    finder_->stop();
    stopBtn_->setEnabled(false);
    statusLabel_->setText(QString("Stopped. %1 unique instructions found").arg(finder_->results().size()));
}

} // namespace ce::gui
