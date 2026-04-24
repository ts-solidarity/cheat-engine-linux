#include "gui/stackview.hpp"

#include "platform/linux/ptrace_wrapper.hpp"

#include <QFont>
#include <QHeaderView>
#include <QPushButton>
#include <QVBoxLayout>

namespace ce::gui {

StackViewWindow::StackViewWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Stack View");
    resize(700, 500);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    threadCombo_ = new QComboBox;
    layout->addWidget(threadCombo_);

    auto* refreshButton = new QPushButton("Refresh");
    connect(refreshButton, &QPushButton::clicked, this, &StackViewWindow::refreshStack);
    layout->addWidget(refreshButton);

    statusLabel_ = new QLabel;
    layout->addWidget(statusLabel_);

    table_ = new QTableWidget;
    table_->setColumnCount(3);
    table_->setHorizontalHeaderLabels({"Address", "Value", "Offset"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setFont(QFont("Monospace", 9));
    layout->addWidget(table_);

    setCentralWidget(central);
    populateThreads();
    refreshStack();
}

void StackViewWindow::populateThreads() {
    threadCombo_->clear();
    if (!proc_) return;

    for (const auto& thread : proc_->threads())
        threadCombo_->addItem(QString::number(thread.tid), QVariant::fromValue((qlonglong)thread.tid));
}

void StackViewWindow::refreshStack() {
    table_->setRowCount(0);
    if (!proc_ || threadCombo_->currentIndex() < 0) return;

    auto tid = (pid_t)threadCombo_->currentData().toLongLong();

    os::LinuxDebugger debugger;
    auto attached = debugger.attach(proc_->pid());
    if (!attached) {
        statusLabel_->setText("Could not attach to process for stack context.");
        return;
    }

    auto context = debugger.getContext(tid);
    debugger.detach();
    if (!context) {
        statusLabel_->setText("Could not read thread context.");
        return;
    }

    constexpr int rows = 32;
    table_->setRowCount(rows);
    for (int i = 0; i < rows; ++i) {
        auto address = context->rsp + (uintptr_t)i * sizeof(uintptr_t);
        uintptr_t value = 0;
        auto read = proc_->read(address, &value, sizeof(value));

        table_->setItem(i, 0, new QTableWidgetItem(QString("%1").arg(address, 16, 16, QChar('0'))));
        table_->setItem(i, 1, new QTableWidgetItem(read ? QString("%1").arg(value, 16, 16, QChar('0')) : "??"));
        table_->setItem(i, 2, new QTableWidgetItem(QString("+0x%1").arg(i * (int)sizeof(uintptr_t), 0, 16)));
    }

    statusLabel_->setText(QString("TID %1 RSP=0x%2").arg(tid).arg(context->rsp, 0, 16));
}

} // namespace ce::gui
