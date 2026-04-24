#include "gui/registereditor.hpp"

#include "platform/linux/ptrace_wrapper.hpp"

#include <QFont>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QPushButton>
#include <QVBoxLayout>
#include <iterator>

namespace ce::gui {
namespace {

struct RegisterField {
    const char* name;
    uint64_t CpuContext::*member;
};

constexpr RegisterField kRegisters[] = {
    {"RAX", &CpuContext::rax}, {"RBX", &CpuContext::rbx}, {"RCX", &CpuContext::rcx},
    {"RDX", &CpuContext::rdx}, {"RSI", &CpuContext::rsi}, {"RDI", &CpuContext::rdi},
    {"RBP", &CpuContext::rbp}, {"RSP", &CpuContext::rsp}, {"RIP", &CpuContext::rip},
    {"R8", &CpuContext::r8},   {"R9", &CpuContext::r9},   {"R10", &CpuContext::r10},
    {"R11", &CpuContext::r11}, {"R12", &CpuContext::r12}, {"R13", &CpuContext::r13},
    {"R14", &CpuContext::r14}, {"R15", &CpuContext::r15}, {"RFLAGS", &CpuContext::rflags},
};

QString hexValue(uint64_t value) {
    return QString("%1").arg(value, 16, 16, QChar('0'));
}

} // namespace

RegisterEditorWindow::RegisterEditorWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Register Editor");
    resize(420, 620);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    threadCombo_ = new QComboBox;
    layout->addWidget(threadCombo_);

    auto* buttons = new QHBoxLayout;
    auto* refreshButton = new QPushButton("Refresh");
    auto* applyButton = new QPushButton("Apply");
    buttons->addWidget(refreshButton);
    buttons->addWidget(applyButton);
    layout->addLayout(buttons);
    connect(refreshButton, &QPushButton::clicked, this, &RegisterEditorWindow::refreshRegisters);
    connect(applyButton, &QPushButton::clicked, this, &RegisterEditorWindow::applyRegisters);

    statusLabel_ = new QLabel;
    layout->addWidget(statusLabel_);

    table_ = new QTableWidget;
    table_->setColumnCount(2);
    table_->setHorizontalHeaderLabels({"Register", "Value"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setFont(QFont("Monospace", 9));
    table_->setRowCount((int)std::size(kRegisters));
    for (int row = 0; row < (int)std::size(kRegisters); ++row) {
        auto* name = new QTableWidgetItem(kRegisters[row].name);
        name->setFlags(name->flags() & ~Qt::ItemIsEditable);
        table_->setItem(row, 0, name);
        table_->setItem(row, 1, new QTableWidgetItem("0"));
    }
    layout->addWidget(table_);

    setCentralWidget(central);
    populateThreads();
    refreshRegisters();
}

void RegisterEditorWindow::populateThreads() {
    threadCombo_->clear();
    if (!proc_) return;

    for (const auto& thread : proc_->threads())
        threadCombo_->addItem(QString::number(thread.tid), QVariant::fromValue((qlonglong)thread.tid));
}

void RegisterEditorWindow::refreshRegisters() {
    if (!proc_ || threadCombo_->currentIndex() < 0) return;

    auto tid = (pid_t)threadCombo_->currentData().toLongLong();
    os::LinuxDebugger debugger;
    auto attached = debugger.attach(proc_->pid());
    if (!attached) {
        statusLabel_->setText("Could not attach to process.");
        return;
    }

    auto context = debugger.getContext(tid);
    debugger.detach();
    if (!context) {
        statusLabel_->setText("Could not read thread context.");
        return;
    }

    context_ = *context;
    for (int row = 0; row < (int)std::size(kRegisters); ++row)
        table_->item(row, 1)->setText(hexValue(context_.*(kRegisters[row].member)));
    statusLabel_->setText(QString("Loaded TID %1").arg(tid));
}

void RegisterEditorWindow::applyRegisters() {
    if (!proc_ || threadCombo_->currentIndex() < 0) return;

    CpuContext updated = context_;
    for (int row = 0; row < (int)std::size(kRegisters); ++row) {
        bool ok = false;
        auto value = table_->item(row, 1)->text().toULongLong(&ok, 16);
        if (!ok) {
            statusLabel_->setText(QString("Invalid %1 value.").arg(kRegisters[row].name));
            return;
        }
        updated.*(kRegisters[row].member) = value;
    }

    auto tid = (pid_t)threadCombo_->currentData().toLongLong();
    os::LinuxDebugger debugger;
    auto attached = debugger.attach(proc_->pid());
    if (!attached) {
        statusLabel_->setText("Could not attach to process.");
        return;
    }

    auto applied = debugger.setContext(tid, updated);
    debugger.detach();
    if (!applied) {
        statusLabel_->setText("Could not apply register context.");
        return;
    }

    context_ = updated;
    statusLabel_->setText(QString("Applied TID %1").arg(tid));
}

} // namespace ce::gui
