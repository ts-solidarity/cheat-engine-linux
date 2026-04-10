#include "gui/processlistdialog.hpp"
#include "platform/linux/linux_process.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFont>

namespace ce::gui {

ProcessListDialog::ProcessListDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Open Process");
    resize(400, 500);

    auto* layout = new QVBoxLayout(this);

    // Filter
    filterEdit_ = new QLineEdit;
    filterEdit_->setPlaceholderText("Filter...");
    connect(filterEdit_, &QLineEdit::textChanged, this, &ProcessListDialog::onFilter);
    layout->addWidget(filterEdit_);

    // Tabs
    tabs_ = new QTabWidget;
    processList_ = new QListWidget;
    processList_->setFont(QFont("Monospace", 9));
    connect(processList_, &QListWidget::itemDoubleClicked, this, &ProcessListDialog::onAccept);

    tabs_->addTab(processList_, "Processes");
    layout->addWidget(tabs_);

    // Buttons
    auto* btnLayout = new QHBoxLayout;
    auto* openBtn = new QPushButton("Open");
    openBtn->setDefault(true);
    auto* cancelBtn = new QPushButton("Cancel");
    auto* refreshBtn = new QPushButton("Refresh");
    connect(openBtn, &QPushButton::clicked, this, &ProcessListDialog::onAccept);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    connect(refreshBtn, &QPushButton::clicked, this, &ProcessListDialog::refreshList);
    btnLayout->addStretch();
    btnLayout->addWidget(openBtn);
    btnLayout->addWidget(cancelBtn);
    btnLayout->addWidget(refreshBtn);
    layout->addLayout(btnLayout);

    refreshList();
}

void ProcessListDialog::refreshList() {
    processList_->clear();
    os::LinuxProcessEnumerator enumerator;
    auto procs = enumerator.list();

    for (auto& p : procs) {
        auto text = QString("%1 - %2").arg(p.pid, 8, 16, QChar('0')).arg(QString::fromStdString(p.name));
        auto* item = new QListWidgetItem(text);
        item->setData(Qt::UserRole, QVariant::fromValue((qlonglong)p.pid));
        item->setData(Qt::UserRole + 1, QString::fromStdString(p.name));
        processList_->addItem(item);
    }

    // Scroll to bottom (newest processes)
    processList_->scrollToBottom();
}

void ProcessListDialog::onAccept() {
    auto* item = processList_->currentItem();
    if (!item) return;
    selectedPid_ = item->data(Qt::UserRole).toLongLong();
    selectedName_ = item->data(Qt::UserRole + 1).toString();
    accept();
}

void ProcessListDialog::onFilter(const QString& text) {
    for (int i = 0; i < processList_->count(); ++i) {
        auto* item = processList_->item(i);
        item->setHidden(!text.isEmpty() && !item->text().contains(text, Qt::CaseInsensitive));
    }
}

} // namespace ce::gui
