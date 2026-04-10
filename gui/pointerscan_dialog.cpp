#include "gui/pointerscan_dialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFont>

namespace ce::gui {

PointerScanDialog::PointerScanDialog(ProcessHandle* proc, QWidget* parent)
    : QDialog(parent), proc_(proc) {
    setWindowTitle("Pointer Scanner");
    resize(700, 500);

    auto* layout = new QVBoxLayout(this);

    // Config row
    auto* configRow = new QHBoxLayout;
    configRow->addWidget(new QLabel("Target Address:"));
    targetEdit_ = new QLineEdit;
    targetEdit_->setFont(QFont("Monospace", 10));
    targetEdit_->setPlaceholderText("0x7f1234");
    configRow->addWidget(targetEdit_);

    configRow->addWidget(new QLabel("Depth:"));
    depthSpin_ = new QSpinBox;
    depthSpin_->setRange(1, 7);
    depthSpin_->setValue(4);
    configRow->addWidget(depthSpin_);

    configRow->addWidget(new QLabel("Max Offset:"));
    offsetSpin_ = new QSpinBox;
    offsetSpin_->setRange(64, 65536);
    offsetSpin_->setValue(2048);
    offsetSpin_->setSingleStep(256);
    configRow->addWidget(offsetSpin_);

    scanBtn_ = new QPushButton("Scan");
    scanBtn_->setStyleSheet("font-weight: bold;");
    connect(scanBtn_, &QPushButton::clicked, this, &PointerScanDialog::onScan);
    configRow->addWidget(scanBtn_);
    layout->addLayout(configRow);

    statusLabel_ = new QLabel("Ready");
    layout->addWidget(statusLabel_);

    // Results table
    resultsTable_ = new QTableWidget;
    resultsTable_->setColumnCount(3);
    resultsTable_->setHorizontalHeaderLabels({"Path", "Current Address", "Value"});
    resultsTable_->horizontalHeader()->setStretchLastSection(true);
    resultsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable_->setFont(QFont("Monospace", 9));
    resultsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(resultsTable_, &QTableWidget::cellDoubleClicked, this, &PointerScanDialog::onResultDoubleClicked);
    layout->addWidget(resultsTable_);
}

void PointerScanDialog::onScan() {
    if (!proc_) return;

    bool ok;
    uintptr_t target = targetEdit_->text().toULongLong(&ok, 16);
    if (!ok) { statusLabel_->setText("Invalid address"); return; }

    scanBtn_->setEnabled(false);
    statusLabel_->setText("Scanning...");
    resultsTable_->setRowCount(0);

    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = depthSpin_->value();
    config.maxOffset = offsetSpin_->value();

    PointerScanner scanner;
    results_ = scanner.scan(*proc_, config);

    resultsTable_->setRowCount(std::min(results_.size(), size_t(1000)));
    for (size_t i = 0; i < std::min(results_.size(), size_t(1000)); ++i) {
        auto& p = results_[i];
        resultsTable_->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(p.toString())));

        auto addr = PointerScanner::dereference(*proc_, p);
        resultsTable_->setItem(i, 1, new QTableWidgetItem(
            addr ? QString("0x%1").arg(addr, 0, 16) : "??"));

        if (addr) {
            int32_t val = 0;
            proc_->read(addr, &val, 4);
            resultsTable_->setItem(i, 2, new QTableWidgetItem(QString::number(val)));
        }
    }

    statusLabel_->setText(QString("Found %1 paths").arg(results_.size()));
    scanBtn_->setEnabled(true);
}

void PointerScanDialog::onResultDoubleClicked(int row, int) {
    if (row < 0 || row >= (int)results_.size()) return;
    auto addr = PointerScanner::dereference(*proc_, results_[row]);
    if (addr)
        emit addressSelected(addr, QString::fromStdString(results_[row].toString()));
}

} // namespace ce::gui
