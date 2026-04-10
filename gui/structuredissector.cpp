#include "gui/structuredissector.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QFont>
#include <cstring>
#include <cmath>

namespace ce::gui {

StructureDissector::StructureDissector(ProcessHandle* proc, uintptr_t baseAddr, QWidget* parent)
    : QMainWindow(parent), proc_(proc), baseAddr_(baseAddr) {

    setWindowTitle("Structure Dissector");
    resize(750, 600);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    // Address bar
    auto* addrRow = new QHBoxLayout;
    addrRow->addWidget(new QLabel("Base Address:"));
    addressEdit_ = new QLineEdit(QString("0x%1").arg(baseAddr, 0, 16));
    addressEdit_->setFont(QFont("Monospace", 10));
    connect(addressEdit_, &QLineEdit::returnPressed, this, &StructureDissector::onGotoAddress);
    addrRow->addWidget(addressEdit_);
    auto* goBtn = new QPushButton("Go");
    connect(goBtn, &QPushButton::clicked, this, &StructureDissector::onGotoAddress);
    addrRow->addWidget(goBtn);
    layout->addLayout(addrRow);

    // Table
    table_ = new QTableWidget;
    table_->setColumnCount(6);
    table_->setHorizontalHeaderLabels({"Offset", "Hex", "Int8", "Int32", "Float", "Pointer?"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setFont(QFont("Monospace", 9));
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->verticalHeader()->setVisible(false);
    table_->setAlternatingRowColors(true);
    layout->addWidget(table_);

    setCentralWidget(central);

    // Auto-refresh
    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &StructureDissector::onRefresh);
    refreshTimer_->start(1000);

    if (baseAddr_) populateTable();
}

void StructureDissector::onGotoAddress() {
    bool ok;
    baseAddr_ = addressEdit_->text().toULongLong(&ok, 16);
    if (ok) populateTable();
}

void StructureDissector::onRefresh() {
    if (baseAddr_ && proc_) populateTable();
}

QString StructureDissector::formatValue(const uint8_t* data, int offset, const QString& type) const {
    if (offset + 8 > (int)cache_.size()) return "??";

    if (type == "hex") {
        return QString("%1 %2 %3 %4 %5 %6 %7 %8")
            .arg(data[0], 2, 16, QChar('0')).arg(data[1], 2, 16, QChar('0'))
            .arg(data[2], 2, 16, QChar('0')).arg(data[3], 2, 16, QChar('0'))
            .arg(data[4], 2, 16, QChar('0')).arg(data[5], 2, 16, QChar('0'))
            .arg(data[6], 2, 16, QChar('0')).arg(data[7], 2, 16, QChar('0'));
    }
    if (type == "int8") return QString::number((int8_t)data[0]);
    if (type == "int32") {
        int32_t v; memcpy(&v, data, 4);
        return QString::number(v);
    }
    if (type == "float") {
        float v; memcpy(&v, data, 4);
        if (std::isnan(v) || std::isinf(v)) return "NaN";
        if (v == 0.0f) return "0";
        if (std::abs(v) < 1e-20 || std::abs(v) > 1e20) return "-";
        return QString::number(v, 'f', 4);
    }
    if (type == "ptr") {
        uintptr_t v; memcpy(&v, data, 8);
        if (v > 0x10000 && v < 0x7fffffffffff)
            return QString("-> 0x%1").arg(v, 0, 16);
        return "-";
    }
    return "?";
}

void StructureDissector::populateTable() {
    if (!proc_) return;

    cache_.resize(structSize_);
    auto r = proc_->read(baseAddr_, cache_.data(), structSize_);
    if (!r) return;

    int rows = structSize_ / 8; // Show every 8 bytes
    table_->setRowCount(rows);

    for (int i = 0; i < rows; ++i) {
        int off = i * 8;
        const uint8_t* d = cache_.data() + off;

        table_->setItem(i, 0, new QTableWidgetItem(QString("+0x%1").arg(off, 2, 16, QChar('0'))));
        table_->setItem(i, 1, new QTableWidgetItem(formatValue(d, off, "hex")));
        table_->setItem(i, 2, new QTableWidgetItem(formatValue(d, off, "int8")));
        table_->setItem(i, 3, new QTableWidgetItem(formatValue(d, off, "int32")));
        table_->setItem(i, 4, new QTableWidgetItem(formatValue(d, off, "float")));
        table_->setItem(i, 5, new QTableWidgetItem(formatValue(d, off, "ptr")));
    }
}

} // namespace ce::gui
