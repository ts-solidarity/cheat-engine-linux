#pragma once
#include "platform/process_api.hpp"
#include <QMainWindow>
#include <QTableWidget>
#include <QLineEdit>
#include <QTimer>

namespace ce::gui {

class StructureDissector : public QMainWindow {
    Q_OBJECT
public:
    explicit StructureDissector(ce::ProcessHandle* proc, uintptr_t baseAddr = 0, QWidget* parent = nullptr);

private slots:
    void onGotoAddress();
    void onRefresh();

private:
    void populateTable();
    QString formatValue(const uint8_t* data, int offset, const QString& type) const;

    ce::ProcessHandle* proc_;
    uintptr_t baseAddr_ = 0;
    int structSize_ = 256;
    QLineEdit* addressEdit_;
    QTableWidget* table_;
    QTimer* refreshTimer_;
    std::vector<uint8_t> cache_;
};

} // namespace ce::gui
