#pragma once

#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"
#include "core/autoasm.hpp"
#include "scripting/lua_engine.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/code_finder.hpp"

#include <QMainWindow>
#include <QTableView>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QSplitter>
#include <QGroupBox>
#include <QProgressBar>

namespace ce::gui {

class ScanResultsModel;
class AddressListModel;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onOpenProcess();
    void onFirstScan();
    void onNextScan();
    void onUndoScan();
    void onResultDoubleClicked(const QModelIndex& index);
    void onMemoryView();
    void onDeleteAddresses();
    void onSaveTable();
    void onLoadTable();
    void onFreezeTimer();

private:
    void setupUi();
    void setupMenus();
    void updateScanButtons();

    // Process
    std::unique_ptr<os::LinuxProcessHandle> process_;
    pid_t currentPid_ = 0;

    // Scanner + AutoAssembler + Lua + Debug
    MemoryScanner scanner_;
    AutoAssembler autoAsm_;
    LuaEngine luaEngine_;
    BreakpointManager bpManager_;
    std::unique_ptr<ScanResult> lastResult_;
    std::unique_ptr<ScanResult> undoResult_;

    // Top panel — process & scan
    QLabel* processLabel_;
    QLineEdit* scanValueEdit_;
    QComboBox* scanTypeCombo_;
    QComboBox* valueTypeCombo_;
    QPushButton* firstScanBtn_;
    QPushButton* nextScanBtn_;
    QPushButton* undoScanBtn_;
    QLabel* foundLabel_;
    QProgressBar* progressBar_;

    // Scan options
    QLineEdit* fromAddressEdit_;
    QLineEdit* toAddressEdit_;
    QCheckBox* writableCheck_;
    QCheckBox* executableCheck_;
    QCheckBox* fastScanCheck_;
    QLineEdit* alignEdit_;

    // Results
    QTableView* resultsView_;
    ScanResultsModel* resultsModel_;

    // Bottom panel — address list
    QTableView* addressListView_;
    AddressListModel* addressListModel_;
};

// ── Models ──

class ScanResultsModel : public QAbstractTableModel {
    Q_OBJECT
public:
    explicit ScanResultsModel(QObject* parent = nullptr);
    void setResult(ScanResult* result, ce::ValueType vt);
    void clear();

    int rowCount(const QModelIndex& = {}) const override;
    int columnCount(const QModelIndex& = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation, int role) const override;

    uintptr_t addressAt(int row) const;

private:
    ScanResult* result_ = nullptr;
    ce::ValueType valueType_ = ce::ValueType::Int32;
};

struct AddressEntry {
    bool active = false;
    QString description;
    uintptr_t address = 0;
    ce::ValueType type = ce::ValueType::Int32;
    QString currentValue;
    QString frozenValue;      // Value to continuously write when active
    ce::FreezeMode freezeMode = ce::FreezeMode::Normal;
    QString autoAsmScript;    // Auto-assembler script to run on enable/disable
    int indent = 0;           // Nesting level (0 = root, 1 = child, etc.)
    bool isGroup = false;     // Group header (no address, just a label)
};

class AddressListModel : public QAbstractTableModel {
    Q_OBJECT
public:
    explicit AddressListModel(QObject* parent = nullptr);
    void addEntry(uintptr_t addr, ce::ValueType type, const QString& desc = "No description");
    void removeEntry(int row);
    void removeEntries(QList<int> rows);
    void setFreezeMode(int row, ce::FreezeMode mode);
    const std::vector<AddressEntry>& entries() const { return entries_; }
    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; }
    void updateValues(ce::ProcessHandle* proc);
    void freezeWrite(ce::ProcessHandle* proc);
    QJsonArray toJson() const;
    void fromJson(const QJsonArray& arr);

    int rowCount(const QModelIndex& = {}) const override;
    int columnCount(const QModelIndex& = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation, int role) const override;
    Qt::ItemFlags flags(const QModelIndex& index) const override;
    bool setData(const QModelIndex& index, const QVariant& value, int role) override;

private:
    std::vector<AddressEntry> entries_;
    ce::ProcessHandle* proc_ = nullptr;
};

} // namespace ce::gui
