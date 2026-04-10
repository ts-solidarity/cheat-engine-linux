#pragma once

#include "platform/process_api.hpp"
#include "arch/disassembler.hpp"
#include "symbols/elf_symbols.hpp"

#include <QMainWindow>
#include <QSplitter>
#include <QAbstractScrollArea>
#include <QLineEdit>
#include <QToolBar>
#include <QFont>
#include <QTimer>

namespace ce::gui {

// ── Hex View Widget ──
class HexView : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);

    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; }
    void setAddress(uintptr_t addr);
    uintptr_t currentAddress() const { return address_; }
    void refresh();

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;

private:
    void updateScrollBar();
    int visibleRows() const;

    ce::ProcessHandle* proc_ = nullptr;
    uintptr_t address_ = 0;
    int bytesPerRow_ = 16;
    QFont monoFont_{"Monospace", 10};
    int charW_ = 0;
    int charH_ = 0;
    std::vector<uint8_t> cache_;
};

// ── Disassembler View Widget ──
class DisasmView : public QAbstractScrollArea {
    Q_OBJECT
public:
    explicit DisasmView(QWidget* parent = nullptr);

    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; }
    void setResolver(ce::SymbolResolver* resolver) { resolver_ = resolver; }
    void setAddress(uintptr_t addr);
    uintptr_t currentAddress() const { return address_; }
    void refresh();

signals:
    void addressChanged(uintptr_t addr);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;

private:
    int visibleRows() const;
    uintptr_t scrollBack(uintptr_t addr, int count);

    ce::ProcessHandle* proc_ = nullptr;
    ce::SymbolResolver* resolver_ = nullptr;
    ce::Disassembler disasm_{ce::Arch::X86_64};
    uintptr_t address_ = 0;
    QFont monoFont_{"Monospace", 10};
    int charW_ = 0;
    int charH_ = 0;
    std::vector<ce::Instruction> instructions_;
};

// ── Memory Browser Window ──
class MemoryBrowser : public QMainWindow {
    Q_OBJECT
public:
    explicit MemoryBrowser(ce::ProcessHandle* proc, QWidget* parent = nullptr);

    void gotoAddress(uintptr_t addr);

private slots:
    void onGotoAddress();
    void onRefresh();

private:
    ce::ProcessHandle* proc_;
    ce::SymbolResolver resolver_;
    DisasmView* disasmView_;
    HexView* hexView_;
    QLineEdit* addressEdit_;
    QTimer* refreshTimer_;
};

} // namespace ce::gui
