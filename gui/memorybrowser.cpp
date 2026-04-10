#include "gui/memorybrowser.hpp"

#include <QPainter>
#include <QScrollBar>
#include <QKeyEvent>
#include <QWheelEvent>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QInputDialog>
#include <QFontMetrics>
#include <QShortcut>
#include <cstring>

namespace ce::gui {

// ═══════════════════════════════════════════════════════════════
// HexView
// ═══════════════════════════════════════════════════════════════

HexView::HexView(QWidget* parent) : QAbstractScrollArea(parent) {
    setFont(monoFont_);
    QFontMetrics fm(monoFont_);
    charW_ = fm.horizontalAdvance('0');
    charH_ = fm.height();
    setMinimumHeight(charH_ * 8);
    viewport()->setCursor(Qt::IBeamCursor);
}

void HexView::setAddress(uintptr_t addr) {
    address_ = addr & ~0xFULL; // Align to 16
    refresh();
}

int HexView::visibleRows() const {
    return viewport()->height() / charH_;
}

void HexView::updateScrollBar() {
    verticalScrollBar()->setRange(0, 0xFFFF);
    verticalScrollBar()->setPageStep(visibleRows());
}

void HexView::refresh() {
    int rows = visibleRows() + 1;
    size_t total = rows * bytesPerRow_;
    cache_.resize(total);
    if (proc_) {
        auto r = proc_->read(address_, cache_.data(), total);
        if (!r) std::fill(cache_.begin(), cache_.end(), 0);
    } else {
        std::fill(cache_.begin(), cache_.end(), 0);
    }
    viewport()->update();
}

void HexView::resizeEvent(QResizeEvent* e) {
    QAbstractScrollArea::resizeEvent(e);
    updateScrollBar();
    refresh();
}

void HexView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    p.setFont(monoFont_);

    int rows = visibleRows();
    int addrColW = charW_ * 18;     // "0x0000000000000000"
    int hexColW = charW_ * 3 * bytesPerRow_ + charW_; // "XX " * 16
    int asciiX = addrColW + hexColW + charW_;

    // Background
    p.fillRect(viewport()->rect(), QColor(0x1e, 0x1e, 0x2e)); // Dark background
    p.setPen(QColor(0x89, 0xb4, 0xfa)); // Address color

    for (int row = 0; row < rows && row * bytesPerRow_ < (int)cache_.size(); ++row) {
        int y = (row + 1) * charH_;
        uintptr_t rowAddr = address_ + row * bytesPerRow_;

        // Address
        p.setPen(QColor(0x89, 0xb4, 0xfa));
        p.drawText(0, y, QString("%1").arg(rowAddr, 16, 16, QChar('0')));

        // Hex bytes
        for (int col = 0; col < bytesPerRow_; ++col) {
            int idx = row * bytesPerRow_ + col;
            if (idx >= (int)cache_.size()) break;
            uint8_t b = cache_[idx];

            int x = addrColW + col * charW_ * 3;
            if (col == 8) x += charW_; // gap in middle

            p.setPen(b == 0 ? QColor(0x58, 0x5b, 0x70) : QColor(0xcd, 0xd6, 0xf4));
            p.drawText(x, y, QString("%1").arg(b, 2, 16, QChar('0')));
        }

        // ASCII
        p.setPen(QColor(0xa6, 0xad, 0xc8));
        for (int col = 0; col < bytesPerRow_; ++col) {
            int idx = row * bytesPerRow_ + col;
            if (idx >= (int)cache_.size()) break;
            uint8_t b = cache_[idx];
            char c = (b >= 32 && b < 127) ? (char)b : '.';
            p.drawText(asciiX + col * charW_, y, QString(QChar(c)));
        }
    }
}

void HexView::keyPressEvent(QKeyEvent* e) {
    int rows = visibleRows();
    if (e->key() == Qt::Key_Down) { address_ += bytesPerRow_; refresh(); }
    else if (e->key() == Qt::Key_Up) { address_ -= bytesPerRow_; refresh(); }
    else if (e->key() == Qt::Key_PageDown) { address_ += rows * bytesPerRow_; refresh(); }
    else if (e->key() == Qt::Key_PageUp) { address_ -= rows * bytesPerRow_; refresh(); }
    else QAbstractScrollArea::keyPressEvent(e);
}

void HexView::wheelEvent(QWheelEvent* e) {
    int delta = e->angleDelta().y() / 120;
    address_ -= delta * bytesPerRow_ * 3;
    refresh();
}

// ═══════════════════════════════════════════════════════════════
// DisasmView
// ═══════════════════════════════════════════════════════════════

DisasmView::DisasmView(QWidget* parent) : QAbstractScrollArea(parent) {
    setFont(monoFont_);
    QFontMetrics fm(monoFont_);
    charW_ = fm.horizontalAdvance('0');
    charH_ = fm.height();
    setMinimumHeight(charH_ * 8);
}

void DisasmView::setAddress(uintptr_t addr) {
    address_ = addr;
    refresh();
}

int DisasmView::visibleRows() const {
    return viewport()->height() / charH_;
}

void DisasmView::resizeEvent(QResizeEvent* e) {
    QAbstractScrollArea::resizeEvent(e);
    refresh();
}

void DisasmView::refresh() {
    instructions_.clear();
    if (!proc_) { viewport()->update(); return; }

    int rows = visibleRows() + 5;
    std::vector<uint8_t> buf(rows * 15);
    auto r = proc_->read(address_, buf.data(), buf.size());
    if (!r || *r == 0) { viewport()->update(); return; }

    instructions_ = disasm_.disassemble(address_, {buf.data(), *r}, rows);
    viewport()->update();
}

void DisasmView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    p.setFont(monoFont_);
    p.fillRect(viewport()->rect(), QColor(0x1e, 0x1e, 0x2e));

    int addrColW = charW_ * 18;
    int bytesColW = charW_ * 25;
    int mnemonicX = addrColW + bytesColW;

    for (int i = 0; i < (int)instructions_.size() && i < visibleRows(); ++i) {
        auto& inst = instructions_[i];
        int y = (i + 1) * charH_;

        // Symbol label (if this address has a symbol)
        if (resolver_) {
            auto sym = resolver_->resolve(inst.address);
            if (!sym.empty() && sym.find('+') == std::string::npos) {
                // Exact symbol match — show as label
                p.setPen(QColor(0xf9, 0xe2, 0xaf)); // Yellow for labels
                p.drawText(0, y, QString::fromStdString(sym + ":"));
                y += charH_;
            }
        }

        // Address
        p.setPen(QColor(0x89, 0xb4, 0xfa));
        p.drawText(0, y, QString("%1").arg(inst.address, 16, 16, QChar('0')));

        // Bytes
        p.setPen(QColor(0x58, 0x5b, 0x70));
        QString bytes;
        for (auto b : inst.bytes) bytes += QString("%1 ").arg(b, 2, 16, QChar('0'));
        p.drawText(addrColW, y, bytes.left(24));

        // Mnemonic
        p.setPen(QColor(0xcb, 0xa6, 0xf7)); // Purple for mnemonics
        p.drawText(mnemonicX, y, QString::fromStdString(inst.mnemonic));

        // Operands — try to annotate with symbol name
        auto operands = QString::fromStdString(inst.operands);
        QString annotation;
        if (resolver_ && (inst.mnemonic == "call" || inst.mnemonic == "jmp" || inst.mnemonic.substr(0, 1) == "j")) {
            // Try to resolve the target address from operands
            bool ok;
            uintptr_t target = operands.trimmed().toULongLong(&ok, 16);
            if (!ok) target = operands.trimmed().mid(2).toULongLong(&ok, 16); // skip "0x"
            if (ok && target) {
                auto sym = resolver_->resolve(target);
                if (!sym.empty()) annotation = " ; " + QString::fromStdString(sym);
            }
        }

        p.setPen(QColor(0xcd, 0xd6, 0xf4));
        p.drawText(mnemonicX + charW_ * 8, y, operands);

        if (!annotation.isEmpty()) {
            p.setPen(QColor(0x6c, 0x70, 0x86)); // Dim for comments
            p.drawText(mnemonicX + charW_ * 8 + p.fontMetrics().horizontalAdvance(operands), y, annotation);
        }
    }
}

// Try to find a valid instruction boundary `count` instructions before `addr`
uintptr_t DisasmView::scrollBack(uintptr_t addr, int count) {
    if (!proc_ || count <= 0) return addr;
    // Read a chunk before the address and disassemble forward to find boundaries
    constexpr int LOOKBACK = 128;
    uintptr_t startAddr = (addr > LOOKBACK) ? addr - LOOKBACK : 0;
    size_t readSize = addr - startAddr;
    if (readSize == 0) return addr;

    std::vector<uint8_t> buf(readSize);
    auto r = proc_->read(startAddr, buf.data(), readSize);
    if (!r || *r == 0) return (addr > (uintptr_t)count * 4) ? addr - count * 4 : 0;

    auto insns = disasm_.disassemble(startAddr, {buf.data(), *r}, 0);
    if (insns.empty()) return (addr > (uintptr_t)count * 4) ? addr - count * 4 : 0;

    // Find which instruction index lands at our current address
    int targetIdx = -1;
    for (int i = 0; i < (int)insns.size(); ++i) {
        if (insns[i].address >= addr) { targetIdx = i; break; }
    }
    if (targetIdx < 0) targetIdx = insns.size();

    int newIdx = targetIdx - count;
    if (newIdx < 0) newIdx = 0;
    return insns[newIdx].address;
}

void DisasmView::keyPressEvent(QKeyEvent* e) {
    if (e->key() == Qt::Key_Down && !instructions_.empty()) {
        address_ = instructions_.size() > 1 ? instructions_[1].address : address_ + 1;
        refresh();
    } else if (e->key() == Qt::Key_Up) {
        address_ = scrollBack(address_, 1);
        refresh();
    } else if (e->key() == Qt::Key_PageDown && !instructions_.empty()) {
        int rows = visibleRows();
        if ((int)instructions_.size() > rows)
            address_ = instructions_[rows - 1].address;
        refresh();
    } else if (e->key() == Qt::Key_PageUp) {
        address_ = scrollBack(address_, visibleRows());
        refresh();
    } else {
        QAbstractScrollArea::keyPressEvent(e);
    }
}

void DisasmView::wheelEvent(QWheelEvent* e) {
    int delta = e->angleDelta().y() / 120;
    if (delta > 0) {
        // Scroll up
        address_ = scrollBack(address_, delta * 3);
    } else if (delta < 0 && !instructions_.empty()) {
        // Scroll down
        int steps = std::min((int)instructions_.size() - 1, -delta * 3);
        if (steps > 0)
            address_ = instructions_[steps].address;
    }
    refresh();
}

// ═══════════════════════════════════════════════════════════════
// MemoryBrowser
// ═══════════════════════════════════════════════════════════════

MemoryBrowser::MemoryBrowser(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {

    setWindowTitle("Memory Browser");
    resize(900, 600);

    // Toolbar
    auto* toolbar = new QToolBar;
    toolbar->addWidget(new QLabel(" Address: "));
    addressEdit_ = new QLineEdit;
    addressEdit_->setFont(QFont("Monospace", 10));
    addressEdit_->setFixedWidth(200);
    addressEdit_->setPlaceholderText("0x0000000000000000");
    connect(addressEdit_, &QLineEdit::returnPressed, this, &MemoryBrowser::onGotoAddress);
    toolbar->addWidget(addressEdit_);

    auto* goBtn = new QPushButton("Go");
    connect(goBtn, &QPushButton::clicked, this, &MemoryBrowser::onGotoAddress);
    toolbar->addWidget(goBtn);

    toolbar->addSeparator();
    auto* refreshBtn = new QPushButton("Refresh");
    connect(refreshBtn, &QPushButton::clicked, this, &MemoryBrowser::onRefresh);
    toolbar->addWidget(refreshBtn);
    addToolBar(toolbar);

    // Splitter: disasm (top) / hex (bottom)
    auto* splitter = new QSplitter(Qt::Vertical);

    // Load symbols
    if (proc_) resolver_.loadProcess(*proc_);

    disasmView_ = new DisasmView;
    disasmView_->setProcess(proc);
    disasmView_->setResolver(&resolver_);
    splitter->addWidget(disasmView_);

    hexView_ = new HexView;
    hexView_->setProcess(proc);
    splitter->addWidget(hexView_);

    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);
    setCentralWidget(splitter);

    // Keyboard shortcuts
    auto* gotoShortcut = new QShortcut(QKeySequence("Ctrl+G"), this);
    connect(gotoShortcut, &QShortcut::activated, this, [this]() {
        bool ok;
        auto text = QInputDialog::getText(this, "Goto Address", "Address (hex):",
            QLineEdit::Normal, addressEdit_->text(), &ok);
        if (ok && !text.isEmpty()) {
            addressEdit_->setText(text);
            onGotoAddress();
        }
    });

    auto* findShortcut = new QShortcut(QKeySequence("Ctrl+F"), this);
    connect(findShortcut, &QShortcut::activated, this, [this]() {
        bool ok;
        auto text = QInputDialog::getText(this, "Find Bytes", "Hex bytes (e.g., 7F 45 4C 46):",
            QLineEdit::Normal, "", &ok);
        if (ok && !text.isEmpty() && proc_) {
            // Parse hex bytes
            std::vector<uint8_t> pattern;
            std::istringstream ss(text.toStdString());
            std::string tok;
            while (ss >> tok) {
                try { pattern.push_back((uint8_t)std::stoul(tok, nullptr, 16)); } catch (...) {}
            }
            if (pattern.empty()) return;

            // Search forward from current address
            auto regions = proc_->queryRegions();
            uintptr_t startAddr = hexView_->currentAddress();
            std::vector<uint8_t> buf;
            for (auto& r : regions) {
                if (r.base + r.size <= startAddr) continue;
                if (!(r.protection & ce::MemProt::Read)) continue;
                buf.resize(r.size);
                auto rr = proc_->read(r.base, buf.data(), r.size);
                if (!rr) continue;
                for (size_t off = 0; off + pattern.size() <= *rr; ++off) {
                    if (std::memcmp(buf.data() + off, pattern.data(), pattern.size()) == 0) {
                        uintptr_t found = r.base + off;
                        if (found > startAddr) {
                            gotoAddress(found);
                            return;
                        }
                    }
                }
            }
        }
    });

    // Auto-refresh
    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &MemoryBrowser::onRefresh);
    refreshTimer_->start(2000);

    // Navigate to first executable region
    if (proc_) {
        auto regions = proc_->queryRegions();
        for (auto& r : regions) {
            if (r.protection & ce::MemProt::Exec) {
                gotoAddress(r.base);
                break;
            }
        }
    }
}

void MemoryBrowser::gotoAddress(uintptr_t addr) {
    addressEdit_->setText(QString("0x%1").arg(addr, 16, 16, QChar('0')));
    disasmView_->setAddress(addr);
    hexView_->setAddress(addr);
}

void MemoryBrowser::onGotoAddress() {
    bool ok;
    uintptr_t addr = addressEdit_->text().toULongLong(&ok, 16);
    if (ok) gotoAddress(addr);
}

void MemoryBrowser::onRefresh() {
    disasmView_->refresh();
    hexView_->refresh();
}

} // namespace ce::gui
