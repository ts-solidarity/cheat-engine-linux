#include "gui/mainwindow.hpp"
#include "gui/processlistdialog.hpp"
#include "gui/registereditor.hpp"
#include "gui/memorybrowser.hpp"
#include "gui/scripteditor.hpp"
#include "gui/pointerscan_dialog.hpp"
#include "gui/structuredissector.hpp"
#include "gui/luaconsole.hpp"
#include "gui/breakpointlist.hpp"
#include "gui/codefinder.hpp"
#include "gui/codereferences.hpp"
#include "gui/memoryregions.hpp"
#include "gui/modulelist.hpp"
#include "gui/stackview.hpp"
#include "gui/threadlist.hpp"
#include "gui/settingsdialog.hpp"
#include "core/ct_file.hpp"

#include <QMenuBar>
#include <QApplication>
#include <QClipboard>
#include <QPixmap>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QTimer>
#include <QFont>
#include <QMenu>
#include <QShortcut>
#include <QInputDialog>
#include <QColor>
#include <QDoubleValidator>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <QMap>
#include <cstring>

namespace ce::gui {

// Forward declarations of static helpers
static ScanCompare mapScanType(int index);
static ValueType mapValueType(int index);

// ═══════════════════════════════════════════════════════════════
// MainWindow
// ═══════════════════════════════════════════════════════════════

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setupUi();
    setupMenus();
    setWindowTitle("Cheat Engine");
    resize(734, 572);

    // Refresh address list values periodically (skip if user is editing)
    auto* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [this]() {
        if (process_ && !addressListView_->indexWidget(addressListView_->currentIndex()))
            addressListModel_->updateValues(process_.get());
    });
    timer->start(1000);

    // Freeze timer — writes frozen values at 100ms intervals
    auto* freezeTimer = new QTimer(this);
    connect(freezeTimer, &QTimer::timeout, this, &MainWindow::onFreezeTimer);
    freezeTimer->start(100);
}

void MainWindow::setupMenus() {
    auto* file = menuBar()->addMenu("&File");
    file->addAction("Open Process...", this, &MainWindow::onOpenProcess, QKeySequence("Ctrl+O"));
    file->addSeparator();
    file->addAction("Save Table...", this, &MainWindow::onSaveTable, QKeySequence("Ctrl+S"));
    file->addAction("Load Table...", this, &MainWindow::onLoadTable, QKeySequence("Ctrl+L"));
    file->addSeparator();
    file->addAction("Quit", this, &QWidget::close, QKeySequence("Ctrl+Q"));

    auto* view = menuBar()->addMenu("&View");
    view->addAction("Memory Browser", this, &MainWindow::onMemoryView, QKeySequence("Ctrl+M"));
    view->addAction("Breakpoint List", this, [this]() {
        auto* w = new BreakpointListWindow(&bpManager_, this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    }, QKeySequence("Ctrl+B"));
    view->addAction("Memory Regions", this, [this]() {
        if (!process_) return;
        auto* w = new MemoryRegionsWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &MemoryRegionsWindow::navigateTo, this, [this](uintptr_t addr) {
            auto* browser = new MemoryBrowser(process_.get(), this);
            browser->setAttribute(Qt::WA_DeleteOnClose);
            browser->gotoAddress(addr);
            browser->show();
        });
        w->show();
    });
    view->addAction("Module List", this, [this]() {
        if (!process_) return;
        auto* w = new ModuleListWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &ModuleListWindow::navigateTo, this, [this](uintptr_t addr) {
            auto* browser = new MemoryBrowser(process_.get(), this);
            browser->setAttribute(Qt::WA_DeleteOnClose);
            browser->gotoAddress(addr);
            browser->show();
        });
        w->show();
    });
    view->addAction("Code References", this, [this]() {
        if (!process_) return;
        auto* w = new CodeReferencesWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &CodeReferencesWindow::navigateTo, this, [this](uintptr_t addr) {
            auto* browser = new MemoryBrowser(process_.get(), this);
            browser->setAttribute(Qt::WA_DeleteOnClose);
            browser->gotoAddress(addr);
            browser->show();
        });
        w->show();
    });
    view->addAction("Thread List", this, [this]() {
        if (!process_) return;
        auto* w = new ThreadListWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    view->addAction("Stack View", this, [this]() {
        if (!process_) return;
        auto* w = new StackViewWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    view->addAction("Register Editor", this, [this]() {
        if (!process_) return;
        auto* w = new RegisterEditorWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    view->addSeparator();
    view->addAction("Settings...", this, [this]() {
        SettingsDialog dlg(this);
        dlg.exec();
    });

    auto* tools = menuBar()->addMenu("&Tools");
    tools->addAction("Auto Assemble...", this, [this]() {
        auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
        editor->setAttribute(Qt::WA_DeleteOnClose);
        editor->show();
    }, QKeySequence("Ctrl+A"));
    tools->addAction("Pointer Scanner...", this, [this]() {
        if (!process_) return;
        auto* dlg = new PointerScanDialog(process_.get(), this);
        connect(dlg, &PointerScanDialog::addressSelected, this, [this](uintptr_t addr, const QString& desc) {
            addressListModel_->addEntry(addr, ce::ValueType::Int32, desc);
        });
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }, QKeySequence("Ctrl+P"));
    tools->addAction("Structure Dissector...", this, [this]() {
        if (!process_) return;
        bool ok;
        auto text = QInputDialog::getText(this, "Structure Dissector", "Base address (hex):",
            QLineEdit::Normal, "0", &ok);
        uintptr_t addr = ok ? text.toULongLong(nullptr, 16) : 0;
        auto* sd = new StructureDissector(process_.get(), addr, this);
        sd->setAttribute(Qt::WA_DeleteOnClose);
        sd->show();
    });
    tools->addSeparator();
    tools->addAction("Lua Console...", this, [this]() {
        luaEngine_.setProcess(process_.get());
        auto* console = new LuaConsole(&luaEngine_, this);
        console->setAttribute(Qt::WA_DeleteOnClose);
        console->show();
    }, QKeySequence("Ctrl+Shift+L"));
    tools->addSeparator();
    tools->addAction("Speedhack...", this, [this]() {
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Speedhack");
        dlg->resize(300, 120);
        auto* layout = new QVBoxLayout(dlg);
        auto* label = new QLabel("Speed: 1.0x");
        auto* slider = new QSlider(Qt::Horizontal);
        slider->setRange(1, 100);  // 0.1x to 10.0x
        slider->setValue(10);      // 1.0x default
        connect(slider, &QSlider::valueChanged, [label](int v) {
            double speed = v / 10.0;
            label->setText(QString("Speed: %1x").arg(speed, 0, 'f', 1));
        });
        auto* applyBtn = new QPushButton("Apply (writes /dev/shm/ce_speedhack)");
        connect(applyBtn, &QPushButton::clicked, [slider]() {
            double speed = slider->value() / 10.0;
            int shmfd = ::open("/dev/shm/ce_speedhack", O_CREAT | O_RDWR, 0666);
            if (shmfd >= 0) {
                ::ftruncate(shmfd, sizeof(double));
                void* mem = ::mmap(nullptr, sizeof(double), PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, 0);
                if (mem != MAP_FAILED) { *(double*)mem = speed; ::munmap(mem, sizeof(double)); }
                ::close(shmfd);
            }
        });
        layout->addWidget(label);
        layout->addWidget(slider);
        layout->addWidget(applyBtn);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });

    auto* help = menuBar()->addMenu("&Help");
    help->addAction("About", this, [this]() {
        QMessageBox::about(this, "Cheat Engine for Linux",
            "<h2>Cheat Engine for Linux</h2>"
            "<p>Memory scanner, debugger, and code injection tool</p>"
            "<p>C++23 / Qt6 / Capstone / Keystone / Lua 5.3</p>"
            "<p>9,120 lines of code</p>"
            "<p><a href='https://github.com/ts-solidarity/cheat-engine-linux'>GitHub</a></p>");
    });
}

void MainWindow::setupUi() {
    auto* central = new QWidget;
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(4, 4, 4, 4);
    mainLayout->setSpacing(4);

    // ── Process bar ──
    auto* processBar = new QHBoxLayout;
    auto* openBtn = new QPushButton;
    openBtn->setFixedSize(30, 30);
    // Use CE icon for the process selector button
    QPixmap btnIcon(":/icon.png");
    if (!btnIcon.isNull())
        openBtn->setIcon(QIcon(btnIcon.scaled(24, 24, Qt::KeepAspectRatio, Qt::SmoothTransformation)));
    else
        openBtn->setText("CE");
    openBtn->setIconSize(QSize(24, 24));
    connect(openBtn, &QPushButton::clicked, this, &MainWindow::onOpenProcess);
    processLabel_ = new QLabel("No process selected");
    processLabel_->setStyleSheet("font-weight: bold;");
    processBar->addWidget(openBtn);
    processBar->addWidget(processLabel_, 1);
    mainLayout->addLayout(processBar);

    // ── Top area: results + scan controls ──
    auto* topSplitter = new QSplitter(Qt::Horizontal);

    // Left: scan results
    auto* leftPanel = new QWidget;
    auto* leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(0, 0, 0, 0);

    resultsModel_ = new ScanResultsModel(this);
    resultsView_ = new QTableView;
    resultsView_->setModel(resultsModel_);
    resultsView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsView_->setFont(QFont("Monospace", 9));
    resultsView_->verticalHeader()->setVisible(false);
    resultsView_->horizontalHeader()->setStretchLastSection(true);
    connect(resultsView_, &QTableView::doubleClicked, this, &MainWindow::onResultDoubleClicked);
    leftLayout->addWidget(resultsView_);

    foundLabel_ = new QLabel("Found: 0");
    leftLayout->addWidget(foundLabel_);

    auto* leftBtns = new QHBoxLayout;
    auto* memViewBtn = new QPushButton("Memory View");
    connect(memViewBtn, &QPushButton::clicked, this, &MainWindow::onMemoryView);
    auto* addAddrBtn = new QPushButton("Add Address");
    leftBtns->addWidget(memViewBtn);
    leftBtns->addWidget(addAddrBtn);
    leftBtns->addStretch();
    leftLayout->addLayout(leftBtns);

    // Right: scan controls
    auto* rightPanel = new QWidget;
    auto* rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(4, 0, 0, 0);

    // Value input
    auto* valueLayout = new QHBoxLayout;
    valueLayout->addWidget(new QLabel("Value:"));
    scanValueEdit_ = new QLineEdit;
    valueLayout->addWidget(scanValueEdit_);
    rightLayout->addLayout(valueLayout);

    // Scan type
    scanTypeCombo_ = new QComboBox;
    scanTypeCombo_->addItems({"Exact Value", "Bigger than...", "Smaller than...",
        "Value between...", "Unknown initial value", "Increased value",
        "Decreased value", "Changed value", "Unchanged value"});
    rightLayout->addWidget(scanTypeCombo_);

    // Value type
    valueTypeCombo_ = new QComboBox;
    valueTypeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "Text", "Unicode Text", "Array of Bytes", "Binary", "All Types"});
    valueTypeCombo_->setCurrentIndex(2); // 4 Bytes default
    rightLayout->addWidget(valueTypeCombo_);

    auto* floatLayout = new QHBoxLayout;
    floatRoundingCombo_ = new QComboBox;
    floatRoundingCombo_->addItems({"Exact", "Rounded", "Truncated", "Extreme"});
    floatToleranceEdit_ = new QLineEdit;
    floatToleranceEdit_->setPlaceholderText("Tolerance");
    floatToleranceEdit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 8, floatToleranceEdit_));
    floatLayout->addWidget(floatRoundingCombo_);
    floatLayout->addWidget(floatToleranceEdit_);
    rightLayout->addLayout(floatLayout);
    auto updateFloatOptions = [this]() {
        auto vt = mapValueType(valueTypeCombo_->currentIndex());
        bool isFloat = vt == ValueType::Float || vt == ValueType::Double;
        floatRoundingCombo_->setEnabled(isFloat);
        floatToleranceEdit_->setEnabled(isFloat && floatRoundingCombo_->currentIndex() == 3);
    };
    connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions](int) { updateFloatOptions(); });
    connect(floatRoundingCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions](int) { updateFloatOptions(); });
    updateFloatOptions();

    // Buttons
    auto* btnLayout = new QHBoxLayout;
    firstScanBtn_ = new QPushButton("First Scan");
    firstScanBtn_->setStyleSheet("font-weight: bold;");
    nextScanBtn_ = new QPushButton("Next Scan");
    nextScanBtn_->setEnabled(false);
    undoScanBtn_ = new QPushButton("Undo Scan");
    undoScanBtn_->setEnabled(false);
    connect(firstScanBtn_, &QPushButton::clicked, this, &MainWindow::onFirstScan);
    connect(nextScanBtn_, &QPushButton::clicked, this, &MainWindow::onNextScan);
    connect(undoScanBtn_, &QPushButton::clicked, this, &MainWindow::onUndoScan);
    btnLayout->addWidget(firstScanBtn_);
    btnLayout->addWidget(nextScanBtn_);
    rightLayout->addLayout(btnLayout);
    rightLayout->addWidget(undoScanBtn_);

    // Scan options group
    auto* optGroup = new QGroupBox("Memory Scan Options");
    auto* optLayout = new QGridLayout(optGroup);
    optLayout->addWidget(new QLabel("From:"), 0, 0);
    fromAddressEdit_ = new QLineEdit("0000000000");
    fromAddressEdit_->setFont(QFont("Monospace", 9));
    optLayout->addWidget(fromAddressEdit_, 0, 1);
    optLayout->addWidget(new QLabel("To:"), 1, 0);
    toAddressEdit_ = new QLineEdit("7fffffffffff");
    toAddressEdit_->setFont(QFont("Monospace", 9));
    optLayout->addWidget(toAddressEdit_, 1, 1);
    writableCheck_ = new QCheckBox("Writable");
    writableCheck_->setChecked(true);
    optLayout->addWidget(writableCheck_, 2, 0, 1, 2);
    executableCheck_ = new QCheckBox("Executable");
    optLayout->addWidget(executableCheck_, 3, 0, 1, 2);
    fastScanCheck_ = new QCheckBox("Fast Scan");
    fastScanCheck_->setChecked(true);
    optLayout->addWidget(fastScanCheck_, 4, 0);
    alignEdit_ = new QLineEdit("4");
    alignEdit_->setFixedWidth(30);
    optLayout->addWidget(alignEdit_, 4, 1);

    percentCheck_ = new QCheckBox("Compare by %");
    optLayout->addWidget(percentCheck_, 5, 0);
    percentValueEdit_ = new QLineEdit("10");
    percentValueEdit_->setFixedWidth(60);
    percentValueEdit_->setEnabled(false);
    percentValueEdit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 4, percentValueEdit_));
    optLayout->addWidget(percentValueEdit_, 5, 1);

    auto* percent2Label = new QLabel("Percent max:");
    optLayout->addWidget(percent2Label, 6, 0);
    percentValue2Edit_ = new QLineEdit("20");
    percentValue2Edit_->setFixedWidth(60);
    percentValue2Edit_->setEnabled(false);
    percentValue2Edit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 4, percentValue2Edit_));
    optLayout->addWidget(percentValue2Edit_, 6, 1);

    auto updatePercentUi = [this, percent2Label]() {
        bool enabled = percentCheck_->isChecked();
        bool needsUpper = enabled && mapScanType(scanTypeCombo_->currentIndex()) == ScanCompare::Between;
        percentValueEdit_->setEnabled(enabled);
        percent2Label->setEnabled(needsUpper);
        percentValue2Edit_->setEnabled(needsUpper);
    };
    connect(percentCheck_, &QCheckBox::toggled, this, [updatePercentUi](bool) { updatePercentUi(); });
    connect(scanTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updatePercentUi](int) { updatePercentUi(); });
    updatePercentUi();
    rightLayout->addWidget(optGroup);

    progressBar_ = new QProgressBar;
    progressBar_->setMaximum(100);
    progressBar_->setValue(0);
    progressBar_->setVisible(false);
    rightLayout->addWidget(progressBar_);

    rightLayout->addStretch();

    topSplitter->addWidget(leftPanel);
    topSplitter->addWidget(rightPanel);
    topSplitter->setStretchFactor(0, 2);
    topSplitter->setStretchFactor(1, 1);

    // ── Bottom: address list ──
    addressListModel_ = new AddressListModel(this);
    addressListModel_->setAutoAssembler(&autoAsm_);
    addressListModel_->setActivationErrorCallback([this](const QString& title, const QString& message) {
        QMessageBox::warning(this, title, message);
    });
    addressListView_ = new QTableView;
    addressListView_->setModel(addressListModel_);
    addressListView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    addressListView_->setFont(QFont("Monospace", 9));
    addressListView_->verticalHeader()->setVisible(false);
    addressListView_->horizontalHeader()->setStretchLastSection(true);
    addressListView_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    addressListView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(addressListView_, &QWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        QMenu menu;
        auto selected = addressListView_->selectionModel()->selectedRows();

        if (!selected.isEmpty()) {
            menu.addAction("Copy", this, &MainWindow::onCopyAddresses, QKeySequence::Copy);
            menu.addAction("Delete", this, &MainWindow::onDeleteAddresses, QKeySequence::Delete);

            menu.addSeparator();
            auto* freezeMenu = menu.addMenu("Freeze Mode");
            freezeMenu->addAction("Normal", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::Normal);
            });
            freezeMenu->addAction("Increase Only", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::IncreaseOnly);
            });
            freezeMenu->addAction("Decrease Only", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::DecreaseOnly);
            });
            freezeMenu->addAction("Never Increase", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::NeverIncrease);
            });
            freezeMenu->addAction("Never Decrease", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::NeverDecrease);
            });

            menu.addSeparator();
            menu.addAction("Browse this address", [this, selected]() {
                if (!process_ || selected.isEmpty()) return;
                auto& entries = addressListModel_->entries();
                int row = selected.first().row();
                if (row < (int)entries.size()) {
                    auto* browser = new MemoryBrowser(process_.get(), this);
                    browser->setAttribute(Qt::WA_DeleteOnClose);
                    browser->gotoAddress(entries[row].address);
                    browser->show();
                }
            });
            menu.addAction("Find what accesses this address", [this, selected]() {
                if (!selected.isEmpty())
                    startCodeFinder(selected.first().row(), false);
            });
            menu.addAction("Find what writes to this address", [this, selected]() {
                if (!selected.isEmpty())
                    startCodeFinder(selected.first().row(), true);
            });
        }

        menu.addSeparator();
        menu.addAction("Add Address Manually...", [this]() {
            bool ok;
            auto text = QInputDialog::getText(this, "Add Address", "Address (hex):", QLineEdit::Normal, "", &ok);
            if (ok && !text.isEmpty()) {
                uintptr_t addr = text.toULongLong(&ok, 16);
                if (ok) addressListModel_->addEntry(addr, mapValueType(valueTypeCombo_->currentIndex()), "Manual entry");
            }
        });
        menu.addAction("Add Group", [this]() {
            addressListModel_->addEntry(0, ValueType::Int32, "-- Group --");
        });
        menu.addAction("Paste", this, &MainWindow::onPasteAddresses, QKeySequence::Paste);

        menu.exec(addressListView_->viewport()->mapToGlobal(pos));
    });
    // Delete key shortcut
    auto* delShortcut = new QShortcut(QKeySequence::Delete, addressListView_);
    connect(delShortcut, &QShortcut::activated, this, &MainWindow::onDeleteAddresses);
    auto* copyShortcut = new QShortcut(QKeySequence::Copy, addressListView_);
    connect(copyShortcut, &QShortcut::activated, this, &MainWindow::onCopyAddresses);
    auto* pasteShortcut = new QShortcut(QKeySequence::Paste, addressListView_);
    connect(pasteShortcut, &QShortcut::activated, this, &MainWindow::onPasteAddresses);

    // Main splitter (top / bottom)
    auto* mainSplitter = new QSplitter(Qt::Vertical);
    mainSplitter->addWidget(topSplitter);
    mainSplitter->addWidget(addressListView_);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 1);

    mainLayout->addWidget(mainSplitter);
    setCentralWidget(central);
}

void MainWindow::onOpenProcess() {
    ProcessListDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        currentPid_ = dlg.selectedPid();
        process_ = std::make_unique<os::LinuxProcessHandle>(currentPid_);
        processLabel_->setText(QString("PID: %1 — %2").arg(currentPid_).arg(dlg.selectedName()));
        addressListModel_->setProcess(process_.get());
        firstScanBtn_->setEnabled(true);
        resultsModel_->clear();
        lastResult_.reset();
        updateScanButtons();
    }
}

static ScanCompare mapScanType(int index) {
    switch (index) {
        case 0: return ScanCompare::Exact;
        case 1: return ScanCompare::Greater;
        case 2: return ScanCompare::Less;
        case 3: return ScanCompare::Between;
        case 4: return ScanCompare::Unknown;
        case 5: return ScanCompare::Increased;
        case 6: return ScanCompare::Decreased;
        case 7: return ScanCompare::Changed;
        case 8: return ScanCompare::Unchanged;
        default: return ScanCompare::Exact;
    }
}

static ValueType mapValueType(int index) {
    switch (index) {
        case 0: return ValueType::Byte;
        case 1: return ValueType::Int16;
        case 2: return ValueType::Int32;
        case 3: return ValueType::Int64;
        case 4: return ValueType::Float;
        case 5: return ValueType::Double;
        case 6: return ValueType::String;
        case 7: return ValueType::UnicodeString;
        case 8: return ValueType::ByteArray;
        case 9: return ValueType::Binary;
        case 10: return ValueType::All;
        default: return ValueType::Int32;
    }
}

static void applyFloatOptions(ScanConfig& config, QComboBox* roundingCombo, QLineEdit* toleranceEdit) {
    if (config.valueType != ValueType::Float &&
        config.valueType != ValueType::Double) {
        return;
    }
    config.roundingType = roundingCombo->currentIndex();
    bool ok = false;
    double tolerance = toleranceEdit->text().toDouble(&ok);
    if (ok && tolerance > 0.0)
        config.floatTolerance = tolerance;
}

void MainWindow::onFirstScan() {
    if (!process_) return;

    ScanConfig config;
    config.valueType = mapValueType(valueTypeCombo_->currentIndex());
    config.compareType = mapScanType(scanTypeCombo_->currentIndex());
    config.alignment = alignEdit_->text().toInt();
    if (config.alignment < 1) config.alignment = 1;
    config.startAddress = fromAddressEdit_->text().toULongLong(nullptr, 16);
    config.stopAddress = toAddressEdit_->text().toULongLong(nullptr, 16);
    config.scanWritableOnly = writableCheck_->isChecked();
    config.scanExecutableOnly = executableCheck_->isChecked();

    auto text = scanValueEdit_->text();
    if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
        config.stringValue = text.toStdString();
        config.alignment = 1;
    } else if (config.valueType == ValueType::ByteArray) {
        config.parseAOB(text.toStdString());
        config.alignment = 1;
    } else if (config.valueType == ValueType::Binary) {
        config.parseBinary(text.toStdString());
        config.alignment = 1;
    } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
        config.floatValue = text.toDouble();
    } else if (config.valueType == ValueType::All) {
        config.intValue = text.toLongLong();
        config.floatValue = text.toDouble();
    } else {
        config.intValue = text.toLongLong();
    }
    applyFloatOptions(config, floatRoundingCombo_, floatToleranceEdit_);

    firstScanBtn_->setEnabled(false);
    auto result = std::make_unique<ScanResult>(scanner_.firstScan(*process_, config));
    firstScanBtn_->setEnabled(true);

    foundLabel_->setText(QString("Found: %1").arg(result->count()));
    resultsModel_->setResult(result.get(), config.valueType);

    undoResult_ = std::move(lastResult_);
    lastResult_ = std::move(result);
    updateScanButtons();
}

void MainWindow::onNextScan() {
    if (!process_ || !lastResult_) return;

    ScanConfig config;
    config.valueType = mapValueType(valueTypeCombo_->currentIndex());
    config.compareType = mapScanType(scanTypeCombo_->currentIndex());
    config.alignment = alignEdit_->text().toInt();

    auto text = scanValueEdit_->text();
    if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
        config.stringValue = text.toStdString();
        config.alignment = 1;
    } else if (config.valueType == ValueType::ByteArray) {
        config.parseAOB(text.toStdString());
        config.alignment = 1;
    } else if (config.valueType == ValueType::Binary) {
        config.parseBinary(text.toStdString());
        config.alignment = 1;
    } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
        config.floatValue = text.toDouble();
    } else if (config.valueType == ValueType::All) {
        config.intValue = text.toLongLong();
        config.floatValue = text.toDouble();
    } else {
        config.intValue = text.toLongLong();
    }
    applyFloatOptions(config, floatRoundingCombo_, floatToleranceEdit_);

    if (percentCheck_->isChecked()) {
        config.percentageScan = true;
        config.percentageValue = percentValueEdit_->text().toDouble();
        auto percent2Text = percentValue2Edit_->text().trimmed();
        config.percentageValue2 = percent2Text.isEmpty()
            ? config.percentageValue
            : percent2Text.toDouble();
    }

    nextScanBtn_->setEnabled(false);
    auto result = std::make_unique<ScanResult>(scanner_.nextScan(*process_, config, *lastResult_));
    nextScanBtn_->setEnabled(true);

    foundLabel_->setText(QString("Found: %1").arg(result->count()));
    resultsModel_->setResult(result.get(), config.valueType);

    undoResult_ = std::move(lastResult_);
    lastResult_ = std::move(result);
    updateScanButtons();
}

void MainWindow::onUndoScan() {
    if (!undoResult_) return;
    lastResult_ = std::move(undoResult_);
    auto vt = mapValueType(valueTypeCombo_->currentIndex());
    resultsModel_->setResult(lastResult_.get(), vt);
    foundLabel_->setText(QString("Found: %1").arg(lastResult_->count()));
    updateScanButtons();
}

void MainWindow::onResultDoubleClicked(const QModelIndex& index) {
    if (!lastResult_) return;
    auto addr = resultsModel_->addressAt(index.row());
    auto vt = mapValueType(valueTypeCombo_->currentIndex());
    addressListModel_->addEntry(addr, vt);
}

void MainWindow::onDeleteAddresses() {
    auto selected = addressListView_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;
    QList<int> rows;
    for (auto& idx : selected) rows.append(idx.row());
    addressListModel_->removeEntries(rows);
}

void MainWindow::onCopyAddresses() {
    auto selected = addressListView_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;

    std::sort(selected.begin(), selected.end(), [](const QModelIndex& a, const QModelIndex& b) {
        return a.row() < b.row();
    });

    auto allEntries = addressListModel_->toJson();
    QJsonArray copied;
    for (const auto& idx : selected) {
        if (idx.row() >= 0 && idx.row() < allEntries.size())
            copied.append(allEntries[idx.row()].toObject());
    }

    QApplication::clipboard()->setText(
        QString::fromUtf8(QJsonDocument(copied).toJson(QJsonDocument::Compact)));
}

void MainWindow::onPasteAddresses() {
    auto text = QApplication::clipboard()->text().toUtf8();
    QJsonParseError error{};
    auto doc = QJsonDocument::fromJson(text, &error);
    if (error.error != QJsonParseError::NoError)
        return;

    QJsonArray pasted;
    if (doc.isArray()) {
        pasted = doc.array();
    } else if (doc.isObject()) {
        pasted = doc.object()["entries"].toArray();
    }
    if (pasted.isEmpty())
        return;

    auto entries = addressListModel_->toJson();
    for (auto value : pasted) {
        auto obj = value.toObject();
        if (obj.isEmpty())
            continue;
        obj["active"] = false;
        entries.append(obj);
    }
    addressListModel_->fromJson(entries);
}

void MainWindow::onFreezeTimer() {
    if (process_)
        addressListModel_->freezeWrite(process_.get());
}

void MainWindow::onSaveTable() {
    auto path = QFileDialog::getSaveFileName(this, "Save Cheat Table", "",
        "Cheat Tables (*.ct);;JSON Tables (*.json);;All Files (*)");
    if (path.isEmpty()) return;

    if (path.endsWith(".ct")) {
        // Save as CE-compatible XML .CT format
        CheatTable table;
        table.gameName = processLabel_->text().toStdString();
        auto json = addressListModel_->toJson();
        for (auto val : json) {
            auto obj = val.toObject();
            CheatEntry e;
            e.description = obj["description"].toString().toStdString();
            e.address = obj["address"].toString().toULongLong(nullptr, 16);
            auto typeStr = obj["type"].toString().toStdString();
            // Map our JSON type names to ValueType
            if (typeStr == "byte") e.type = ValueType::Byte;
            else if (typeStr == "i16") e.type = ValueType::Int16;
            else if (typeStr == "i32") e.type = ValueType::Int32;
            else if (typeStr == "i64") e.type = ValueType::Int64;
            else if (typeStr == "float") e.type = ValueType::Float;
            else if (typeStr == "double") e.type = ValueType::Double;
            else e.type = ValueType::Int32;
            e.value = obj["value"].toString().toStdString();
            e.active = obj["active"].toBool();
            e.autoAsmScript = obj["asm"].toString().toStdString();
            e.color = obj["color"].toString().toStdString();
            e.dropdownList = obj["dropdown"].toString().toStdString();
            table.entries.push_back(e);
        }
        table.save(path.toStdString());
    } else {
        // Save as JSON
        QJsonObject root;
        root["process"] = processLabel_->text();
        root["entries"] = addressListModel_->toJson();
        QFile f(path);
        if (f.open(QIODevice::WriteOnly))
            f.write(QJsonDocument(root).toJson());
    }
}

void MainWindow::onLoadTable() {
    auto path = QFileDialog::getOpenFileName(this, "Load Cheat Table", "",
        "Cheat Tables (*.ct);;JSON Tables (*.json);;All Files (*)");
    if (path.isEmpty()) return;

    if (path.endsWith(".ct")) {
        // Load CE XML .CT format
        CheatTable table;
        if (!table.load(path.toStdString())) return;
        QJsonArray arr;
        for (auto& e : table.entries) {
            QJsonObject obj;
            obj["description"] = QString::fromStdString(e.description);
            obj["address"] = QString("0x%1").arg(e.address, 0, 16);
            obj["type"] = QString::number((int)e.type);
            obj["value"] = QString::fromStdString(e.value);
            obj["active"] = e.active;
            obj["asm"] = QString::fromStdString(e.autoAsmScript);
            obj["color"] = QString::fromStdString(e.color);
            obj["dropdown"] = QString::fromStdString(e.dropdownList);
            arr.append(obj);
        }
        loadAddressEntries(arr);
    } else {
        // Load JSON
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return;
        auto doc = QJsonDocument::fromJson(f.readAll());
        if (!doc.isObject()) return;
        loadAddressEntries(doc.object()["entries"].toArray());
    }
}

void MainWindow::loadAddressEntries(const QJsonArray& entries) {
    QJsonArray normalized = entries;
    QStringList failures;
    bool skippedForMissingProcess = false;

    for (int i = 0; i < normalized.size(); ++i) {
        auto obj = normalized[i].toObject();
        auto script = obj["asm"].toString();
        if (!obj["active"].toBool() || script.isEmpty())
            continue;

        if (!process_) {
            obj["active"] = false;
            skippedForMissingProcess = true;
            normalized.replace(i, obj);
            continue;
        }

        auto result = autoAsm_.execute(*process_, script.toStdString());
        if (!result.success) {
            obj["active"] = false;
            normalized.replace(i, obj);
            auto desc = obj["description"].toString("Unnamed entry");
            failures << QString("%1: %2").arg(desc, QString::fromStdString(result.error));
        }
    }

    addressListModel_->fromJson(normalized);

    if (skippedForMissingProcess) {
        QMessageBox::warning(this, "Process required",
            "Some active auto-assembler records were loaded inactive because no process is open.");
    }
    if (!failures.isEmpty()) {
        QMessageBox::warning(this, "Auto-assembler activation failed",
            failures.join('\n'));
    }
}

void MainWindow::startCodeFinder(int row, bool writesOnly) {
    if (!process_) return;

    const auto& entries = addressListModel_->entries();
    if (row < 0 || row >= (int)entries.size()) return;
    const auto& entry = entries[row];
    if (entry.isGroup) return;

    auto debugger = std::make_unique<os::LinuxDebugger>();
    auto finder = std::make_unique<CodeFinder>();
    if (!finder->start(*process_, *debugger, entry.address, writesOnly)) {
        QMessageBox::warning(this, "Code finder unavailable",
            "Could not start hardware watchpoint monitoring for this address.");
        return;
    }

    auto* finderPtr = finder.get();
    codeFinderDebuggers_.push_back(std::move(debugger));
    codeFinders_.push_back(std::move(finder));

    auto title = writesOnly ? "Find what writes" : "Find what accesses";
    auto* window = new CodeFinderWindow(finderPtr,
        QString("%1 0x%2").arg(title).arg(entry.address, 0, 16), this);
    window->setAttribute(Qt::WA_DeleteOnClose);
    window->show();
}

void MainWindow::onMemoryView() {
    if (!process_) return;
    auto* browser = new MemoryBrowser(process_.get(), this);
    browser->setAttribute(Qt::WA_DeleteOnClose);
    browser->show();
}

void MainWindow::updateScanButtons() {
    bool hasProcess = (process_ != nullptr);
    bool hasResults = (lastResult_ != nullptr && lastResult_->count() > 0);
    firstScanBtn_->setEnabled(hasProcess);
    nextScanBtn_->setEnabled(hasResults);
    undoScanBtn_->setEnabled(undoResult_ != nullptr);
}

// ═══════════════════════════════════════════════════════════════
// ScanResultsModel
// ═══════════════════════════════════════════════════════════════

ScanResultsModel::ScanResultsModel(QObject* parent) : QAbstractTableModel(parent) {}

void ScanResultsModel::setResult(ScanResult* result, ValueType vt) {
    beginResetModel();
    result_ = result;
    valueType_ = vt;
    endResetModel();
}

void ScanResultsModel::clear() {
    beginResetModel();
    result_ = nullptr;
    endResetModel();
}

int ScanResultsModel::rowCount(const QModelIndex&) const {
    return result_ ? std::min(result_->count(), size_t(10000)) : 0;
}

int ScanResultsModel::columnCount(const QModelIndex&) const { return 2; }

QVariant ScanResultsModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    return section == 0 ? "Address" : "Value";
}

QVariant ScanResultsModel::data(const QModelIndex& index, int role) const {
    if (!result_ || role != Qt::DisplayRole) return {};

    if (index.column() == 0) {
        return QString("0x%1").arg(result_->address(index.row()), 0, 16);
    } else {
        size_t vs = 4;
        switch (valueType_) {
            case ValueType::Byte:   vs = 1; break;
            case ValueType::Int16:  vs = 2; break;
            case ValueType::Int32:  vs = 4; break;
            case ValueType::Int64:  vs = 8; break;
            case ValueType::Float:  vs = 4; break;
            case ValueType::Double: vs = 8; break;
            default: break;
        }
        uint8_t buf[8] = {};
        result_->value(index.row(), buf, vs);

        switch (valueType_) {
            case ValueType::Byte:   return QString::number(buf[0]);
            case ValueType::Int16:  { int16_t v; memcpy(&v, buf, 2); return QString::number(v); }
            case ValueType::Int32:  { int32_t v; memcpy(&v, buf, 4); return QString::number(v); }
            case ValueType::Int64:  { int64_t v; memcpy(&v, buf, 8); return QString::number(v); }
            case ValueType::Float:  { float v; memcpy(&v, buf, 4); return QString::number(v, 'f', 4); }
            case ValueType::Double: { double v; memcpy(&v, buf, 8); return QString::number(v, 'f', 6); }
            default: return "?";
        }
    }
}

uintptr_t ScanResultsModel::addressAt(int row) const {
    return result_ ? result_->address(row) : 0;
}

// ═══════════════════════════════════════════════════════════════
// AddressListModel
// ═══════════════════════════════════════════════════════════════

AddressListModel::AddressListModel(QObject* parent) : QAbstractTableModel(parent) {}

void AddressListModel::addEntry(uintptr_t addr, ValueType type, const QString& desc) {
    beginInsertRows({}, entries_.size(), entries_.size());
    entries_.push_back({false, desc, addr, type, "?"});
    endInsertRows();
}

static const char* typeToStr(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:   return "byte";
        case ValueType::Int16:  return "i16";
        case ValueType::Int32:  return "i32";
        case ValueType::Int64:  return "i64";
        case ValueType::Float:  return "float";
        case ValueType::Double: return "double";
        default: return "i32";
    }
}

static ValueType strToType(const QString& s) {
    if (s == "byte")   return ValueType::Byte;
    if (s == "i16")    return ValueType::Int16;
    if (s == "i32")    return ValueType::Int32;
    if (s == "i64")    return ValueType::Int64;
    if (s == "float")  return ValueType::Float;
    if (s == "double") return ValueType::Double;
    bool ok = false;
    int raw = s.toInt(&ok);
    if (ok) {
        switch (raw) {
            case 0: return ValueType::Byte;
            case 1: return ValueType::Int16;
            case 2: return ValueType::Int32;
            case 3: return ValueType::Int64;
            case 4: return ValueType::Float;
            case 5: return ValueType::Double;
            case 6: return ValueType::String;
            case 8: return ValueType::ByteArray;
            case 9: return ValueType::Binary;
            case 10: return ValueType::All;
            default: break;
        }
    }
    return ValueType::Int32;
}

static QMap<QString, QString> parseDropdownList(const QString& dropdownList) {
    QMap<QString, QString> choices;
    for (const auto& rawItem : dropdownList.split(';', Qt::SkipEmptyParts)) {
        auto item = rawItem.trimmed();
        auto sep = item.indexOf(':');
        if (sep <= 0) continue;
        auto value = item.left(sep).trimmed();
        auto label = item.mid(sep + 1).trimmed();
        if (!value.isEmpty())
            choices[value] = label.isEmpty() ? value : label;
    }
    return choices;
}

static QString displayDropdownValue(const QString& value, const QString& dropdownList) {
    auto choices = parseDropdownList(dropdownList);
    auto it = choices.find(value.trimmed());
    return it == choices.end() ? value : QString("%1 (%2)").arg(it.value(), it.key());
}

static QString resolveDropdownInput(const QString& input, const QString& dropdownList) {
    auto choices = parseDropdownList(dropdownList);
    auto trimmed = input.trimmed();
    if (choices.contains(trimmed))
        return trimmed;
    for (auto it = choices.begin(); it != choices.end(); ++it) {
        if (QString::compare(it.value(), trimmed, Qt::CaseInsensitive) == 0)
            return it.key();
    }
    return input;
}

static QVariant entryForeground(const QString& color) {
    if (color.isEmpty())
        return {};
    auto name = color.startsWith('#') ? color : "#" + color;
    QColor parsed(name);
    return parsed.isValid() ? QVariant(parsed) : QVariant();
}

static size_t vtSize(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:   return 1;
        case ValueType::Int16:  return 2;
        case ValueType::Int32:  return 4;
        case ValueType::Int64:  return 8;
        case ValueType::Float:  return 4;
        case ValueType::Double: return 8;
        default: return 4;
    }
}

static void writeValueToProcess(ProcessHandle* proc, uintptr_t addr, ValueType type, const QString& valStr) {
    uint8_t buf[8] = {};
    size_t vs = vtSize(type);
    switch (type) {
        case ValueType::Byte:   { uint8_t v = valStr.toUInt(); memcpy(buf, &v, 1); break; }
        case ValueType::Int16:  { int16_t v = valStr.toShort(); memcpy(buf, &v, 2); break; }
        case ValueType::Int32:  { int32_t v = valStr.toInt(); memcpy(buf, &v, 4); break; }
        case ValueType::Int64:  { int64_t v = valStr.toLongLong(); memcpy(buf, &v, 8); break; }
        case ValueType::Float:  { float v = valStr.toFloat(); memcpy(buf, &v, 4); break; }
        case ValueType::Double: { double v = valStr.toDouble(); memcpy(buf, &v, 8); break; }
        default: break;
    }
    proc->write(addr, buf, vs);
}

static bool readComparableValue(ProcessHandle* proc, uintptr_t addr, ValueType type, double& value) {
    uint8_t buf[8] = {};
    size_t vs = vtSize(type);
    auto r = proc->read(addr, buf, vs);
    if (!r || *r < vs) return false;

    switch (type) {
        case ValueType::Byte: {
            uint8_t v; memcpy(&v, buf, 1); value = v; return true;
        }
        case ValueType::Int16: {
            int16_t v; memcpy(&v, buf, 2); value = v; return true;
        }
        case ValueType::Int32: {
            int32_t v; memcpy(&v, buf, 4); value = v; return true;
        }
        case ValueType::Int64: {
            int64_t v; memcpy(&v, buf, 8); value = static_cast<double>(v); return true;
        }
        case ValueType::Float: {
            float v; memcpy(&v, buf, 4); value = v; return true;
        }
        case ValueType::Double: {
            double v; memcpy(&v, buf, 8); value = v; return true;
        }
        default:
            return false;
    }
}

static bool parseComparableValue(ValueType type, const QString& valStr, double& value) {
    bool ok = false;
    switch (type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64:
            value = valStr.toLongLong(&ok);
            return ok;
        case ValueType::Float:
        case ValueType::Double:
            value = valStr.toDouble(&ok);
            return ok;
        default:
            return false;
    }
}

void AddressListModel::freezeWrite(ProcessHandle* proc) {
    for (auto& e : entries_) {
        if (!e.active || e.frozenValue.isEmpty()) continue;

        if (e.freezeMode == FreezeMode::Normal) {
            writeValueToProcess(proc, e.address, e.type, e.frozenValue);
            continue;
        }

        // Read current value to compare for directional freeze.
        double current = 0;
        double frozen = 0;
        if (!readComparableValue(proc, e.address, e.type, current) ||
            !parseComparableValue(e.type, e.frozenValue, frozen)) {
            writeValueToProcess(proc, e.address, e.type, e.frozenValue);
            continue;
        }

        bool shouldWrite = false;
        switch (e.freezeMode) {
            case FreezeMode::IncreaseOnly:   shouldWrite = (current < frozen); break;
            case FreezeMode::DecreaseOnly:   shouldWrite = (current > frozen); break;
            case FreezeMode::NeverIncrease:  shouldWrite = (current > frozen); break;
            case FreezeMode::NeverDecrease:  shouldWrite = (current < frozen); break;
            default: shouldWrite = true; break;
        }
        if (shouldWrite)
            writeValueToProcess(proc, e.address, e.type, e.frozenValue);
    }
}

QJsonArray AddressListModel::toJson() const {
    QJsonArray arr;
    for (auto& e : entries_) {
        QJsonObject obj;
        obj["description"] = e.description;
        obj["address"] = QString("0x%1").arg(e.address, 0, 16);
        obj["type"] = typeToStr(e.type);
        obj["value"] = e.currentValue;
        obj["active"] = e.active;
        obj["asm"] = e.autoAsmScript;
        obj["color"] = e.color;
        obj["dropdown"] = e.dropdownList;
        arr.append(obj);
    }
    return arr;
}

void AddressListModel::fromJson(const QJsonArray& arr) {
    beginResetModel();
    entries_.clear();
    for (auto val : arr) {
        auto obj = val.toObject();
        AddressEntry e;
        e.description = obj["description"].toString();
        e.address = obj["address"].toString().toULongLong(nullptr, 16);
        e.type = strToType(obj["type"].toString());
        e.currentValue = obj["value"].toString();
        e.active = obj["active"].toBool();
        e.autoAsmScript = obj["asm"].toString();
        e.color = obj["color"].toString();
        e.dropdownList = obj["dropdown"].toString();
        if (e.active) e.frozenValue = e.currentValue;
        entries_.push_back(e);
    }
    endResetModel();
}

void AddressListModel::setFreezeMode(int row, FreezeMode mode) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].freezeMode = mode;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

void AddressListModel::reportActivationError(const QString& title, const QString& message) {
    if (activationErrorCb_)
        activationErrorCb_(title, message);
}

bool AddressListModel::setEntryActive(int row, bool active) {
    if (row < 0 || row >= (int)entries_.size()) return false;

    auto& e = entries_[row];
    if (e.active == active) return true;

    if (!e.autoAsmScript.isEmpty()) {
        if (!proc_ || !autoAsm_) {
            reportActivationError("Process required",
                "Open a process before activating this auto-assembler record.");
            return false;
        }

        if (active) {
            auto result = autoAsm_->execute(*proc_, e.autoAsmScript.toStdString());
            if (!result.success) {
                reportActivationError("Auto-assembler activation failed",
                    QString::fromStdString(result.error));
                return false;
            }
            e.autoAsmDisableInfo = std::move(result.disableInfo);
        } else {
            auto result = autoAsm_->disable(*proc_, e.autoAsmScript.toStdString(), e.autoAsmDisableInfo);
            if (!result.success) {
                reportActivationError("Auto-assembler deactivation failed",
                    QString::fromStdString(result.error));
                return false;
            }
            e.autoAsmDisableInfo = {};
        }
    }

    e.active = active;
    if (e.active)
        e.frozenValue = e.currentValue;
    else
        e.frozenValue.clear();
    return true;
}

void AddressListModel::removeEntry(int row) {
    if (row < 0 || row >= (int)entries_.size()) return;
    beginRemoveRows({}, row, row);
    entries_.erase(entries_.begin() + row);
    endRemoveRows();
}

void AddressListModel::removeEntries(QList<int> rows) {
    std::sort(rows.begin(), rows.end(), std::greater<int>());
    for (int row : rows)
        removeEntry(row);
}

void AddressListModel::updateValues(ProcessHandle* proc) {
    for (size_t i = 0; i < entries_.size(); ++i) {
        auto& e = entries_[i];
        if (e.active) continue; // Don't overwrite display for frozen entries

        uint8_t buf[8] = {};
        size_t vs = vtSize(e.type);
        auto r = proc->read(e.address, buf, vs);
        if (r) {
            switch (e.type) {
                case ValueType::Byte:   { uint8_t v; memcpy(&v, buf, 1); e.currentValue = QString::number(v); break; }
                case ValueType::Int16:  { int16_t v; memcpy(&v, buf, 2); e.currentValue = QString::number(v); break; }
                case ValueType::Int32:  { int32_t v; memcpy(&v, buf, 4); e.currentValue = QString::number(v); break; }
                case ValueType::Int64:  { int64_t v; memcpy(&v, buf, 8); e.currentValue = QString::number(v); break; }
                case ValueType::Float:  { float v; memcpy(&v, buf, 4); e.currentValue = QString::number(v, 'f', 4); break; }
                case ValueType::Double: { double v; memcpy(&v, buf, 8); e.currentValue = QString::number(v, 'f', 6); break; }
                default: e.currentValue = "?"; break;
            }
        } else {
            e.currentValue = "??";
        }
    }
    if (!entries_.empty())
        emit dataChanged(index(0, 4), index(entries_.size() - 1, 4));
}

int AddressListModel::rowCount(const QModelIndex&) const { return entries_.size(); }
int AddressListModel::columnCount(const QModelIndex&) const { return 5; }

QVariant AddressListModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (section) {
        case 0: return "Active";
        case 1: return "Description";
        case 2: return "Address";
        case 3: return "Type";
        case 4: return "Value";
        default: return {};
    }
}

QVariant AddressListModel::data(const QModelIndex& index, int role) const {
    if (role == Qt::CheckStateRole && index.column() == 0)
        return entries_[index.row()].active ? Qt::Checked : Qt::Unchecked;

    auto& e = entries_[index.row()];
    if (role == Qt::ForegroundRole)
        return entryForeground(e.color);
    if (role == Qt::EditRole) {
        if (index.column() == 1) return e.description;
        if (index.column() == 4) return e.currentValue;
        return {};
    }
    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
        case 1: {
            QString prefix;
            for (int i = 0; i < e.indent; ++i) prefix += "  ";
            return prefix + e.description;
        }
        case 2: return e.isGroup ? QString("") : QString("0x%1").arg(e.address, 0, 16);
        case 3: {
            switch (e.type) {
                case ValueType::Byte:   return "Byte";
                case ValueType::Int16:  return "2 Bytes";
                case ValueType::Int32:  return "4 Bytes";
                case ValueType::Int64:  return "8 Bytes";
                case ValueType::Float:  return "Float";
                case ValueType::Double: return "Double";
                default: return "?";
            }
        }
        case 4: return e.dropdownList.isEmpty()
            ? e.currentValue
            : displayDropdownValue(e.currentValue, e.dropdownList);
        default: return {};
    }
}

Qt::ItemFlags AddressListModel::flags(const QModelIndex& index) const {
    auto f = QAbstractTableModel::flags(index);
    if (index.column() == 0) f |= Qt::ItemIsUserCheckable;
    if (index.column() == 1 || index.column() == 4) f |= Qt::ItemIsEditable;
    return f;
}

bool AddressListModel::setData(const QModelIndex& index, const QVariant& value, int role) {
    if (role == Qt::CheckStateRole && index.column() == 0) {
        auto& e = entries_[index.row()];
        bool requestedActive = (value.toInt() == Qt::Checked);
        if (!setEntryActive(index.row(), requestedActive))
            return false;
        emit dataChanged(index, index);

        // Cascade to children if this is a group
        if (e.isGroup) {
            int parentIndent = e.indent;
            for (int i = index.row() + 1; i < (int)entries_.size(); ++i) {
                if (entries_[i].indent <= parentIndent) break;
                setEntryActive(i, requestedActive);
            }
            emit dataChanged(this->index(index.row() + 1, 0),
                this->index(std::min((int)entries_.size() - 1, index.row() + 50), columnCount() - 1));
        }
        return true;
    }
    if (role == Qt::EditRole) {
        if (index.column() == 1) {
            entries_[index.row()].description = value.toString();
            emit dataChanged(index, index, {Qt::DisplayRole, Qt::EditRole});
            return true;
        }
        if (index.column() == 4) {
            auto& e = entries_[index.row()];
            auto rawValue = e.dropdownList.isEmpty()
                ? value.toString()
                : resolveDropdownInput(value.toString(), e.dropdownList);
            e.currentValue = rawValue;
            if (e.active) e.frozenValue = rawValue;
            if (proc_)
                writeValueToProcess(proc_, e.address, e.type, rawValue);
            emit dataChanged(index, index);
            return true;
        }
    }
    return false;
}

} // namespace ce::gui
