#include "gui/codereferences.hpp"
#include "analysis/code_analysis.hpp"

#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>

namespace ce::gui {

CodeReferencesWindow::CodeReferencesWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Code References");
    resize(900, 560);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    auto* top = new QHBoxLayout;
    moduleCombo_ = new QComboBox;
    minCaveSizeSpin_ = new QSpinBox;
    minCaveSizeSpin_->setRange(4, 4096);
    minCaveSizeSpin_->setValue(16);
    assemblyPatternEdit_ = new QLineEdit;
    assemblyPatternEdit_->setPlaceholderText("Assembly pattern");
    auto* analyzeBtn = new QPushButton("Analyze");
    top->addWidget(moduleCombo_, 1);
    top->addWidget(new QLabel("Min cave bytes:"));
    top->addWidget(minCaveSizeSpin_);
    top->addWidget(assemblyPatternEdit_, 1);
    top->addWidget(analyzeBtn);
    layout->addLayout(top);

    auto* tabs = new QTabWidget;
    stringsTable_ = new QTableWidget;
    functionsTable_ = new QTableWidget;
    ripRelativeTable_ = new QTableWidget;
    assemblyTable_ = new QTableWidget;
    cavesTable_ = new QTableWidget;
    for (auto* table : {stringsTable_, functionsTable_, ripRelativeTable_, assemblyTable_}) {
        table->setColumnCount(3);
        table->setHorizontalHeaderLabels({"Instruction", "Target", "Text"});
        table->horizontalHeader()->setStretchLastSection(true);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->verticalHeader()->setVisible(false);
        connect(table, &QTableWidget::cellDoubleClicked, this, [this, table](int row, int column) {
            bool ok = false;
            auto text = table->item(row, column == 1 ? 1 : 0)->text();
            auto addr = text.toULongLong(&ok, 16);
            if (ok) emit navigateTo(addr);
        });
    }
    cavesTable_->setColumnCount(2);
    cavesTable_->setHorizontalHeaderLabels({"Address", "Size"});
    cavesTable_->horizontalHeader()->setStretchLastSection(true);
    cavesTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    cavesTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    cavesTable_->verticalHeader()->setVisible(false);
    connect(cavesTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        bool ok = false;
        auto addr = cavesTable_->item(row, 0)->text().toULongLong(&ok, 16);
        if (ok) emit navigateTo(addr);
    });
    tabs->addTab(stringsTable_, "Referenced Strings");
    tabs->addTab(functionsTable_, "Referenced Functions");
    tabs->addTab(ripRelativeTable_, "RIP-relative");
    tabs->addTab(assemblyTable_, "Assembly Scan");
    tabs->addTab(cavesTable_, "Code Caves");
    layout->addWidget(tabs, 1);

    statusLabel_ = new QLabel;
    layout->addWidget(statusLabel_);

    setCentralWidget(central);
    connect(analyzeBtn, &QPushButton::clicked, this, &CodeReferencesWindow::analyzeSelectedModule);

    if (proc_) {
        modules_ = proc_->modules();
        for (const auto& module : modules_) {
            auto label = QString("%1  %2")
                .arg(module.base, 16, 16, QChar('0'))
                .arg(QString::fromStdString(module.name.empty() ? module.path : module.name));
            moduleCombo_->addItem(label);
        }
    }

    statusLabel_->setText(QString("%1 modules available").arg(modules_.size()));
}

ModuleInfo CodeReferencesWindow::selectedModule() const {
    auto index = moduleCombo_->currentIndex();
    if (index < 0 || index >= (int)modules_.size()) return {};
    return modules_[index];
}

void CodeReferencesWindow::analyzeSelectedModule() {
    if (!proc_ || modules_.empty()) return;

    auto module = selectedModule();
    CodeAnalyzer analyzer;
    auto strings = analyzer.findReferencedStrings(*proc_, module);
    auto functions = analyzer.findReferencedFunctions(*proc_, module);
    auto ripRelative = analyzer.findRipRelativeInstructions(*proc_, module);
    auto assembly = assemblyPatternEdit_->text().trimmed().isEmpty()
        ? std::vector<CodeRef>{}
        : analyzer.findAssemblyPattern(*proc_, module, assemblyPatternEdit_->text().toStdString());
    auto caves = analyzer.findCodeCaves(*proc_, module, minCaveSizeSpin_->value());

    fillTable(stringsTable_, strings);
    fillTable(functionsTable_, functions);
    fillTable(ripRelativeTable_, ripRelative);
    fillTable(assemblyTable_, assembly);
    fillCavesTable(caves);
    statusLabel_->setText(QString("%1: %2 strings, %3 functions, %4 RIP-relative, %5 assembly, %6 caves")
        .arg(QString::fromStdString(module.name))
        .arg(strings.size())
        .arg(functions.size())
        .arg(ripRelative.size())
        .arg(assembly.size())
        .arg(caves.size()));
}

void CodeReferencesWindow::fillTable(QTableWidget* table, const std::vector<CodeRef>& refs) {
    table->setRowCount((int)refs.size());
    for (int row = 0; row < (int)refs.size(); ++row) {
        const auto& ref = refs[row];
        table->setItem(row, 0, new QTableWidgetItem(QString("%1").arg(ref.address, 16, 16, QChar('0'))));
        table->setItem(row, 1, new QTableWidgetItem(QString("%1").arg(ref.target, 16, 16, QChar('0'))));
        table->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(ref.text)));
    }
}

void CodeReferencesWindow::fillCavesTable(const std::vector<CodeCave>& caves) {
    cavesTable_->setRowCount((int)caves.size());
    for (int row = 0; row < (int)caves.size(); ++row) {
        const auto& cave = caves[row];
        cavesTable_->setItem(row, 0, new QTableWidgetItem(QString("%1").arg(cave.address, 16, 16, QChar('0'))));
        cavesTable_->setItem(row, 1, new QTableWidgetItem(QString::number(cave.size)));
    }
}

} // namespace ce::gui
