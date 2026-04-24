#include "gui/codereferences.hpp"
#include "analysis/code_analysis.hpp"

#include <QHeaderView>
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
    auto* analyzeBtn = new QPushButton("Analyze");
    top->addWidget(moduleCombo_, 1);
    top->addWidget(analyzeBtn);
    layout->addLayout(top);

    auto* tabs = new QTabWidget;
    stringsTable_ = new QTableWidget;
    functionsTable_ = new QTableWidget;
    for (auto* table : {stringsTable_, functionsTable_}) {
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
    tabs->addTab(stringsTable_, "Referenced Strings");
    tabs->addTab(functionsTable_, "Referenced Functions");
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

    fillTable(stringsTable_, strings);
    fillTable(functionsTable_, functions);
    statusLabel_->setText(QString("%1: %2 strings, %3 functions")
        .arg(QString::fromStdString(module.name))
        .arg(strings.size())
        .arg(functions.size()));
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

} // namespace ce::gui
