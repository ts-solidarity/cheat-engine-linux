#include "gui/scripteditor.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QFont>
#include <QLabel>
#include <QToolBar>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>

namespace ce::gui {

ScriptEditor::ScriptEditor(ProcessHandle* proc, AutoAssembler* autoAsm, QWidget* parent)
    : QMainWindow(parent), proc_(proc), autoAsm_(autoAsm) {

    setWindowTitle("Auto Assembler");
    resize(700, 500);

    // Toolbar
    auto* toolbar = new QToolBar;
    executeBtn_ = new QPushButton("Execute");
    executeBtn_->setStyleSheet("font-weight: bold; color: green;");
    connect(executeBtn_, &QPushButton::clicked, this, &ScriptEditor::onExecute);

    disableBtn_ = new QPushButton("Disable");
    disableBtn_->setEnabled(false);
    connect(disableBtn_, &QPushButton::clicked, this, &ScriptEditor::onDisable);

    auto* checkBtn = new QPushButton("Syntax Check");
    connect(checkBtn, &QPushButton::clicked, this, &ScriptEditor::onCheck);

    auto* loadBtn = new QPushButton("Load");
    connect(loadBtn, &QPushButton::clicked, this, [this]() {
        auto path = QFileDialog::getOpenFileName(this, "Load Script", "", "CE Scripts (*.cea *.asm);;All Files (*)");
        if (path.isEmpty()) return;
        QFile f(path);
        if (f.open(QIODevice::ReadOnly)) {
            editor_->setPlainText(QTextStream(&f).readAll());
        }
    });

    auto* saveBtn = new QPushButton("Save");
    connect(saveBtn, &QPushButton::clicked, this, [this]() {
        auto path = QFileDialog::getSaveFileName(this, "Save Script", "", "CE Scripts (*.cea);;All Files (*)");
        if (path.isEmpty()) return;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly)) {
            QTextStream(&f) << editor_->toPlainText();
        }
    });

    toolbar->addWidget(executeBtn_);
    toolbar->addWidget(disableBtn_);
    toolbar->addSeparator();
    toolbar->addWidget(checkBtn);
    toolbar->addSeparator();
    toolbar->addWidget(loadBtn);
    toolbar->addWidget(saveBtn);
    addToolBar(toolbar);

    // Main content: editor (top) + output (bottom)
    auto* splitter = new QSplitter(Qt::Vertical);

    editor_ = new QPlainTextEdit;
    editor_->setFont(QFont("Monospace", 10));
    editor_->setPlaceholderText(
        "[ENABLE]\n"
        "// Your auto-assembler script here\n"
        "alloc(newmem, 1024)\n"
        "label(returnhere)\n"
        "\n"
        "newmem:\n"
        "  mov eax, 999\n"
        "  jmp returnhere\n"
        "\n"
        "[DISABLE]\n"
        "dealloc(newmem)\n"
    );
    splitter->addWidget(editor_);

    output_ = new QTextEdit;
    output_->setReadOnly(true);
    output_->setFont(QFont("Monospace", 9));
    output_->setMaximumHeight(150);
    output_->setStyleSheet("background: #1e1e2e; color: #cdd6f4;");
    splitter->addWidget(output_);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    setCentralWidget(splitter);
}

void ScriptEditor::setScript(const std::string& script) {
    editor_->setPlainText(QString::fromStdString(script));
}

void ScriptEditor::onExecute() {
    if (!proc_ || !autoAsm_) {
        output_->setTextColor(Qt::red);
        output_->append("No process selected!");
        return;
    }

    auto script = editor_->toPlainText().toStdString();
    output_->clear();
    output_->setTextColor(QColor(0xcd, 0xd6, 0xf4));
    output_->append("Executing...");

    auto result = autoAsm_->execute(*proc_, script);

    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(Qt::green);
        output_->append("Script executed successfully.");
        lastDisableInfo_ = result.disableInfo;
        enabled_ = true;
        executeBtn_->setEnabled(false);
        disableBtn_->setEnabled(true);
    } else {
        output_->setTextColor(Qt::red);
        output_->append("FAILED: " + QString::fromStdString(result.error));
    }
}

void ScriptEditor::onDisable() {
    if (!proc_ || !autoAsm_ || !enabled_) return;

    auto script = editor_->toPlainText().toStdString();
    output_->clear();
    output_->setTextColor(QColor(0xcd, 0xd6, 0xf4));
    output_->append("Disabling...");

    auto result = autoAsm_->disable(*proc_, script, lastDisableInfo_);

    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(Qt::green);
        output_->append("Script disabled.");
        enabled_ = false;
        executeBtn_->setEnabled(true);
        disableBtn_->setEnabled(false);
    }
}

void ScriptEditor::onCheck() {
    auto script = editor_->toPlainText().toStdString();
    output_->clear();

    auto result = autoAsm_->check(script);
    for (auto& msg : result.log)
        output_->append(QString::fromStdString(msg));

    if (result.success) {
        output_->setTextColor(Qt::green);
        output_->append("Syntax check passed.");
    }
}

} // namespace ce::gui
