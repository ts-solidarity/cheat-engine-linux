#pragma once

#include "core/autoasm.hpp"
#include "platform/process_api.hpp"

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QTextEdit>
#include <QPushButton>

namespace ce::gui {

class ScriptEditor : public QMainWindow {
    Q_OBJECT
public:
    explicit ScriptEditor(ce::ProcessHandle* proc, ce::AutoAssembler* autoAsm, QWidget* parent = nullptr);

    void setScript(const std::string& script);

private slots:
    void onExecute();
    void onDisable();
    void onCheck();

private:
    ce::ProcessHandle* proc_;
    ce::AutoAssembler* autoAsm_;
    QPlainTextEdit* editor_;
    QTextEdit* output_;
    QPushButton* executeBtn_;
    QPushButton* disableBtn_;
    ce::DisableInfo lastDisableInfo_;
    bool enabled_ = false;
};

} // namespace ce::gui
