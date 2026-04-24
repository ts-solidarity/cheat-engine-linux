#pragma once

#include "analysis/code_analysis.hpp"
#include "platform/process_api.hpp"
#include <QComboBox>
#include <QLabel>
#include <QMainWindow>
#include <QTableWidget>

namespace ce::gui {

class CodeReferencesWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit CodeReferencesWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

signals:
    void navigateTo(uintptr_t addr);

private:
    void analyzeSelectedModule();
    void fillTable(QTableWidget* table, const std::vector<ce::CodeRef>& refs);
    ce::ModuleInfo selectedModule() const;

    ce::ProcessHandle* proc_;
    std::vector<ce::ModuleInfo> modules_;
    QComboBox* moduleCombo_;
    QLabel* statusLabel_;
    QTableWidget* stringsTable_;
    QTableWidget* functionsTable_;
};

} // namespace ce::gui
