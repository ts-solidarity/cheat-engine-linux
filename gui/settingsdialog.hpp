#pragma once
#include <QDialog>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>

namespace ce::gui {

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget* parent = nullptr);
private slots:
    void onApply();
private:
    QSpinBox* alignSpin_;
    QCheckBox* writableCheck_;
    QCheckBox* executableCheck_;
    QCheckBox* hexUpperCheck_;
    QSpinBox* fontSizeSpin_;
    QComboBox* bpTypeCombo_;
};

} // namespace ce::gui
