#include "gui/settingsdialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QSettings>

namespace ce::gui {

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Settings");
    resize(400, 350);

    auto* layout = new QVBoxLayout(this);

    // Scan defaults
    auto* scanGroup = new QGroupBox("Scan Defaults");
    auto* scanLayout = new QVBoxLayout(scanGroup);
    auto* alignRow = new QHBoxLayout;
    alignRow->addWidget(new QLabel("Default alignment:"));
    alignSpin_ = new QSpinBox;
    alignSpin_->setRange(1, 16);
    alignSpin_->setValue(QSettings().value("scan/alignment", 4).toInt());
    alignRow->addWidget(alignSpin_);
    scanLayout->addLayout(alignRow);
    writableCheck_ = new QCheckBox("Scan writable memory only");
    writableCheck_->setChecked(QSettings().value("scan/writable", true).toBool());
    scanLayout->addWidget(writableCheck_);
    executableCheck_ = new QCheckBox("Scan executable memory only");
    executableCheck_->setChecked(QSettings().value("scan/executable", false).toBool());
    scanLayout->addWidget(executableCheck_);
    layout->addWidget(scanGroup);

    // Display
    auto* displayGroup = new QGroupBox("Display");
    auto* displayLayout = new QVBoxLayout(displayGroup);
    hexUpperCheck_ = new QCheckBox("Uppercase hex");
    hexUpperCheck_->setChecked(QSettings().value("display/hexUpper", false).toBool());
    displayLayout->addWidget(hexUpperCheck_);
    auto* fontRow = new QHBoxLayout;
    fontRow->addWidget(new QLabel("Font size:"));
    fontSizeSpin_ = new QSpinBox;
    fontSizeSpin_->setRange(8, 20);
    fontSizeSpin_->setValue(QSettings().value("display/fontSize", 10).toInt());
    fontRow->addWidget(fontSizeSpin_);
    displayLayout->addLayout(fontRow);
    layout->addWidget(displayGroup);

    // Debug
    auto* debugGroup = new QGroupBox("Debug");
    auto* debugLayout = new QVBoxLayout(debugGroup);
    auto* bpRow = new QHBoxLayout;
    bpRow->addWidget(new QLabel("Default breakpoint:"));
    bpTypeCombo_ = new QComboBox;
    bpTypeCombo_->addItems({"Hardware", "Software"});
    bpTypeCombo_->setCurrentIndex(QSettings().value("debug/bpType", 0).toInt());
    bpRow->addWidget(bpTypeCombo_);
    debugLayout->addLayout(bpRow);
    layout->addWidget(debugGroup);

    // Buttons
    auto* btnRow = new QHBoxLayout;
    auto* okBtn = new QPushButton("OK");
    connect(okBtn, &QPushButton::clicked, this, [this]() { onApply(); accept(); });
    auto* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    btnRow->addStretch();
    btnRow->addWidget(okBtn);
    btnRow->addWidget(cancelBtn);
    layout->addLayout(btnRow);
}

void SettingsDialog::onApply() {
    QSettings s;
    s.setValue("scan/alignment", alignSpin_->value());
    s.setValue("scan/writable", writableCheck_->isChecked());
    s.setValue("scan/executable", executableCheck_->isChecked());
    s.setValue("display/hexUpper", hexUpperCheck_->isChecked());
    s.setValue("display/fontSize", fontSizeSpin_->value());
    s.setValue("debug/bpType", bpTypeCombo_->currentIndex());
}

} // namespace ce::gui
