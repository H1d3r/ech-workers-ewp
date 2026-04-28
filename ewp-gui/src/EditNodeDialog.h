#pragma once

#include <QDialog>
#include "EWPNode.h"

QT_BEGIN_NAMESPACE
namespace Ui { class EditNodeDialog; }
QT_END_NAMESPACE

// v2 EditNodeDialog. Trojan/flow/PQC/TLS-version selectors are
// removed — v2 mandates EWP + TLS 1.3 + ML-KEM-768 + Mozilla CA.
class EditNodeDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EditNodeDialog(QWidget *parent = nullptr);
    ~EditNodeDialog();

    void setNode(const EWPNode &node);
    EWPNode getNode() const;

private slots:
    void onTransportModeChanged(int index);
    void onGenerateUUID();

private:
    void updateVisibility();

    Ui::EditNodeDialog *ui;
    EWPNode currentNode;
};
