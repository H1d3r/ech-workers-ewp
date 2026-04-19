#pragma once

#include <QObject>
#include <QString>

class SystemProxy : public QObject
{
    Q_OBJECT

public:
    explicit SystemProxy(QObject *parent = nullptr);
    ~SystemProxy();

    bool enable(const QString &proxyAddr);
    void disable();
    bool isEnabled() const { return enabled; }

private:
    bool enabled = false;
    QString currentProxy;
    QString pacFilePath;  // P1-19: PAC file path for cleanup
    
    // P2-34: Save original proxy state for restoration
    struct OriginalProxyState {
        bool saved = false;
        quint32 flags = 0;
        QString proxyServer;
        QString proxyBypass;
        QString autoConfigUrl;
    };
    OriginalProxyState originalState;
    
    // P1-19: PAC file generation and configuration
    bool generatePACFile(const QString &proxyAddr, QString &outPath);
    bool setPACUrl(const QString &pacUrl);
    bool clearPACUrl();
    
    // P2-34: Save and restore original proxy settings
    void saveOriginalProxyState();
    void restoreOriginalProxyState();
};
