#include "CoreProcess.h"
#include "ConfigGenerator.h"
#include "SettingsDialog.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QNetworkRequest>
#include <QUrl>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>

CoreProcess::CoreProcess(QObject *parent)
    : QObject(parent)
{
    coreExecutable = findCoreExecutable();
    networkManager = new QNetworkAccessManager(this);
    retryTimer = new QTimer(this);
    retryTimer->setSingleShot(true);
    connect(retryTimer, &QTimer::timeout, this, &CoreProcess::attemptReconnect);
}

CoreProcess::~CoreProcess()
{
    stop();
}

QString CoreProcess::findCoreExecutable()
{
    QString appDir = QCoreApplication::applicationDirPath();

#ifdef Q_OS_WIN
    QStringList candidates = {
        appDir + "/ewp-core.exe",
        appDir + "/ewp-core-client.exe",
        appDir + "/../ewp-core.exe",
        appDir + "/../ewp-core-client.exe",
    };
    QString fallback = "ewp-core.exe";
#else
    QStringList candidates = {
        appDir + "/ewp-core",
        appDir + "/ewp-core-client",
        appDir + "/../ewp-core",
        appDir + "/../ewp-core-client",
    };
    QString fallback = "ewp-core";
#endif

    for (const QString &path : candidates) {
        QFileInfo fi(path);
        if (fi.exists()) {
            return fi.absoluteFilePath();
        }
    }

    return fallback;
}

bool CoreProcess::start(const EWPNode &node, bool tunMode)
{
    retryCount = 0;
    retryTimer->stop();
    return startCore(node, tunMode);
}

bool CoreProcess::startCore(const EWPNode &node, bool tunMode)
{
    if (isRunning()) {
        lastError = "进程已在运行";
        return false;
    }
    
    if (!QFile::exists(coreExecutable)) {
        lastError = "找不到核心文件: " + coreExecutable;
        emit errorOccurred(lastError);
        return false;
    }
    
    if (!node.isValid()) {
        lastError = "节点配置无效";
        emit errorOccurred(lastError);
        return false;
    }
    
    lastNode = node;
    lastTunMode = tunMode;
    
    configFilePath = generateConfigFile(node, tunMode);
    if (configFilePath.isEmpty()) {
        lastError = "生成配置文件失败";
        emit errorOccurred(lastError);
        return false;
    }
    
    QStringList args;
    args << "-c" << configFilePath;
    
    process = new QProcess(this);
    
    connect(process, &QProcess::started, this, &CoreProcess::onProcessStarted);
    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &CoreProcess::onProcessFinished);
    connect(process, &QProcess::errorOccurred, this, &CoreProcess::onProcessError);
    connect(process, &QProcess::readyReadStandardOutput, 
            this, &CoreProcess::onReadyReadStandardOutput);
    connect(process, &QProcess::readyReadStandardError, 
            this, &CoreProcess::onReadyReadStandardError);
    
    qDebug() << "启动核心:" << coreExecutable << args;
    
    process->start(coreExecutable, args);
    
    if (!process->waitForStarted(5000)) {
        lastError = "启动超时";
        emit errorOccurred(lastError);
        delete process;
        process = nullptr;
        return false;
    }
    
    return true;
}

void CoreProcess::stop()
{
    if (!isRunning() && !retryTimer->isActive()) return;
    
    retryCount = 0;
    retryTimer->stop();
    
    if (!isRunning()) return;
    
    gracefulStop = true;
    
    // 尝试通过控制服务器优雅退出
    if (!controlAddr.isEmpty()) {
        sendQuitRequest();
        // 等待短时间，如果没有退出则强制终止
        if (process->waitForFinished(500)) {
            delete process;
            process = nullptr;
            
            // 清理临时配置文件
            if (!configFilePath.isEmpty() && QFile::exists(configFilePath)) {
                QFile::remove(configFilePath);
            }
            
            return;
        }
    }
    
    // 快速终止
    process->terminate();
    if (!process->waitForFinished(300)) {
        process->kill();
        process->waitForFinished(200);
    }
    
    delete process;
    process = nullptr;
    
    // 清理临时配置文件
    if (!configFilePath.isEmpty() && QFile::exists(configFilePath)) {
        QFile::remove(configFilePath);
    }
}

void CoreProcess::sendQuitRequest()
{
    if (controlAddr.isEmpty()) return;
    
    QUrl url(QString("http://%1/quit").arg(controlAddr));
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setTransferTimeout(500);  // 500ms 超时
    
    QNetworkReply *reply = networkManager->post(request, QByteArray());
    connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

bool CoreProcess::isRunning() const
{
    return process && process->state() == QProcess::Running;
}

QString CoreProcess::generateConfigFile(const EWPNode &node, bool tunMode)
{
    SettingsDialog::AppSettings settings = SettingsDialog::loadFromRegistry();
    listenAddr = settings.listenAddr;
    QJsonObject config = ConfigGenerator::generateClientConfig(node, settings, tunMode);
    
    QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    QString configPath = tempDir + QString("/ewp-gui-config-%1.json").arg(QCoreApplication::applicationPid());
    
    if (!ConfigGenerator::saveConfig(config, configPath)) {
        qWarning() << "Failed to save config to:" << configPath;
        return QString();
    }
    
    qDebug() << "Generated config file:" << configPath;
    return configPath;
}

void CoreProcess::onProcessStarted()
{
    emit started();
}

void CoreProcess::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    Q_UNUSED(exitCode)
    
    bool crashed = (exitStatus == QProcess::CrashExit && !gracefulStop);
    
    gracefulStop = false;
    controlAddr.clear();
    emit stopped();
    
    if (crashed) {
        scheduleReconnect();
    }
}

void CoreProcess::scheduleReconnect()
{
    if (retryCount >= kMaxRetries) {
        emit reconnectFailed();
        retryCount = 0;
        return;
    }
    
    int delaySec = 2 << retryCount;
    retryCount++;
    
    emit reconnecting(retryCount, kMaxRetries);
    emit logReceived(QString("⚠️ 核心进程崩溃，%1 秒后尝试第 %2/%3 次重连...")
                         .arg(delaySec).arg(retryCount).arg(kMaxRetries));
    
    retryTimer->start(delaySec * 1000);
}

void CoreProcess::attemptReconnect()
{
    emit logReceived(QString("🔄 正在尝试重连 (%1/%2)...").arg(retryCount).arg(kMaxRetries));
    
    if (!startCore(lastNode, lastTunMode)) {
        scheduleReconnect();
    }
}

void CoreProcess::onProcessError(QProcess::ProcessError error)
{
    // 优雅退出时忽略 Crashed 错误（Windows 上 terminate() 会触发此错误）
    if (gracefulStop && error == QProcess::Crashed) {
        return;
    }
    
    QString errorMsg;
    
    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = "进程启动失败";
            break;
        case QProcess::Crashed:
            errorMsg = "进程崩溃";
            break;
        case QProcess::Timedout:
            errorMsg = "进程超时";
            break;
        default:
            errorMsg = "未知错误";
            break;
    }
    
    emit errorOccurred(errorMsg);
}

void CoreProcess::onReadyReadStandardOutput()
{
    if (!process) return;
    
    QByteArray data = process->readAllStandardOutput();
    QString text = QString::fromUtf8(data).trimmed();
    
    if (!text.isEmpty()) {
        for (const auto &line : text.split('\n')) {
            QString trimmedLine = line.trimmed();
            // 解析控制服务器地址
            if (trimmedLine.startsWith("CONTROL_ADDR=")) {
                controlAddr = trimmedLine.mid(13);
            }
            emit logReceived(trimmedLine);
        }
    }
}

void CoreProcess::onReadyReadStandardError()
{
    if (!process) return;
    
    QByteArray data = process->readAllStandardError();
    QString text = QString::fromUtf8(data).trimmed();
    
    if (!text.isEmpty()) {
        for (const auto &line : text.split('\n')) {
            emit logReceived("[ERR] " + line.trimmed());
        }
    }
}
