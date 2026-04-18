#include "SystemProxy.h"
#include <QDebug>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QTextStream>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wininet.h>
#endif

SystemProxy::SystemProxy(QObject *parent)
    : QObject(parent)
{
}

SystemProxy::~SystemProxy()
{
    if (enabled) {
        disable();
    }
    
    // P1-19: Clean up PAC file on destruction
    if (!pacFilePath.isEmpty() && QFile::exists(pacFilePath)) {
        QFile::remove(pacFilePath);
    }
}

bool SystemProxy::enable(const QString &proxyAddr)
{
#ifdef Q_OS_WIN
    // P2-34: Save original proxy state before making changes
    if (!originalState.saved) {
        saveOriginalProxyState();
    }
    
    // P1-19: Generate PAC file for better Chromium compatibility
    QString pacPath;
    if (!generatePACFile(proxyAddr, pacPath)) {
        qWarning() << "生成 PAC 文件失败";
        return false;
    }
    
    pacFilePath = pacPath;
    QString pacUrl = "file:///" + pacPath.replace("\\", "/");
    
    INTERNET_PER_CONN_OPTION_LIST list;
    INTERNET_PER_CONN_OPTION options[4];
    DWORD nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    
    std::wstring proxyWStr = proxyAddr.toStdWString();
    std::wstring bypassWStr = L"localhost;127.*;10.*;172.16.*;192.168.*;<local>";
    std::wstring pacUrlWStr = pacUrl.toStdWString();
    
    // P1-19: Set both proxy server AND PAC URL for maximum compatibility
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL;
    
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = const_cast<LPWSTR>(proxyWStr.c_str());
    
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = const_cast<LPWSTR>(bypassWStr.c_str());
    
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    options[3].Value.pszValue = const_cast<LPWSTR>(pacUrlWStr.c_str());
    
    list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    list.pszConnection = NULL;
    list.dwOptionCount = 4;
    list.dwOptionError = 0;
    list.pOptions = options;
    
    if (!InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, nSize)) {
        qWarning() << "设置系统代理失败";
        return false;
    }
    
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    
    enabled = true;
    currentProxy = proxyAddr;
    qDebug() << "系统代理已启用 (含 PAC):" << proxyAddr;
    qDebug() << "PAC URL:" << pacUrl;
    qDebug() << "注意: Chromium 系浏览器(Chrome/Edge)可能需要额外配置才能正确使用代理";
    qDebug() << "建议: 启动浏览器时添加参数 --proxy-server=" << proxyAddr;
    return true;
#else
    Q_UNUSED(proxyAddr)
    qWarning() << "系统代理设置仅支持 Windows";
    return false;
#endif
}

void SystemProxy::disable()
{
#ifdef Q_OS_WIN
    // P2-34: Restore original proxy state instead of forcing DIRECT
    if (originalState.saved) {
        restoreOriginalProxyState();
    } else {
        // Fallback: set to DIRECT if no original state was saved
        INTERNET_PER_CONN_OPTION_LIST list;
        INTERNET_PER_CONN_OPTION options[1];
        DWORD nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
        
        options[0].dwOption = INTERNET_PER_CONN_FLAGS;
        options[0].Value.dwValue = PROXY_TYPE_DIRECT;
        
        list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
        list.pszConnection = NULL;
        list.dwOptionCount = 1;
        list.dwOptionError = 0;
        list.pOptions = options;
        
        InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, nSize);
    }
    
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    
    // P1-19: Clean up PAC file
    if (!pacFilePath.isEmpty() && QFile::exists(pacFilePath)) {
        QFile::remove(pacFilePath);
        pacFilePath.clear();
    }
    
    enabled = false;
    currentProxy.clear();
    qDebug() << "系统代理已禁用" << (originalState.saved ? "(已恢复原始设置)" : "");
#endif
}

// P1-19: Generate PAC file for proxy configuration
bool SystemProxy::generatePACFile(const QString &proxyAddr, QString &outPath)
{
    QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    QString pacPath = QDir(tempDir).filePath("ewp-proxy.pac");
    
    QFile pacFile(pacPath);
    if (!pacFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "无法创建 PAC 文件:" << pacPath;
        return false;
    }
    
    QTextStream out(&pacFile);
    
    // PAC file content - routes all traffic through proxy except local addresses
    out << "function FindProxyForURL(url, host) {\n";
    out << "    // Bypass proxy for local addresses\n";
    out << "    if (isPlainHostName(host) ||\n";
    out << "        shExpMatch(host, \"*.local\") ||\n";
    out << "        isInNet(host, \"10.0.0.0\", \"255.0.0.0\") ||\n";
    out << "        isInNet(host, \"172.16.0.0\", \"255.240.0.0\") ||\n";
    out << "        isInNet(host, \"192.168.0.0\", \"255.255.0.0\") ||\n";
    out << "        isInNet(host, \"127.0.0.0\", \"255.0.0.0\")) {\n";
    out << "        return \"DIRECT\";\n";
    out << "    }\n";
    out << "    \n";
    out << "    // All other traffic goes through proxy\n";
    out << "    return \"PROXY " << proxyAddr << "; DIRECT\";\n";
    out << "}\n";
    
    pacFile.close();
    outPath = pacPath;
    
    qDebug() << "PAC 文件已生成:" << pacPath;
    return true;
}

// P2-34: Save original proxy state before enabling our proxy
void SystemProxy::saveOriginalProxyState()
{
#ifdef Q_OS_WIN
    INTERNET_PER_CONN_OPTION_LIST list;
    INTERNET_PER_CONN_OPTION options[4];
    DWORD nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    
    list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    list.pszConnection = NULL;
    list.dwOptionCount = 4;
    list.dwOptionError = 0;
    list.pOptions = options;
    
    if (InternetQueryOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &nSize)) {
        originalState.flags = options[0].Value.dwValue;
        
        if (options[1].Value.pszValue) {
            originalState.proxyServer = QString::fromWCharArray(options[1].Value.pszValue);
            GlobalFree(options[1].Value.pszValue);
        }
        
        if (options[2].Value.pszValue) {
            originalState.proxyBypass = QString::fromWCharArray(options[2].Value.pszValue);
            GlobalFree(options[2].Value.pszValue);
        }
        
        if (options[3].Value.pszValue) {
            originalState.autoConfigUrl = QString::fromWCharArray(options[3].Value.pszValue);
            GlobalFree(options[3].Value.pszValue);
        }
        
        originalState.saved = true;
        qDebug() << "已保存原始代理设置:" 
                 << "flags=" << originalState.flags
                 << "server=" << originalState.proxyServer
                 << "bypass=" << originalState.proxyBypass
                 << "pac=" << originalState.autoConfigUrl;
    } else {
        qWarning() << "无法查询原始代理设置";
    }
#endif
}

// P2-34: Restore original proxy state when disabling
void SystemProxy::restoreOriginalProxyState()
{
#ifdef Q_OS_WIN
    if (!originalState.saved) {
        qWarning() << "没有保存的原始代理状态";
        return;
    }
    
    INTERNET_PER_CONN_OPTION_LIST list;
    INTERNET_PER_CONN_OPTION options[4];
    DWORD nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    
    std::wstring proxyServerWStr = originalState.proxyServer.toStdWString();
    std::wstring proxyBypassWStr = originalState.proxyBypass.toStdWString();
    std::wstring autoConfigUrlWStr = originalState.autoConfigUrl.toStdWString();
    
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = originalState.flags;
    
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = originalState.proxyServer.isEmpty() 
        ? NULL 
        : const_cast<LPWSTR>(proxyServerWStr.c_str());
    
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = originalState.proxyBypass.isEmpty() 
        ? NULL 
        : const_cast<LPWSTR>(proxyBypassWStr.c_str());
    
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    options[3].Value.pszValue = originalState.autoConfigUrl.isEmpty() 
        ? NULL 
        : const_cast<LPWSTR>(autoConfigUrlWStr.c_str());
    
    list.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    list.pszConnection = NULL;
    list.dwOptionCount = 4;
    list.dwOptionError = 0;
    list.pOptions = options;
    
    if (InternetSetOptionW(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, nSize)) {
        qDebug() << "已恢复原始代理设置";
    } else {
        qWarning() << "恢复原始代理设置失败";
    }
#endif
}
