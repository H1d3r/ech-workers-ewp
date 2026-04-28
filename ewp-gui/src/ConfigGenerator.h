#pragma once

#include <QString>
#include <QJsonObject>
#include "EWPNode.h"
#include "SettingsDialog.h"

// ConfigGenerator emits a v2 cmd/ewp config (the same schema as
// examples/client-socks5.yaml) — JSON form, since cmd/ewp accepts
// either yaml or JSON via the same parser.
class ConfigGenerator
{
public:
    // Build the full config object (engine.yaml-equivalent JSON).
    static QJsonObject generateClientConfig(const EWPNode &node,
                                            const SettingsDialog::AppSettings &settings,
                                            bool tunMode = false);

    // Pretty-print to a string (for diagnostics / preview).
    static QString generateConfigFile(const EWPNode &node,
                                      const SettingsDialog::AppSettings &settings,
                                      bool tunMode = false);

    // Write JSON to disk; cmd/ewp -config <file> consumes it directly.
    static bool saveConfig(const QJsonObject &config, const QString &filePath);

private:
    static QJsonArray generateInbounds(const SettingsDialog::AppSettings &settings, bool tunMode);
    static QJsonObject generateOutbound(const EWPNode &node);
    static QJsonObject generateTransport(const EWPNode &node);
    static QJsonObject generateRouter();
    static QJsonObject generateClient(const EWPNode &node);
};
