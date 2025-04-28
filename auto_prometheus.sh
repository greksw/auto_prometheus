#!/bin/bash
set -euo pipefail

# --- Конфигурация ---
GRAFANA_DOMAIN="$(hostname -f)"
PROMETHEUS_PASSWORD="$(openssl rand -hex 16)"
EXPORTER_PASSWORD="$(openssl rand -hex 16)"
FAIL2BAN_BANTIME="1h"
FAIL2BAN_MAXRETRY="3"

# --- Логирование ---
LOG_FILE="/var/log/monitoring_setup_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "📅 Начало установки: $(date)"

# --- Проверка интернет-соединения ---
check_internet() {
    if ! ping -c 2 8.8.8.8 &> /dev/null; then
        echo "❌ Нет интернет-соединения!"
        exit 1
    fi
    echo "🌐 Интернет-соединение работает"
}

# --- Установка базовых зависимостей ---
install_dependencies() {
    echo "🔄 Установка базовых пакетов..."
    apt-get update -q
    apt-get install -yq \
        wget curl ufw fail2ban openssl \
        apache2-utils python3 software-properties-common \
        gnupg2 apt-transport-https
}

# --- Настройка firewall ---
setup_firewall() {
    echo "🔥 Настройка firewall..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 443/tcp
    ufw allow 9090/tcp
    echo "y" | ufw enable
    ufw status verbose
}

# --- Генерация SSL сертификатов ---
generate_ssl() {
    echo "🔐 Генерация SSL сертификатов..."
    mkdir -p /etc/ssl/private
    if ! openssl ecparam -genkey -name secp384r1 -out /etc/ssl/private/monitoring.key 2>/dev/null; then
        echo "⚠️ Используем RSA 2048 (ECDSA не поддерживается)"
        openssl genrsa -out /etc/ssl/private/monitoring.key 2048
    fi
    openssl req -new -x509 -sha384 -days 365 \
        -key /etc/ssl/private/monitoring.key \
        -out /etc/ssl/private/monitoring.crt \
        -subj "/CN=$GRAFANA_DOMAIN/O=Secure Monitoring/OU=DevOps"
    chmod 600 /etc/ssl/private/monitoring.*
}

# --- Установка Prometheus ---
install_prometheus() {
    echo "📊 Установка Prometheus..."
    useradd --system --no-create-home --shell /bin/false prometheus || true
    
    PROM_VERSION="2.47.0"
    PROM_URL="https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz"
    
    if ! wget -q "$PROM_URL"; then
        echo "❌ Ошибка загрузки Prometheus"
        exit 1
    fi
    
    tar xf prometheus-*.tar.gz -C /opt/
    mv /opt/prometheus-* /opt/prometheus
    rm prometheus-*.tar.gz

    # Конфигурация
    cat > /opt/prometheus/prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
    basic_auth:
      username: exporter
      password: '$EXPORTER_PASSWORD'
EOF

    # Аутентификация
    if ! command -v htpasswd &> /dev/null; then
        apt-get install -yq apache2-utils
    fi
    htpasswd -b -c /opt/prometheus/web.yml admin "$PROMETHEUS_PASSWORD"

    chown -R prometheus:prometheus /opt/prometheus

    # Systemd сервис
    cat > /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
ExecStart=/opt/prometheus/prometheus \\
    --config.file=/opt/prometheus/prometheus.yml \\
    --web.config.file=/opt/prometheus/web.yml \\
    --web.listen-address=:9090 \\
    --web.external-url=https://$GRAFANA_DOMAIN:9090
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now prometheus
    echo "✅ Prometheus установлен"
}

# --- Установка Grafana ---
install_grafana() {
    echo "📈 Попытка установки Grafana через репозиторий..."
    
    # Попытка 1: Официальный репозиторий
    if curl -s -I https://packages.grafana.com/oss/deb/dists/stable/Release | grep -q "HTTP/.* 200"; then
        echo "🔑 Добавление GPG-ключа Grafana..."
        curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor > /usr/share/keyrings/grafana-archive-keyring.gpg
        
        echo "📦 Добавление репозитория..."
        echo "deb [signed-by=/usr/share/keyrings/grafana-archive-keyring.gpg] https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
        
        apt-get update -q
        apt-get install -yq grafana
    else
        # Попытка 2: Прямая загрузка .deb пакета
        echo "⚠️ Репозиторий недоступен, пробуем прямой .deb пакет..."
        GRAFANA_VERSION="10.4.3"
        GRAFANA_DEB="grafana_${GRAFANA_VERSION}_amd64.deb"
        GRAFANA_URL="https://dl.grafana.com/oss/release/${GRAFANA_DEB}"
        
        if wget -q "$GRAFANA_URL"; then
            apt-get install -yq ./"$GRAFANA_DEB"
            rm "$GRAFANA_DEB"
        else
            echo "❌ Не удалось установить Grafana!"
            exit 1
        fi
    fi

    # Конфигурация Grafana
    cat > /etc/grafana/grafana.ini <<EOF
[server]
protocol = https
http_port = 3000
domain = $GRAFANA_DOMAIN
cert_file = /etc/ssl/private/monitoring.crt
cert_key = /etc/ssl/private/monitoring.key
cipher_suites = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
min_tls_version = tls1.2

[security]
disable_initial_admin_creation = true
admin_user = admin
admin_password = $(openssl rand -hex 12)
EOF

    systemctl enable --now grafana-server
    echo "✅ Grafana установлен"
}

# --- Установка Node Exporter ---
install_node_exporter() {
    echo "🖥️ Установка Node Exporter..."
    useradd --system --no-create-home --shell /bin/false node_exporter || true
    
    NODE_VERSION="1.6.1"
    NODE_URL="https://github.com/prometheus/node_exporter/releases/download/v${NODE_VERSION}/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz"
    
    wget -q "$NODE_URL"
    tar xf node_exporter-*.tar.gz
    mv node_exporter-*/node_exporter /usr/local/bin/
    rm -rf node_exporter-*

    # Аутентификация
    mkdir -p /etc/node_exporter
    htpasswd -b -c /etc/node_exporter/web.yml exporter "$EXPORTER_PASSWORD"
    chown node_exporter:node_exporter /etc/node_exporter/web.yml

    # Systemd сервис
    cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \\
    --web.config.file=/etc/node_exporter/web.yml

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable --now node_exporter
    echo "✅ Node Exporter установлен"
}

# --- Настройка Fail2Ban ---
setup_fail2ban() {
    echo "🛡️ Настройка Fail2Ban..."
    
    cat > /etc/fail2ban/jail.d/monitoring.conf <<EOF
[grafana]
enabled = true
port = 443,3000
filter = grafana
logpath = /var/log/grafana/grafana.log
maxretry = $FAIL2BAN_MAXRETRY
bantime = $FAIL2BAN_BANTIME

[prometheus]
enabled = true
port = 9090
filter = prometheus
logpath = /var/log/syslog
maxretry = $FAIL2BAN_MAXRETRY
bantime = $FAIL2BAN_BANTIME
EOF

    cat > /etc/fail2ban/filter.d/grafana.conf <<EOF
[Definition]
failregex = ^.*Failed.* user=<HOST>.*
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/prometheus.conf <<EOF
[Definition]
failregex = ^.*invalid username or password.* <HOST>
ignoreregex =
EOF

    systemctl restart fail2ban
    echo "✅ Fail2Ban настроен"
}

# --- Основной процесс установки ---
main() {
    check_internet
    install_dependencies
    setup_firewall
    generate_ssl
    install_prometheus
    install_grafana
    install_node_exporter
    setup_fail2ban

    # Итоговая информация
    echo "
🎉 Установка завершена!

🔗 Доступ к сервисам:
- Prometheus:  https://$GRAFANA_DOMAIN:9090
  Логин: admin
  Пароль: $PROMETHEUS_PASSWORD

- Grafana:     https://$GRAFANA_DOMAIN:3000
  Логин: admin
  Пароль: $(grep 'admin_password' /etc/grafana/grafana.ini | cut -d' ' -f3)

- Node Exporter: http://$(hostname -I | awk '{print $1}'):9100/metrics
  Логин: exporter
  Пароль: $EXPORTER_PASSWORD

📋 Лог установки: $LOG_FILE
"
}

# Запуск
main
