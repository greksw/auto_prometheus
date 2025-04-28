#!/bin/bash

# Проверка на root-права
if [ "$(id -u)" -ne 0 ]; then
    echo "Этот скрипт должен запускаться от root!" >&2
    exit 1
fi

# Обновление системы
apt update && apt upgrade -y

# Установка необходимых пакетов
apt install -y wget curl ufw fail2ban openssl

### Настройка firewall (ufw) ###
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp  # Для HTTPS Grafana
ufw allow 9090/tcp # Для HTTPS Prometheus
ufw --force enable

### Генерация самоподписного SSL-сертификата ###
mkdir -p /etc/ssl/private
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/grafana.key \
    -out /etc/ssl/private/grafana.crt \
    -subj "/CN=grafana.local/O=Grafana HTTPS"

chmod 600 /etc/ssl/private/grafana.*

### Установка и настройка Prometheus ###
wget https://github.com/prometheus/prometheus/releases/download/v2.47.0/prometheus-2.47.0.linux-amd64.tar.gz
tar xvf prometheus-*.tar.gz
mv prometheus-*/ /opt/prometheus/
rm prometheus-*.tar.gz

# Создание пользователя и назначение прав
useradd --no-create-home --shell /bin/false prometheus
chown -R prometheus:prometheus /opt/prometheus/

# Конфигурация systemd для Prometheus
cat > /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/opt/prometheus/prometheus \
    --config.file=/opt/prometheus/prometheus.yml \
    --web.config.file=/opt/prometheus/web.yml \
    --storage.tsdb.path=/opt/prometheus/data \
    --web.listen-address=:9090 \
    --web.external-url=https://$(hostname -I | awk '{print $1}'):9090 \
    --web.route-prefix=/

[Install]
WantedBy=multi-user.target
EOF

# Настройка аутентификации в Prometheus (Basic Auth)
echo "Введите пароль для Prometheus (логин: admin):"
read -s PROMETHEUS_PASSWORD
htpasswd -b -c /opt/prometheus/web.yml admin "$PROMETHEUS_PASSWORD" || {
    apt install -y apache2-utils
    htpasswd -b -c /opt/prometheus/web.yml admin "$PROMETHEUS_PASSWORD"
}

chown prometheus:prometheus /opt/prometheus/web.yml

# Запуск Prometheus
systemctl daemon-reload
systemctl enable --now prometheus

### Установка и настройка Grafana ###
apt install -y apt-transport-https software-properties-common
wget -q -O - https://packages.grafana.com/gpg.key | apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | tee /etc/apt/sources.list.d/grafana.list
apt update && apt install -y grafana

# Настройка HTTPS в Grafana
cat > /etc/grafana/grafana.ini <<EOF
[server]
protocol = https
http_port = 3000
domain = $(hostname -I | awk '{print $1}')
cert_file = /etc/ssl/private/grafana.crt
cert_key = /etc/ssl/private/grafana.key
EOF

# Включение Basic Auth в Grafana
sed -i 's/;disable_login_form = false/disable_login_form = true/' /etc/grafana/grafana.ini

systemctl enable --now grafana-server

### Настройка fail2ban для Grafana и Prometheus ###
cat > /etc/fail2ban/jail.d/grafana.conf <<EOF
[grafana]
enabled = true
port = 443,3000
filter = grafana
logpath = /var/log/grafana/grafana.log
maxretry = 3
bantime = 1h
EOF

cat > /etc/fail2ban/filter.d/grafana.conf <<EOF
[Definition]
failregex = ^.*Failed.* user=<HOST>.*
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/prometheus.conf <<EOF
[prometheus]
enabled = true
port = 9090
filter = prometheus
logpath = /var/log/prometheus.log
maxretry = 3
bantime = 1h
EOF

cat > /etc/fail2ban/filter.d/prometheus.conf <<EOF
[Definition]
failregex = ^.*invalid username or password.* <HOST>
ignoreregex =
EOF

systemctl restart fail2ban

### Защита экспортеров (Node Exporter в примере) ###
# Установка Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvf node_exporter-*.tar.gz
mv node_exporter-*/node_exporter /usr/local/bin/
rm -rf node_exporter-*

# Создание systemd-юнита с аутентификацией
cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \
    --web.config.file=/etc/node_exporter/web.yml

[Install]
WantedBy=multi-user.target
EOF

# Создание пользователя
useradd --no-create-home --shell /bin/false node_exporter

# Настройка Basic Auth для Node Exporter
echo "Введите пароль для Node Exporter (логин: exporter):"
read -s EXPORTER_PASSWORD
htpasswd -b -c /etc/node_exporter/web.yml exporter "$EXPORTER_PASSWORD"

chown node_exporter:node_exporter /etc/node_exporter/web.yml

systemctl enable --now node_exporter

### Настройка Prometheus для работы с защищенными экспортерами ###
cat >> /opt/prometheus/prometheus.yml <<EOF
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
    basic_auth:
      username: exporter
      password: '$EXPORTER_PASSWORD'
EOF

systemctl restart prometheus

echo "
=== Установка завершена! ===
- Prometheus: https://$(hostname -I | awk '{print $1}'):9090 (логин: admin, пароль: $PROMETHEUS_PASSWORD)
- Grafana: https://$(hostname -I | awk '{print $1}'):3000 (логин: admin, пароль: admin)
- Node Exporter защищен Basic Auth (логин: exporter, пароль: $EXPORTER_PASSWORD)
- Firewall (ufw) и fail2ban настроены.
"
