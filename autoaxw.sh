#!/bin/bash

. /etc/autoaxw/options.conf

options() {
  clear
  if [ -e "/etc/autoaxw/options.conf" ]; then
    echo ""
  else
    echo -e "
  ${green}请先填入脚本一些必要的变量${plain}
  ${red}变量文件保存在 /etc/autoaxw/options.conf ${plain}
————————————————
    "
    read -p "输入 v2board 面板 API 链接: " v2bapi
    read -p "输入 v2board 面板密钥: " v2btoken
    read -p "输入 Cloudflare Email: " cfemail
    read -p "输入 Cloudflare APIKey: " cfkey
    [ ! -d "/etc/autoaxw" ] && mkdir -p /etc/autoaxw
    cat > /etc/autoaxw/options.conf << EOF
# ACME 证书（CF)
# 如您不是使用 Cloudflare，请将下方变量更改为您的
export CF_Key="${cfkey}"
export CF_Email="${cfemail}"
sslmail="${cfemail}"

# v2b面板
v2bHost="${v2bapi}"
v2bAPI="${v2btoken}"
EOF
  curl -o /usr/bin/autoaxw -Ls https://raw.githubusercontent.com/LoliStudio/autoaxw/main/autoaxw.sh
  chmod +x /usr/bin/autoaxw
  fi
  show_menu
}

# 字体颜色
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 请使用 root 用户运行！\n" && exit 1

# check os
if cat /etc/issue | grep -Eqi "debian"; then
  release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
  release="ubuntu"
elif cat /proc/version | grep -Eqi "debian"; then
  release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
  release="ubuntu"
else
  echo -e "${red}未检测到系统版本，请联系脚本作者！${plain}\n" && exit 1
fi

# os version
os_version=""
if [[ -f /etc/os-release ]]; then
  os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
  os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"ubuntu" ]]; then
  if [[ ${os_version} -lt 16 ]]; then
    echo -e "${red}请使用 Ubuntu 16 或更高版本的系统！${plain}\n" && exit 1
  fi
elif [[ x"${release}" == x"debian" ]]; then
  if [[ ${os_version} -lt 8 ]]; then
    echo -e "${red}请使用 Debian 8 或更高版本的系统！${plain}\n" && exit 1
  fi
fi

# base
install_base() {
  if [[ x"${release}" == x"debian" ]]; then
    apt update -y
    apt install wget curl unzip tar cron socat gnupg ntpdate -y
  else
    apt update -y
    apt install wget curl unzip tar cron socat gnupg ntpdate -y
  fi
  [ -e /etc/security/limits.d/*nproc.conf ] && rename nproc.conf nproc.conf_bk /etc/security/limits.d/*nproc.conf
  [ -z "$(grep 'session required pam_limits.so' /etc/pam.d/common-session)" ] && echo "session required pam_limits.so" >> /etc/pam.d/common-session
  sed -i '/^# End of file/,$d' /etc/security/limits.conf
  cat >> /etc/security/limits.conf <<EOF
# End of file
* soft nofile 512000
* hard nofile 1024000
EOF
  [ -e "/etc/sysctl.conf" ] && /bin/mv /etc/sysctl.conf{,_bk}
  cat >> /etc/sysctl.conf << EOF
fs.file-max = 1024000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward = 1
net.ipv4.tcp_fastopen = 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  sysctl -p
  rm -rf /etc/localtime
  ln -s /usr/share/zoneinfo/Asia/Hong_Kong /etc/localtime
  if [ -e "$(which ntpdate)" ]; then
    ntpdate -u pool.ntp.org
    [ ! -e "/var/spool/cron/crontabs/root" -o -z "$(grep ntpdate /var/spool/cron/crontabs/root 2>/dev/null)" ] && { echo "*/20 * * * * $(which ntpdate) -u pool.ntp.org > /dev/null 2>&1" >> /var/spool/cron/crontabs/root;chmod 600 /var/spool/cron/crontabs/root; }
  fi
}

# Acme.sh
install_acme(){
  if [ -e "/root/.acme.sh/${domain}_ecc/${domain}.key" ]; then
    echo ""
  else
    if [ -e "/root/.acme.sh/acme.sh" ]; then
      /root/.acme.sh/acme.sh --issue  --dns dns_cf -d ${domain} --keylength ec-256
    else
      curl https://get.acme.sh | sh
      /root/.acme.sh/acme.sh  --set-default-ca  --server zerossl
      /root/.acme.sh/acme.sh --register-account -m ${sslmail}
      /root/.acme.sh/acme.sh --issue  --dns dns_cf -d ${domain} --keylength ec-256
    fi
  fi
}

# XrayR
install_xrayr() {
  wget https://github.com/XrayR-project/XrayR/releases/latest/download/XrayR-linux-64.zip
  unzip XrayR-linux-64.zip -d /usr/local/XrayR
  rm XrayR-linux-64.zip
  cat > /etc/systemd/system/XrayR.service << EOF
[Unit]
Description=XrayR Service
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
Group=root
Type=simple
LimitAS=infinity
LimitRSS=infinity
LimitCORE=infinity
LimitNOFILE=999999
WorkingDirectory=/usr/local/XrayR/
ExecStart=/usr/local/XrayR/XrayR -config /etc/XrayR/config.yml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

# XrayR Profile
xrayr_conf() {
  [ ! -d "/etc/XrayR" ] && mkdir -p /etc/XrayR
  cat > /etc/XrayR/config.yml << EOF
Log:
  Level: warning
  AccessPath: /etc/XrayR/access.Log
  ErrorPath: /etc/XrayR/error.log
DnsConfigPath:
ConnetionConfig:
  Handshake: 4
  ConnIdle: 10
  UplinkOnly: 2
  DownlinkOnly: 4
  BufferSize: 64
Nodes:
  -
    PanelType: "V2board"
    ApiConfig:
      ApiHost: "${v2bHost}"
      ApiKey: "${v2bAPI}"
      NodeID: ${nodeid}
      NodeType: ${xrayr_type}
      Timeout: 30
      EnableVless: false
      EnableXTLS: false
      SpeedLimit: 0
      DeviceLimit: 0
      RuleListPath:
    ControllerConfig:
      ListenIP: ${xrayr_listen}
      UpdatePeriodic: 60
      EnableDNS: false
      EnableProxyProtocol: ${protocol_type}
      EnableFallback: ${fallback}
      FallBackConfigs:
        -
          SNI:
          Path:
          Dest: ${domain}:80
          ProxyProtocolVer: 0
      CertConfig:
        CertMode: ${ssl_mode}
        CertDomain: ${domain}
        CertFile: /root/.acme.sh/${domain}_ecc/fullchain.cer
        KeyFile: /root/.acme.sh/${domain}_ecc/${domain}.key
EOF
}

# Air-Universe
install_au() {
  # Xray
  wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
  unzip Xray-linux-64.zip -d /usr/local/xray
  rm Xray-linux-64.zip
  cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Air-Universe Xray service
After=network.target
BindsTo=au.service

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/xray/xray run -config /etc/au/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
  # Air-Universe
  wget https://github.com/crossfw/Air-Universe/releases/latest/download/Air-Universe-linux-64.zip
  unzip Air-Universe-linux-64.zip
  mv Air-Universe /usr/local/sbin
  rm Air-Universe-linux-64.zip
  cat > /etc/systemd/system/au.service << EOF
[Unit]
Description=Air-Universe - main Service
After=network.target
BindsTo=xray.service

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/sbin/Air-Universe -c /etc/au/au.json

[Install]
WantedBy=multi-user.target
EOF
}

# Air-Universe Profile
au_conf() {
  [ ! -d "/etc/au" ] && mkdir /etc/au
  cat > /etc/au/au.json << EOF
{
  "log": {
    "log_level": "warning",
    "access": "/etc/au/au.log"
  },
  "panel": {
    "type": "v2board",
    "url": "${v2bHost}",
    "key": "${v2bAPI}",
    "node_ids": [${nodeid}],
    "nodes_type": ["${nodetype}"],
    "nodes_proxy_protocol": [${protocol_type}]
  },
  "proxy": {
    "type":"xray",
    "alter_id": 1,
    "auto_generate": true,
    "in_tags": ["p0"],
    "api_address": "127.0.0.1",
    "api_port": 10085,
    "force_close_tls": ${ssl_type},
    "log_path": "/etc/au/v2.log",
    "cert": {
      "cert_path": "/root/.acme.sh/${domain}_ecc/fullchain.cer",
      "key_path": "/root/.acme.sh/${domain}_ecc/${domain}.key"
    },
    "speed_limit_level": [0]
  },
  "sync": {
    "interval": 60,
    "fail_delay": 5,
    "timeout": 10,
    "post_ip_interval": 90
  }
}
EOF
}

# Xray IPv4
xray_file_v4() {
  [ ! -d "/etc/au" ] && mkdir /etc/au
  cat > /etc/au/config.json << EOF
{
  "log": {
    "log_level": "warning",
    "access": "/etc/au/xr.log"
  },
  "stats": {},
  "api": {
    "services": [
      "HandlerService",
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blackhole",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "blackhole"
      },
      {
        "type": "field",
        "ip": [
          "127.0.0.1/32",
          "10.0.0.0/8",
          "fc00::/7",
          "fe80::/10",
          "172.16.0.0/12"
        ],
        "outboundTag": "blackhole"
      }
    ]
  }
}
EOF
}

# Xray IPv6
xray_file_v6() {
  [ ! -d "/etc/au" ] && mkdir /etc/au
  cat > /etc/au/config.json << EOF
{
  "log": {
    "log_level": "warning",
    "access": "/etc/au/xr.log"
  },
  "stats": {},
  "api": {
    "services": [
      "HandlerService",
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blackhole",
      "protocol": "blackhole",
      "settings": {}
    },
    {
      "tag":"IP4_out",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag":"IP6_out",
      "protocol": "freedom",
       "settings": {
         "domainStrategy": "UseIPv6"
       }
    }
  ],
  "routing": {
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "blackhole"
      },
      {
        "type": "field",
        "ip": [
          "127.0.0.1/32",
          "10.0.0.0/8",
          "fc00::/7",
          "fe80::/10",
          "172.16.0.0/12"
        ],
        "outboundTag": "blackhole"
      },
      {
        "type": "field",
        "outboundTag": "IP6_out",
        "domain": [
          "geosite:netflix"
        ]
      },
      {
        "type": "field",
        "outboundTag": "IP4_out",
        "network": "udp,tcp"
      }
    ]
  }
}
EOF
}

# Nginx
osver=`lsb_release -sc`
install_nginx() {
  wget -qO - https://nginx.org/keys/nginx_signing.key | apt-key add -
  if [[ x"${release}" == x"debian" ]]; then
    cat > /etc/apt/sources.list.d/nginx.list << EOF
deb https://nginx.org/packages/mainline/debian/ ${osver} nginx
deb-src https://nginx.org/packages/mainline/debian/ ${osver} nginx
EOF
  else
    cat > /etc/apt/sources.list.d/nginx.list << EOF
deb https://nginx.org/packages/mainline/ubuntu/ ${osver} nginx
deb-src https://nginx.org/packages/mainline/ubuntu/ ${osver} nginx
EOF
  fi
  apt update && apt install nginx -y
  cat > /lib/systemd/system/nginx.service << EOF
[Unit]
Description=nginx - high performance web server
Documentation=http://nginx.org/en/docs/
After=network.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPost=/bin/sleep 0.1
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
TimeoutStartSec=120
LimitNOFILE=1000000
LimitNPROC=1000000
LimitCORE=1000000

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  rm /etc/nginx/conf.d/*.conf
  cat > /etc/nginx/nginx.conf << EOF
user nginx;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
worker_rlimit_nofile 51200;

events {
  use epoll;
  worker_connections  51200;
  multi_accept on;
}

stream {
  include /etc/nginx/conf.d/stream/*.conf;
}

http {
  include mime.types;
  default_type application/octet-stream;
  server_names_hash_bucket_size 128;
  client_header_buffer_size 32k;
  large_client_header_buffers 4 32k;
  client_max_body_size 1024m;
  client_body_buffer_size 10m;
  sendfile on;
  tcp_nopush on;
  keepalive_timeout 120;
  server_tokens off;
  tcp_nodelay on;

  fastcgi_connect_timeout 300;
  fastcgi_send_timeout 300;
  fastcgi_read_timeout 300;
  fastcgi_buffer_size 64k;
  fastcgi_buffers 4 64k;
  fastcgi_busy_buffers_size 128k;
  fastcgi_temp_file_write_size 128k;
  fastcgi_intercept_errors on;

  gzip on;
  gzip_buffers 16 8k;
  gzip_comp_level 6;
  gzip_http_version 1.1;
  gzip_min_length 256;
  gzip_proxied any;
  gzip_vary on;
  gzip_types
    text/xml application/xml application/atom+xml application/rss+xml application/xhtml+xml image/svg+xml
    text/javascript application/javascript application/x-javascript
    text/x-json application/json application/x-web-app-manifest+json
    text/css text/plain text/x-component
    font/opentype application/x-font-ttf application/vnd.ms-fontobject
    image/x-icon;
  gzip_disable "MSIE [1-6]\.(?!.*SV1)";

  server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    access_log off;
    location / { return 444; }
  }

  include /etc/nginx/conf.d/*.conf;
}
EOF
  git clone https://github.com/cristurm/nyan-cat.git /usr/share/nginx/html/nyan-cat
}

# ws nginx
nginx_ws() {
  cat > /etc/nginx/conf.d/${domain}.conf << EOF
server {
  listen 80;
  listen ${listen_port} ssl http2;
  server_name ${domain};
  server_tokens off;

  ssl_certificate /root/.acme.sh/${domain}_ecc/fullchain.cer;
  ssl_certificate_key /root/.acme.sh/${domain}_ecc/${domain}.key;

  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
  ssl_prefer_server_ciphers off;
  ssl_protocols TLSv1.1 TLSv1.2;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets on;
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 1.1.1.1 valid=300s;
  resolver_timeout 10s;

  access_log off;

  index index.html;

  if (\$ssl_protocol = "") { return 301 https://\$host\$request_uri; }

  location /${wspath} {
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1;mode=block";
    add_header Referrer-Policy no-referrer-when-downgrade;
    add_header Cache-Control no-store;
    add_header Pragma no-cache;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header Host \$http_host;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_redirect off;
    if (\$http_upgrade = "websocket") {
        proxy_pass http://127.0.0.1:${server_port};
    }
    alias /usr/share/nginx/html/nyan-cat/;
  }
}
EOF
}

# trojan nginx
nginx_trojan() {
  [ ! -d "/etc/nginx/conf.d/stream" ] && mkdir -p /etc/nginx/conf.d/stream
  cat > /etc/nginx/conf.d/stream/trojan.conf <<EOF
server {
  listen ${listen_port} ssl;
  ssl_certificate /root/.acme.sh/${domain}_ecc/fullchain.cer;
  ssl_certificate_key /root/.acme.sh/${domain}_ecc/${domain}.key;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
  ssl_protocols TLSv1.1 TLSv1.2;
  ssl_session_cache shared:SSLE:10m;
  ssl_session_timeout 10m;

  proxy_protocol on;
  proxy_pass 127.0.0.1:${server_port};
}
EOF
  cat > /etc/nginx/conf.d/${domain}.conf << EOF
server {
  listen 80;
  server_name ${domain};
  access_log off;
  index index.html;

  location / {
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1;mode=block";
    add_header Referrer-Policy no-referrer-when-downgrade;
    add_header Cache-Control no-store;
    add_header Pragma no-cache;
    alias /usr/share/nginx/html/nyan-cat/;
  }
}
EOF
}

# Warp
install_warp() {
  apt-get install sudo net-tools openresolv -y
  if [[ x"${release}" == x"debian" ]]; then
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 150\n' > /etc/apt/preferences.d/limit-unstable
    apt update
    apt install wireguard-dkms wireguard-tools -y
    modprobe wireguard
  else
    add-apt-repository ppa:wireguard/wireguard
    apt-get update
    apt-get install wireguard -y
    modprobe wireguard
  fi
  curl -fsSL git.io/wgcf.sh | sudo bash
  mkdir -p /tmp/warp
  pushd /tmp/warp
  wgcf register
  wgcf generate
  sed -i '/0.0.0.0/d' wgcf-profile.conf
  sed -i 's/engage.cloudflareclient.com/162.159.192.1/g' wgcf-profile.conf
  cp wgcf-profile.conf /etc/wireguard/wgcf.conf
  popd
  systemctl start wg-quick@wgcf
  systemctl enable wg-quick@wgcf
  rm -r /tmp/warp
}

# warp on|off
warp_on() {
  xray_file=xray_file_v6
}
warp_off() {
  xray_file=xray_file_v4
}

# Update Shell
update_shell() {
  wget -O /usr/bin/autoaxw -N --no-check-certificate https://raw.githubusercontent.com/LoliStudio/autoaxw/main/autoaxw.sh
  if [[ $? != 0 ]]; then
    echo ""
    echo -e "${red}下载脚本失败，请检查本机能否连接 Github${plain}"
    show_menu
  else
    chmod +x /usr/bin/autoaxw
    echo -e "${green}升级脚本成功，请重新运行脚本${plain}" && exit 0
  fi
  before_show_menu
}

# Server VER
check_versions() {
  if [ -e "/usr/local/XrayR/XrayR" ]; then
    echo -n "安装的后端为 XrayR，版本为: "
    /usr/local/XrayR/XrayR -version
    echo ""
  else
    echo -n "安装的后端为 Air-Universe，版本为: "
    /usr/local/sbin/Air-Universe -version
    echo -n "Xray 版本为: "
    /usr/local/xray/xray -version
  fi
  before_show_menu
}

uninstall() {
  clear
  if [ -e "/usr/local/XrayR/XrayR" ]; then
    systemctl stop XrayR.service
    systemctl disable XrayR.service
    rm -rf /etc/systemd/system/XrayR.service
    rm -rf /usr/local/XrayR
    rm -rf /etc/XrayR
  else
    systemctl stop xray.service
    systemctl disable xray.service
    systemctl stop au.service
    systemctl disable au.service
    rm -rf /etc/systemd/system/xray.service
    rm -rf /usr/local/xray
    rm -rf /etc/systemd/system/au.service
    rm -rf /usr/local/sbin/Air-Universe
    rm -rf /etc/au
  fi
  if [ -e "/etc/nginx/nginx.conf" ]; then
    apt purge --remove nginx -y
    apt autoremove
    rm -rf /usr/share/nginx/html
    rm -rf /etc/nginx
  fi
  if [-e "/etc/wireguard/wgcf.conf" ]; then
    systemctl stop wg-quick@wgcf
    systemctl disable wg-quick@wgcf
  fi
  clear
  echo -e "已卸载完毕"
}

before_show_menu() {
    echo && echo -n -e "${yellow}按回车返回主菜单: ${plain}" && read temp
    show_menu
}

# WS TLS
install_ws_tls() {
  read -p "请输入节点域名: " domain
  read -p "请输入节点 ID: " nodeid
  echo -e "
  ${green}是否开启 WARP${plain}
  ${green}1.${plain} 开启
  ${green}2.${plain} 不开启
  不选择默认不开启
  "
  read -p "请选择: " warp_status
  case "${warp_status}" in
    1) warp_on
    ;;
    2) warp_off
    ;;
    *) warp_off
  esac
  use_server
  if [ -e "/usr/local/XrayR/XrayR" ]; then
    xrayr_type=V2ray
    xrayr_listen=0.0.0.0
    ssl_mode=file
    protocol_type=false
    fallback=false
    xrayr_conf
    systemctl enable XrayR.service
    systemctl start XrayR.service
  else
    nodetype=vmess
    ssl_type=false
    protocol_type=false
    ${xray_file}
    au_conf
    systemctl enable xray.service
    systemctl start xray.service
    systemctl enable au.service
    systemctl start au.service
  fi
}

# WS NGINX TLS
install_ws_nginx_tls() {
  read -p "请输入节点域名: " domain
  read -p "请输入节点 ID: " nodeid
  read -p "请输入 Nginx 监听端口: " listen_port
  read -p "请输入 WS Path 路径(默认: /): " wspath
  read -p "请输入后端服务端口: " server_port
  echo -e "
  ${green}是否开启 WARP${plain}
  ${green}1.${plain} 开启
  ${green}2.${plain} 不开启
  不选择默认不开启
  "
  read -p "请选择: " warp_status
  case "${warp_status}" in
    1) warp_on
    ;;
    2) warp_off
    ;;
    *) warp_off
  esac
  use_server
  if [ -e "/usr/local/XrayR/XrayR" ]; then
    xrayr_type=V2ray
    xrayr_listen=127.0.0.1
    ssl_mode=none
    protocol_type=false
    fallback=false
    xrayr_conf
    systemctl enable XrayR.service
    systemctl start XrayR.service
  else
    nodetype=vmess
    ssl_type=true
    protocol_type=false
    ${xray_file}
    au_conf
    systemctl enable xray.service
    systemctl start xray.service
    systemctl enable au.service
    systemctl start au.service
  fi
  install_nginx
  nginx_ws
}

# Trojan TLS
install_trojan_tls() {
  read -p "请输入节点域名: " domain
  read -p "请输入节点 ID: " nodeid
  echo -e "
  ${green}是否开启 WARP${plain}
  ${green}1.${plain} 开启
  ${green}2.${plain} 不开启
  不选择默认不开启
  "
  read -p "请选择: " warp_status
  case "${warp_status}" in
    1) warp_on
    ;;
    2) warp_off
    ;;
    *) warp_off
  esac
  use_server
  if [ -e "/usr/local/XrayR/XrayR" ]; then
    xrayr_type=Trojan
    xrayr_listen=0.0.0.0
    ssl_mode=file
    protocol_type=false
    fallback=false
    xrayr_conf
    systemctl enable XrayR.service
    systemctl start XrayR.service
  else
    nodetype=trojan
    ssl_type=false
    protocol_type=false
    ${xray_file}
    au_conf
    systemctl enable xray.service
    systemctl start xray.service
    systemctl enable au.service
    systemctl start au.service
  fi
}

# Trojan NGINX TLS
install_trojan_nginx_tls() {
  read -p "请输入节点域名: " domain
  read -p "请输入节点 ID: " nodeid
  read -p "请输入 Nginx 监听端口: " listen_port
  read -p "请输入后端服务端口: " server_port
  echo -e "
  ${green}是否开启 WARP${plain}
  ${green}1.${plain} 开启
  ${green}2.${plain} 不开启
  不选择默认不开启
  "
  read -p "请选择: " warp_status
  case "${warp_status}" in
    1) warp_on
    ;;
    2) warp_off
    ;;
    *) warp_off
  esac
  use_server
  if [ -e "/usr/local/XrayR/XrayR" ]; then
    xrayr_type=Trojan
    xrayr_listen=127.0.0.1
    ssl_mode=none
    protocol_type=true
    fallback=true
    xrayr_conf
    systemctl enable XrayR.service
    systemctl start XrayR.service
  else
    nodetype=trojan
    ssl_type=true
    protocol_type=true
    ${xray_file}
    au_conf
    systemctl enable xray.service
    systemctl start xray.service
    systemctl enable au.service
    systemctl start au.service
  fi
  install_nginx
  nginx_trojan
}

# use server base
use_server() {

  clear
  echo -e "
  ${green}请选择需要安装的后端${plain}
————————————————
  ${green}1.${plain} 安装 XrayR
  ${green}2.${plain} 安装 Air-Universe
  "
  read -p "请输入选择: " server
  install_base
  install_acme
  case "${server}" in
    1) install_xrayr
    ;;
    2) install_au
    ;;
    *)
    clear
    echo -e "请选择正确的后端"
    sleep 2s
    use_server
    ;;
  esac
}

# Menu
show_menu() {
  clear
  echo -e "
  ${green}XrayR/Air-Universe后端管理脚本${plain}
  ${red}注意: 仅适用于 Debian or Ubuntu${plain}
————————————————
  ${green}0.${plain} 退出管理脚本
————————————————
  ${green}1.${plain} 安装 WS + TLS
  ${green}2.${plain} 安装 WS + Nginx + TLS
————————————————
  ${green}3.${plain} 安装 Trojan + TLS
  ${green}4.${plain} 安装 Trojan + Nginx + TLS
————————————————
  ${green}5.${plain} 安装 Warp（${red}仅适用于 Air-Universe${plain}）
————————————————
  ${green}6.${plain} 卸载
————————————————
  ${green}7.${plain} 升级维护脚本
  ${green}8.${plain} 查看后端版本
  "
  read -p "请输入选择 [0-8]: " num
  case "${num}" in
    0) exit 1
    ;;
    1) install_ws_tls
    ;;
    2) install_ws_nginx_tls
    ;;
    3) install_trojan_tls
    ;;
    4) install_trojan_nginx_tls
    ;;
    5) install_warp
    ;;
    6) uninstall
    ;;
    7) update_shell
    ;;
    8) check_versions
    ;;
    *)
    echo -e "${red}请输入正确的数字 [0-8]${plain}"
    sleep 2s
    clear
    show_menu
    ;;
  esac
}
options
