#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (V2.1 - Git 仓库版)
# ----------------------------------------------------------
# 此脚本将安装所有依赖，配置核心服务，并将 Python 文件复制到 /usr/local/bin
# ==========================================================

# =============================
# 文件路径定义
# =============================
PANEL_DIR="/etc/wss-panel"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
PANEL_HTML="$PANEL_DIR/index.html" # 实际部署路径
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
WSS_LOG_FILE="/var/log/wss.log"

# 源文件路径 (假设它们都在当前部署目录下)
WSS_CORE_SRC="./wss_core.py"
WSS_PANEL_SRC="./wss_panel.py"
PANEL_HTML_SRC="./panel_template.html"

# FIX (P1): 在任何文件操作之前创建基础目录
mkdir -p "$PANEL_DIR"
echo "创建面板配置目录: $PANEL_DIR"

# =============================
# 提示端口和面板密码
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施端口配置 (使用历史配置) ===="

# 避免二次交互，使用默认值或环境变量
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}
WSS_TLS_PORT=${WSS_TLS_PORT:-443}
STUNNEL_PORT=${STUNNEL_PORT:-444}
UDPGW_PORT=${UDPGW_PORT:-7300}
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}
PANEL_PORT=${PANEL_PORT:-54321}

echo "HTTP Port: $WSS_HTTP_PORT, TLS Port: $WSS_TLS_PORT"
echo "Stunnel Port: $STUNNEL_PORT, Internal Port: $INTERNAL_FORWARD_PORT, Panel Port: $PANEL_PORT"
echo "----------------------------------"

if [ -f "$ROOT_HASH_FILE" ]; then
    echo "使用已保存的面板 Root 密码。面板端口: $PANEL_PORT"
    # 如果已存在文件，读取密码哈希，跳过交互
    PANEL_ROOT_PASS_HASH=$(cat "$ROOT_HASH_FILE")
    # 如果文件不存在，则需要设置新密码
else
    echo "---------------------------------"
    echo "==== 管理面板配置 (首次或重置) ===="
    
    echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
    while true; do
      read -s -p "面板密码: " pw1 && echo
      read -s -p "请再次确认密码: " pw2 && echo
      if [ -z "$pw1" ]; then
        echo "密码不能为空，请重新输入。"
        continue
      fi
      if [ "$pw1" != "$pw2" ]; then
        echo "两次输入不一致，请重试。"
        continue
      fi
      PANEL_ROOT_PASS_RAW="$pw1"
      break
    done
fi


echo "==== 系统清理与依赖检查 ===="
# 停止所有相关服务并清理旧文件
systemctl stop wss.service || true
systemctl stop stunnel4.service || true
systemctl stop udpgw.service || true
systemctl stop wss_panel.service || true

# 依赖检查和安装（新增 libffi-dev 用于 bcrypt 依赖）
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables procps libffi-dev || echo "警告: 依赖安装失败，可能影响功能。"

# 尝试安装 Python 库
if pip3 install flask psutil requests uvloop bcrypt jinja2; then
    HAS_BCRYPT=1
    echo "Python 依赖 (Flask, psutil, uvloop, bcrypt, jinja2) 安装成功。"
else
    if pip3 install flask psutil requests jinja2; then
        HAS_BCRYPT=0
        echo "警告: uvloop/bcrypt 安装失败。性能和安全回退生效。"
    else
        echo "严重警告: 核心 Python 依赖安装失败。"
        exit 1
    fi
fi

# 首次部署，计算 ROOT hash
if [ ! -f "$ROOT_HASH_FILE" ] && [ -n "${PANEL_ROOT_PASS_RAW:-}" ]; then
    if [ "$HAS_BCRYPT" -eq 1 ]; then
        # 使用 Python 生成 bcrypt hash
        PANEL_ROOT_PASS_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$PANEL_ROOT_PASS_RAW'.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8'))")
        echo "使用 bcrypt 生成 ROOT 密码哈希。"
    else
        if command -v python3 >/dev/null; then
            PANEL_ROOT_PASS_HASH=$(python3 -c "import crypt, random, string; salt = '\$6\$' + ''.join(random.choices(string.ascii_letters + string.digits, k=16)); print(crypt.crypt('$PANEL_ROOT_PASS_RAW', salt))")
            echo "回退到带盐的 SHA-512 (crypt) 生成 ROOT 密码哈希。"
        else
            PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | sha256sum | awk '{print $1}')
            echo "最终回退到 SHA256 生成 ROOT 密码哈希 (不安全!)。"
        fi
    fi
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
fi

echo "----------------------------------"

# =============================
# BBR 拥塞控制和网络调优
# =============================
echo "==== 配置 BBR 拥塞控制和网络优化 ===="
# 启用 BBR
echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.conf
# 调整 TCP 缓冲区和连接队列
echo "net.ipv4.tcp_max_syn_backlog = 65536" | tee -a /etc/sysctl.conf
echo "net.core.somaxconn = 65536" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" | tee -a /etc/sysctl.conf
# 增加 TCP Keep-Alive 探测频率和次数
echo "net.ipv4.tcp_keepalive_time = 60" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_probes = 5" | tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_intvl = 5" | tee -a /etc/sysctl.conf

sysctl -p > /dev/null
echo "BBR 拥塞控制和网络参数优化完成。"
echo "----------------------------------"

# =============================
# WSS 核心代理脚本安装
# =============================
echo "==== 复制 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
if [ -f "$WSS_CORE_SRC" ]; then
    install -m 755 "$WSS_CORE_SRC" /usr/local/bin/wss
    echo "WSS 核心代理脚本复制完成。"
else
    echo "错误: WSS 核心脚本 '$WSS_CORE_SRC' 文件丢失。无法继续。"
    exit 1
fi

# 创建日志文件并设置权限
touch "$WSS_LOG_FILE"
chmod 644 "$WSS_LOG_FILE"

# 创建 WSS systemd 服务
tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
# ExecStart 传入端口参数: HTTP_PORT, TLS_PORT, INTERNAL_FORWARD_PORT
ExecStart=/usr/bin/python3 /usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT $INTERNAL_FORWARD_PORT
Restart=on-failure
User=root
StandardOutput=journal
StandardError=journal
# 新增日志文件权限设置
ExecStartPre=/bin/bash -c "touch ${WSS_LOG_FILE} && chmod 644 ${WSS_LOG_FILE}"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wss.service
# 尝试启动并检查状态
systemctl start wss.service
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT, 转发到 $INTERNAL_FORWARD_PORT"
echo "----------------------------------"


# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo "==== 重新安装 Stunnel4 & 证书 ===="
mkdir -p /etc/stunnel/certs
# 重新生成证书，确保文件存在且路径正确
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
chmod 600 /etc/stunnel/certs/*.key
chmod 600 /etc/stunnel/certs/*.pem
chmod 644 /etc/stunnel/certs/*.crt

tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$INTERNAL_FORWARD_PORT
EOF

systemctl enable stunnel4.service
systemctl restart stunnel4.service
echo "Stunnel4 重新启动完成，端口 $STUNNEL_PORT"
echo "----------------------------------"


# =============================
# 安装 UDPGW
# =============================
echo "==== 重新部署 UDPGW ===="
if [ ! -d "/root/badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn > /dev/null 2>&1
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
cd - > /dev/null

tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udpgw.service
systemctl restart udpgw.service
echo "UDPGW 已部署并重启，端口: $UDPGW_PORT"
echo "----------------------------------"


# =============================
# Traffic Control 基础配置
# =============================
echo "==== 配置 Traffic Control (tc) 基础环境 ===="
IP_DEV=$(ip route | grep default | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)

if [ -z "$IP_DEV" ]; then
    echo "警告: 无法找到主网络接口，带宽限制功能可能无效。"
else
    # 清除所有现有的 tc 规则，确保环境干净
    tc qdisc del dev "$IP_DEV" root || true
    # 创建 HTB 根 qdisc
    tc qdisc add dev "$IP_DEV" root handle 1: htb default 10
    # 默认类别 (无限制)
    tc class add dev "$IP_DEV" parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit
    echo "Traffic Control (tc) 已在 $IP_DEV 上初始化。"
fi
echo "----------------------------------"

# =============================
# IPTABLES 基础配置
# =============================
echo "==== 配置 IPTABLES 基础链 (IP 封禁 & 流量追踪优化) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
QUOTA_CHAIN="WSS_QUOTA_OUTPUT"

# 清理旧的 WSS 链和规则
iptables -D INPUT -j $BLOCK_CHAIN 2>/dev/null || true
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true

iptables -D OUTPUT -j $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -F $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -X $QUOTA_CHAIN 2>/dev/null || true


# 1. 创建并插入 IP 阻断链 (必须在端口开放规则之前)
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN # 插入到 INPUT 链最前面

# 2. 创建并挂载 QUOTA 链 (只挂载到 OUTPUT，用于用户进程出站流量计数)
iptables -t filter -N $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -A OUTPUT -j $QUOTA_CHAIN # 流量计数挂载点 (仅对本机发出的流量计数)

echo "IPTABLES 基础链配置完成。服务端口开放将由防火墙软件或管理员手动配置。"
echo "----------------------------------"


# =============================
# WSS 用户管理面板 (Python/Flask)
# =============================
echo "==== 复制 WSS 用户管理面板脚本 & HTML 模板 ===="

USER_DB="$PANEL_DIR/users.json"
IP_BANS_DB="$PANEL_DIR/ip_bans.json"
AUDIT_LOG="$PANEL_DIR/audit.log"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"

# 确保数据库文件存在
[ ! -f "$USER_DB" ] && echo "[]" > "$USER_DB"
[ ! -f "$IP_BANS_DB" ] && echo "{}" > "$IP_BANS_DB"
[ ! -f "$AUDIT_LOG" ] && touch "$AUDIT_LOG"

# 复制 Python 后端
if [ -f "$WSS_PANEL_SRC" ]; then
    install -m 755 "$WSS_PANEL_SRC" /usr/local/bin/wss_panel.py
    echo "面板后端脚本复制完成。"
else
    echo "错误: 面板后端脚本 '$WSS_PANEL_SRC' 文件丢失。无法继续。"
    exit 1
fi

# 复制 HTML 前端模板
if [ -f "$PANEL_HTML_SRC" ]; then
    cp "$PANEL_HTML_SRC" "$PANEL_HTML"
    echo "面板 HTML 模板复制到 $PANEL_HTML 完成。"
else
    echo "错误: 面板 HTML 模板 '$PANEL_HTML_SRC' 文件丢失。无法继续。"
    exit 1
fi

# 修复：生成/加载持久化的 Session Secret Key
if [ ! -f "$SECRET_KEY_FILE" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

# 创建 WSS 面板 systemd 服务
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Flask V2.1 Fixed)
After=network.target

[Service]
Type=simple
# P3 修复: 将所有配置作为环境变量传递
Environment=PANEL_DIR_ENV=$PANEL_DIR \
WSS_LOG_FILE_ENV=$WSS_LOG_FILE \
WSS_HTTP_PORT_ENV=$WSS_HTTP_PORT \
WSS_TLS_PORT_ENV=$WSS_TLS_PORT \
STUNNEL_PORT_ENV=$STUNNEL_PORT \
UDPGW_PORT_ENV=$UDPGW_PORT \
INTERNAL_FORWARD_PORT_ENV=$INTERNAL_FORWARD_PORT \
PANEL_PORT_ENV=$PANEL_PORT
ExecStart=/usr/bin/python3 /usr/local/bin/wss_panel.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wss_panel.service
systemctl restart wss_panel.service
echo "WSS 管理面板 V2.1 已启动，端口 $PANEL_PORT"
echo "----------------------------------"

# =============================
# SSHD 安全配置
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")

echo "==== 配置 SSHD 安全策略 (禁用 Shell, 允许本机密码认证) ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

# 删除旧的 WSS 配置段
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

# 写入新的 WSS 隧道策略
cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by deploy_wss_panel.sh V2.1
# 统一策略: 允许所有用户通过本机 (127.0.0.1, ::1) 使用密码进行认证。
Match Address 127.0.0.1,::1
    # 允许密码认证
    PasswordAuthentication yes
    # 禁止交互式 TTY
    PermitTTY no
    # 允许 TCP 转发 (核心功能)
    AllowTcpForwarding yes
    # 强制执行 /bin/false，禁用 Shell 访问
    ForceCommand /bin/false
# WSS_TUNNEL_BLOCK_END -- managed by deploy_wss_panel.sh V2.1

EOF

chmod 600 "$SSHD_CONFIG"

# 重载 sshd
echo "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置更新完成。内部SSH转发端口: $INTERNAL_FORWARD_PORT (禁止Shell)"
echo "----------------------------------"

# =============================
# 最终重启所有关键服务
# =============================
echo "==== 最终重启所有关键服务，确保配置生效 ===="
systemctl restart wss.service stunnel4.service udpgw.service wss_panel.service
echo "所有服务重启完成：WSS, Stunnel4, UDPGW, Web Panel。"
echo "----------------------------------"

# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ 部署完成！"
echo "=================================================="
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo "=================================================="
