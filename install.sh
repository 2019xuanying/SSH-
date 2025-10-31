#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本 (V2.1 结构修正版)
# ----------------------------------------------------------
# 修正: 适应 Git 仓库的扁平结构，所有模板文件都从根目录复制。
# ==========================================================

# =============================
# 文件路径定义
# =============================
REPO_ROOT=$(dirname "$0")

# 安装目录
PANEL_DIR="/etc/wss-panel"
WSS_LOG_FILE="/var/log/wss.log" 
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
IPTABLES_RULES="/etc/iptables/rules.v4"

# 脚本目标路径
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.py"
PANEL_BACKEND_PATH="/usr/local/bin/wss_panel.py"
PANEL_HTML_DEST="$PANEL_DIR/index.html"

# 创建基础目录 (P1 修复)
mkdir -p "$PANEL_DIR" 
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
touch "$WSS_LOG_FILE"

# =============================
# 提示端口和面板密码 (保持不变)
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施端口配置 ===="

# 使用默认值或环境变量
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}
WSS_TLS_PORT=${WSS_TLS_PORT:-443}
STUNNEL_PORT=${STUNNEL_PORT:-444}
UDPGW_PORT=${UDPGW_PORT:-7300}
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}
PANEL_PORT=${PANEL_PORT:-54321}

echo "HTTP Port: $WSS_HTTP_PORT, TLS Port: $WSS_TLS_PORT"
echo "Stunnel Port: $STUNNEL_PORT, Internal Port: $INTERNAL_FORWARD_PORT"
echo "Panel Port: $PANEL_PORT"

# 交互式设置 ROOT 密码
if [ -f "$ROOT_HASH_FILE" ]; then
    echo "使用已保存的面板 Root 密码。面板端口: $PANEL_PORT"
    PANEL_ROOT_PASS_HASH=$(cat "$ROOT_HASH_FILE")
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


echo "----------------------------------"
echo "==== 系统清理与依赖检查 ===="
# 停止所有相关服务并清理旧文件
systemctl stop wss wss-ssh wss-tls || true
systemctl stop stunnel4 || true
systemctl stop udpgw || true
systemctl stop wss_panel || true

# 依赖检查和安装
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables procps libffi-dev || echo "警告: 依赖安装失败，可能影响功能。"

# 尝试安装 Python 库
if pip3 install flask psutil requests uvloop bcrypt crypt; then
    HAS_BCRYPT=1
    echo "Python 依赖 (Flask, psutil, uvloop, bcrypt, crypt) 安装成功。"
else
    # 尝试安装核心库
    if pip3 install flask psutil requests; then
        HAS_BCRYPT=0
        echo "警告: uvloop/bcrypt/crypt 安装失败。性能和安全回退生效。"
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
        # 回退到带盐的 SHA-512 crypt hash
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

# --- 生成/加载持久化的 Session Secret Key ---
if [ ! -f "$SECRET_KEY_FILE" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

echo "----------------------------------"

# =============================
# BBR 拥塞控制和网络调优
# =============================
echo "==== 配置 BBR 拥塞控制和网络优化 ===="
sed -i '/# WSS_NET_START/,/# WSS_NET_END/d' /etc/sysctl.conf
cat >> /etc/sysctl.conf <<EOF
# WSS_NET_START
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_max_syn_backlog = 65536
net.core.somaxconn = 65536
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 5
# WSS_NET_END
EOF
sysctl -p > /dev/null
echo "BBR 拥塞控制和网络参数优化完成。"
echo "----------------------------------"

# =============================
# 部署代码文件 (修正路径)
# =============================
echo "==== 部署模块化代码文件 (使用扁平路径) ===="
# 1. 复制 WSS Proxy (从仓库根目录)
cp "$REPO_ROOT/wss_proxy.py" "$WSS_PROXY_PATH"
chmod +x "$WSS_PROXY_PATH"
echo "WSS Proxy 脚本复制到 $WSS_PROXY_PATH"

# 2. 复制 Panel Backend (从仓库根目录)
cp "$REPO_ROOT/wss_panel.py" "$PANEL_BACKEND_PATH"
chmod +x "$PANEL_BACKEND_PATH"
echo "Panel Backend 脚本复制到 $PANEL_BACKEND_PATH"

# 3. 复制 Panel Frontend (从仓库根目录)
cp "$REPO_ROOT/index.html" "$PANEL_HTML_DEST"
echo "Panel Frontend 模板复制到 $PANEL_HTML_DEST"

# 4. 初始化数据库文件 (如果不存在)
[ ! -f "$PANEL_DIR/users.json" ] && echo "[]" > "$PANEL_DIR/users.json"
[ ! -f "$PANEL_DIR/ip_bans.json" ] && echo "{}" > "$PANEL_DIR/ip_bans.json"
[ ! -f "$PANEL_DIR/audit.log" ] && touch "$PANEL_DIR/audit.log"
echo "数据库文件初始化完成。"
echo "----------------------------------"


# =============================
# 安装 Stunnel4 并生成证书 (保持不变)
# =============================
echo "==== 重新安装 Stunnel4 & 证书 ===="
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

systemctl enable stunnel4
systemctl restart stunnel4
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

# 部署 UDPGW systemd 服务 (从根目录复制模板并替换变量)
UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service"
# 修正点: 从 $REPO_ROOT/udpgw.service.template 复制
cp "$REPO_ROOT/udpgw.service.template" "$UDPGW_SERVICE_PATH"
# 替换模板中的变量
sed -i "s|@UDPGW_PORT@|$UDPGW_PORT|g" "$UDPGW_SERVICE_PATH"


systemctl daemon-reload
systemctl enable udpgw
systemctl restart udpgw
echo "UDPGW 已部署并重启，端口: $UDPGW_PORT"
echo "----------------------------------"

# =============================
# Traffic Control 基础配置 (保持不变)
# =============================
echo "==== 配置 Traffic Control (tc) 基础环境 ===="
IP_DEV=$(ip route | grep default | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)

if [ -z "$IP_DEV" ]; then
    echo "警告: 无法找到主网络接口，带宽限制功能可能无效。"
else
    tc qdisc del dev "$IP_DEV" root || true
    tc qdisc add dev "$IP_DEV" root handle 1: htb default 10
    tc class add dev "$IP_DEV" parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit
    echo "Traffic Control (tc) 已在 $IP_DEV 上初始化。"
fi
echo "----------------------------------"

# =============================
# IPTABLES 基础配置 (保持不变)
# =============================
echo "==== 配置 IPTABLES 基础链 (IP 封禁 & 流量追踪优化) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
QUOTA_CHAIN="WSS_QUOTA_OUTPUT" 

iptables -D INPUT -j $BLOCK_CHAIN 2>/dev/null || true
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true

iptables -D OUTPUT -j $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -F $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -X $QUOTA_CHAIN 2>/dev/null || true

iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

iptables -t filter -N $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -A OUTPUT -j $QUOTA_CHAIN

echo "IPTABLES 基础链配置完成。服务端口开放请手动配置或使用防火墙软件。"
echo "----------------------------------"


# =============================
# 部署 Systemd 服务 (使用内嵌模板替换变量)
# =============================
echo "==== 部署 Systemd 服务 ===="

# 1. 部署 WSS Proxy Service (从根目录复制模板并替换变量)
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
# 修正点: 从 $REPO_ROOT/wss.service.template 复制
cp "$REPO_ROOT/wss.service.template" "$WSS_SERVICE_PATH"
# 替换模板中的变量
sed -i "s|@WSS_LOG_FILE_PATH@|$WSS_LOG_FILE|g" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_PROXY_SCRIPT_PATH@|$WSS_PROXY_PATH|g" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_HTTP_PORT@|$WSS_HTTP_PORT|g" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_TLS_PORT@|$WSS_TLS_PORT|g" "$WSS_SERVICE_PATH"
sed -i "s|@INTERNAL_FORWARD_PORT@|$INTERNAL_FORWARD_PORT|g" "$WSS_SERVICE_PATH"


systemctl daemon-reload
systemctl enable wss
systemctl start wss
echo "WSS 代理服务已部署并启动。"

# 2. 部署 Panel Service (从根目录复制模板并替换变量)
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
# 修正点: 从 $REPO_ROOT/wss_panel.service.template 复制
cp "$REPO_ROOT/wss_panel.service.template" "$PANEL_SERVICE_PATH"
# 替换模板中的变量
sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$PANEL_SERVICE_PATH"
sed -i "s|@WSS_LOG_FILE_PATH@|$WSS_LOG_FILE|g" "$PANEL_SERVICE_PATH"
sed -i "s|@WSS_HTTP_PORT@|$WSS_HTTP_PORT|g" "$PANEL_SERVICE_PATH"
sed -i "s|@WSS_TLS_PORT@|$WSS_TLS_PORT|g" "$PANEL_SERVICE_PATH"
sed -i "s|@STUNNEL_PORT@|$STUNNEL_PORT|g" "$PANEL_SERVICE_PATH"
sed -i "s|@UDPGW_PORT@|$UDPGW_PORT|g" "$PANEL_SERVICE_PATH"
sed -i "s|@INTERNAL_FORWARD_PORT@|$INTERNAL_FORWARD_PORT|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_PORT@|$PANEL_PORT|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_BACKEND_SCRIPT_PATH@|$PANEL_BACKEND_PATH|g" "$PANEL_SERVICE_PATH"

systemctl daemon-reload
systemctl enable wss_panel
systemctl restart wss_panel
echo "WSS 管理面板服务已部署并启动。"
echo "----------------------------------"

# =============================
# SSHD 安全配置 (禁用 Shell 访问)
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")

echo "==== 配置 SSHD 隧道策略 ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by modular-deploy.sh
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
# WSS_TUNNEL_BLOCK_END -- managed by modular-deploy.sh

EOF

chmod 600 "$SSHD_CONFIG"

echo "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置更新完成。内部SSH转发端口: $INTERNAL_FORWARD_PORT (禁止Shell)"
echo "----------------------------------"


# =============================
# 最终重启所有关键服务
# =============================
echo "==== 最终重启所有关键服务，确保配置生效 ===="
systemctl restart wss stunnel4 udpgw wss_panel
echo "所有服务重启完成：WSS, Stunnel4, UDPGW, Web Panel。"
echo "----------------------------------"


# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ 部署完成！"
echo "=================================================="
echo ""
echo "🔥 WSS & Stunnel 基础设施已启动。"
echo "🌐 WSS 用户管理面板已在后台运行。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 模块化文件路径 ---"
echo "代理核心: $WSS_PROXY_PATH"
echo "后端逻辑: $PANEL_BACKEND_PATH"
echo "前端模板: $PANEL_HTML_DEST"
echo "=================================================="
