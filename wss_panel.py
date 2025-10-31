# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import json
import subprocess
import os
import hashlib
import time
import jinja2
import re
import random
from datetime import date, timedelta, datetime
from functools import wraps
import psutil
import shutil
import logging
import sys

# P10 FIX: 确保变量在导入尝试前被定义，解决 NameError
HAS_BCRYPT = False
HAS_CRYPT = False

# NEW: 尝试导入 bcrypt / crypt (用于密码哈希回退)
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    pass
    
try:
    # crypt 是 Python 的标准库模块，不需要 pip 安装
    import crypt
    HAS_CRYPT = True
except ImportError:
    pass


# --- 配置 (从环境变量读取，不再依赖 Bash 替换硬编码) ---
PANEL_DIR = os.environ.get('PANEL_DIR_ENV', '/etc/wss-panel')
USER_DB_PATH = os.path.join(PANEL_DIR, 'users.json')
IP_BANS_DB_PATH = os.path.join(PANEL_DIR, 'ip_bans.json')
AUDIT_LOG_PATH = os.path.join(PANEL_DIR, 'audit.log')
ROOT_HASH_FILE = os.path.join(PANEL_DIR, 'root_hash.txt')
PANEL_HTML_PATH = os.path.join(PANEL_DIR, 'index.html')
LOGIN_HTML_PATH = os.path.join(PANEL_DIR, 'login.html') # 新增登录页面路径
SECRET_KEY_PATH = os.path.join(PANEL_DIR, 'secret_key.txt')
WSS_LOG_FILE = os.environ.get('WSS_LOG_FILE_ENV', '/var/log/wss.log')

ROOT_USERNAME = "root"
GIGA_BYTE = 1024 * 1024 * 1024 # 1 GB in bytes
BLOCK_CHAIN = "WSS_IP_BLOCK"
QUOTA_CHAIN = "WSS_QUOTA_OUTPUT" 

# 端口配置 (从环境变量读取)
WSS_HTTP_PORT = os.environ.get('WSS_HTTP_PORT_ENV', '80')
WSS_TLS_PORT = os.environ.get('WSS_TLS_PORT_ENV', '443')
STUNNEL_PORT = os.environ.get('STUNNEL_PORT_ENV', '444')
UDPGW_PORT = os.environ.get('UDPGW_PORT_ENV', '7300')
INTERNAL_FORWARD_PORT = os.environ.get('INTERNAL_FORWARD_PORT_ENV', '22')
PANEL_PORT = os.environ.get('PANEL_PORT_ENV', '54321')

# WSS/Stunnel/UDPGW/Panel service names
CORE_SERVICES = {
    'wss': 'WSS Proxy',
    'stunnel4': 'Stunnel4',
    'udpgw': 'UDPGW',
    'wss_panel': 'Web Panel'
}

app = Flask(__name__)

# --- 加载持久化的 Secret Key ---
def load_secret_key():
    try:
        with open(SECRET_KEY_PATH, 'r') as f:
            return f.read().strip()
    except Exception:
        # Fallback to generate a new key if file read fails (unlikely if setup is correct)
        return os.urandom(24).hex() 

app.secret_key = load_secret_key()
# -----------------------------------

# --- 数据库操作 / 认证 / 审计日志 ---

def load_data(path, default_value):
    """加载 JSON 数据。"""
    if not os.path.exists(path): return default_value
    try:
        with open(path, 'r') as f: return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return default_value

def save_data(data, path):
    """保存 JSON 数据。"""
    try:
        with open(path, 'w') as f: json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving {path}: {e}")
        return False

def load_users(): return load_data(USER_DB_PATH, [])
def save_users(users): return save_data(users, USER_DB_PATH)
def load_ip_bans(): return load_data(IP_BANS_DB_PATH, {})
def save_ip_bans(ip_bans): return save_data(ip_bans, IP_BANS_DB_PATH)
def load_root_hash():
    try:
        with open(ROOT_HASH_FILE, 'r') as f: return f.read().strip()
    except Exception: return None

def log_action(action_type, username, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    operator_ip = request.remote_addr if request else "127.0.0.1 (System)"
    log_entry = f"[{timestamp}] [USER:{username}] [IP:{operator_ip}] ACTION:{action_type} DETAILS: {details}\n"
    try:
        with open(AUDIT_LOG_PATH, 'a') as f: f.write(log_entry)
    except Exception as e:
        print(f"Error writing to audit log: {e}")

def get_recent_audit_logs(n=20):
    try:
        if not os.path.exists(AUDIT_LOG_PATH):
            return ["日志文件不存在。"]
        # Use python's tail equivalent if shutil.which('tail') is unreliable
        command = [shutil.which('tail') or '/usr/bin/tail', '-n', str(n), AUDIT_LOG_PATH]
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        # Fix: Ensure each line is processed correctly, avoiding unexpected symbols
        return result.stdout.decode('utf-8').strip().split('\n')
    except Exception:
        return ["读取日志失败或日志文件为空。"]

# FIX P7: 修改 login_required 装饰器，API 请求返回 401 JSON 错误
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_api_request = request.path.startswith('/api/')

        if 'logged_in' not in session or not session.get('logged_in'):
            log_action("LOGIN_ATTEMPT", "N/A", f"Access denied to {request.path}")
            
            if is_api_request:
                # API 请求返回 401 JSON 错误
                return jsonify({"success": False, "message": "认证失败或会话过期"}), 401
            else:
                # 页面请求重定向到登录页
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ + "_decorated"
    return decorated_function

# --- 系统命令执行和状态函数 (核心修改) ---
def safe_run_command(command, input_data=None):
    """
    安全运行系统命令。
    此版本将使用 shutil.which 确定命令的绝对路径，增强鲁棒性。
    """
    # 尝试查找命令的绝对路径
    cmd_path = shutil.which(command[0])
    if not cmd_path:
        return False, f"Command not found: {command[0]}"
    
    # 替换命令列表中的第一个元素为绝对路径
    command[0] = cmd_path

    try:
        process = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            encoding='utf-8',
            input=input_data,
            timeout=5
        )
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()
        
        # 允许某些非零退出码通过 (例如 grep, userdel -r)
        if process.returncode != 0:
            if 'already exists' in stderr or 'No chain/target/match' in stderr or 'user not found' in stderr or 'no such process' in stderr:
                return True, stdout
            
            # 如果是其他非零返回码，返回失败
            return False, stderr or f"Command '{' '.join(command)}' failed with code {process.returncode}. Stderr: {stderr}"
        
        # 成功执行
        return True, stdout
        
    except subprocess.TimeoutExpired:
        return False, f"Command '{' '.join(command)}' timed out"
    except Exception as e:
        return False, f"Execution error for '{' '.join(command)}': {str(e)}"

def get_user(username):
    users = load_users()
    for i, user in enumerate(users):
        if user.get('username') == username: return user, i
    return None, -1

def get_user_uid(username):
    """获取用户的 UID。"""
    success, output = safe_run_command([shutil.which('id') or '/usr/bin/id', '-u', username])
    return int(output) if success and output.isdigit() else None

def get_service_status(service):
    """检查 systemd 服务的状态。"""
    try:
        success, output = safe_run_command([shutil.which('systemctl') or '/bin/systemctl', 'is-active', service])
        return 'running' if success and output.strip() == 'active' else 'failed'
    except Exception:
        return 'failed'

def get_port_status(port):
    """检查端口是否处于 LISTEN 状态 (使用 ss 命令)"""
    try:
        ss_bin = shutil.which('ss') or '/bin/ss'
        # Check for both TCP and UDP
        success_tcp, output_tcp = safe_run_command([ss_bin, '-tuln'])
        if success_tcp and re.search(fr'(:{re.escape(str(port))})\s', output_tcp):
            return 'LISTEN'
        return 'FAIL'
    except Exception:
        return 'FAIL'
        
def get_service_logs(service_name, lines=50):
    """获取指定服务的 journalctl 日志。"""
    try:
        command = [shutil.which('journalctl') or '/bin/journalctl', '-u', service_name, f'-n', str(lines), '--no-pager', '--utc']
        success, output = safe_run_command(command)
        return output if success else f"错误: 无法获取 {service_name} 日志. {output}"
    except Exception as e:
        return f"日志获取异常: {str(e)}"

def kill_user_sessions(username):
    """终止给定用户名的所有活跃 SSH 会话。"""
    safe_run_command([shutil.which('pkill') or '/usr/bin/pkill', '-u', username])

def manage_ip_iptables(ip, action, chain_name=BLOCK_CHAIN):
    """在指定链中添加或移除 IP 阻断规则，并保存规则。"""
    if action == 'check':
        check_cmd = ['iptables', '-C', chain_name, '-s', ip, '-j', 'DROP']
        # subprocess.run handles the return code, 0 is success (rule exists)
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return result.returncode == 0, "Check complete."

    if action == 'block':
        # 先删除可能存在的旧规则，再插入新规则到最前面 (I 1)
        safe_run_command(['iptables', '-D', chain_name, '-s', ip, '-j', 'DROP'])
        command = ['iptables', '-I', chain_name, '1', '-s', ip, '-j', 'DROP']
    elif action == 'unblock':
        command = ['iptables', '-D', chain_name, '-s', ip, '-j', 'DROP']
    else: return False, "Invalid action"

    success, output = safe_run_command(command)
    if success:
        # 尝试保存 IPTABLES 规则
        try:
            iptables_save_path = shutil.which('iptables-save') or '/sbin/iptables-save'
            rules_v4_path = '/etc/iptables/rules.v4'
            rules_v4_dir = os.path.dirname(rules_v4_path)
            
            # 使用绝对路径执行 iptables-save
            if os.path.exists(rules_v4_dir):
                with open(rules_v4_path, 'w') as f:
                    subprocess.run([iptables_save_path], stdout=f, check=True, timeout=3)
        except Exception as e:
            print(f"Warning: Failed to save iptables rules: {e}", file=sys.stderr)
            pass
            
    return success, output

# --- 流量管控 (Quota/Rate Limit) 逻辑 (增强错误日志) ---

def manage_quota_iptables_rule(username, uid, action='add', quota_limit_bytes=0):
    """
    【修正】管理用户的 IPTables 流量配额和计数规则。
    为了解决规则丢失问题，我们确保无论配额如何，都至少有一条规则用于流量计数。
    """
    comment = f"WSS_QUOTA_{username}"
    # 定义匹配规则
    match_rule = [
        '-t', 'filter',
        '-m', 'owner', '--uid-owner', str(uid),
        '-m', 'comment', '--comment', comment
    ]
    
    # 1. 【清理】清除所有匹配到的旧规则 (避免重复添加)
    iptables_bin = shutil.which('iptables') or '/sbin/iptables'
    # 尝试删除所有可能的规则形态（配额RETURN, 配额DROP, 无配额RETURN）
    # 暴力删除匹配的规则直到失败 (没有更多规则可删)
    try:
        for target in ['RETURN', 'DROP']:
            while True:
                # 尝试删除规则，-D 是删除
                # 注意：-D 需要完全匹配规则，所以我们尝试各种形式
                # 尝试删除配额规则
                result = subprocess.run([iptables_bin, '-t', 'filter', '-D', QUOTA_CHAIN] + match_rule + ['-m', 'quota', '--quota', '0', '-j', target], capture_output=True, timeout=1, text=True)
                if result.returncode != 0: break # 删除失败或规则不存在，跳出
            while True:
                # 尝试删除无配额规则（仅计数）
                result = subprocess.run([iptables_bin, '-t', 'filter', '-D', QUOTA_CHAIN] + match_rule + ['-j', target], capture_output=True, timeout=1, text=True)
                if result.returncode != 0: break # 删除失败或规则不存在，跳出
    except Exception as e:
        print(f"Warning: IPTables cleanup failed for {username}: {e}", file=sys.stderr)
        pass # 忽略清理错误

    if action == 'add' or action == 'modify':
        if quota_limit_bytes > 0:
            # 规则 1: 在配额内允许通过 (RETURN)
            command_quota = ['iptables', '-A', QUOTA_CHAIN] + match_rule + ['-m', 'quota', '--quota', str(quota_limit_bytes), '-j', 'RETURN']
            success, output = safe_run_command(command_quota)
            if not success: 
                print(f"Error setting QUOTA RETURN rule for {username}: {output}", file=sys.stderr)
                return False, f"Quota rule setup (RETURN) failed: {output}"
            
            # 规则 2: 超出配额拒绝 (DROP)
            command_drop = ['iptables', '-A', QUOTA_CHAIN] + match_rule + ['-j', 'DROP']
            success_drop, output_drop = safe_run_command(command_drop)
            if not success_drop: 
                print(f"Error setting QUOTA DROP rule for {username}: {output_drop}", file=sys.stderr)
                return False, f"Quota rule setup (DROP) failed: {output_drop}"
        else:
            # 无限流量: 仅添加计数规则 (RETURN)，用于获取流量数据
            # 注意：此规则会匹配流量并返回，但由于没有 quota 限制，其计数器会持续增加。
            command_return = ['iptables', '-A', QUOTA_CHAIN] + match_rule + ['-j', 'RETURN']
            success, output = safe_run_command(command_return)
            if not success: 
                print(f"Error setting QUOTA COUNT rule for {username}: {output}", file=sys.stderr)
                return False, f"Quota count rule failed: {output}"
            
        # 2. 【持久化】每次更改后尝试保存 IPTables 规则
        try:
            iptables_save_path = shutil.which('iptables-save') or '/sbin/iptables-save'
            rules_v4_path = '/etc/iptables/rules.v4'
            # 确保使用绝对路径，并捕获保存错误
            subprocess.run([iptables_save_path], stdout=open(rules_v4_path, 'w'), check=True, timeout=3)
        except Exception as e:
            print(f"Warning: Failed to save iptables rules after rule modification: {e}", file=sys.stderr)
            pass
            
        return True, "Quota rule updated."
        
    # 仅进行清理操作
    return True, "Quota rule cleaned up."


def get_user_current_usage_bytes(username, uid):
    """
    【修正】从 IPTables QUOTA_CHAIN 中获取用户的当前流量使用量（字节）。
    优化：只关注字节数，不依赖 RETURN/DROP 目标的匹配。
    """
    comment = f"WSS_QUOTA_{username}"
    # 获取计数：使用 -Lnvx，只列出匹配到的规则。
    command_get = [
        'iptables', 
        '-t', 'filter', 
        '-nvxL', QUOTA_CHAIN
    ]
    success, output = safe_run_command(command_get)
    if not success: 
        print(f"Error executing iptables to get usage for {username}: {output}", file=sys.stderr)
        return 0
    
    # 正则表达式匹配 QUOTA_CHAIN 中带有指定 COMMENT 的规则 (查找 bytes 字段)
    # iptables -nvxL 输出格式通常是: pkts bytes target prot opt in out source destination ... comment
    # 我们关注的是第二个字段: bytes
    # 匹配规则: 行首 (空格), 任意数字 (pkts), 至少一个空格, 捕获的字节数 (bytes), 任意字符直到 COMMENT 字段
    # 使用 \s+ 确保匹配到字节数字段
    pattern = re.compile(r'^\s*[\d]+\s+([\d]+).*\s+COMMENT\s+--\s+.*' + re.escape(comment))
    
    total_usage = 0
    
    # 关键：由于有两条规则 (RETURN 和 DROP)，我们需要累加它们的流量。
    # 对于无限流量用户只有一条 RETURN 规则，其 bytes 字段即为总用量。
    # 对于有限流量用户，RETURN 规则的 bytes + DROP 规则的 bytes = 总用量。
    for line in output.split('\n'):
        match = pattern.search(line)
        if match:
            try: 
                usage = int(match.group(1))
                total_usage += usage
            except (IndexError, ValueError): 
                # 解析失败，可能是格式不匹配
                continue 
    
    # 如果找到任何匹配规则，返回累加的流量。否则返回 0
    return total_usage

    
def reset_iptables_counters(username):
    """重置指定用户名的 IPTables 计数器。"""
    comment = f"WSS_QUOTA_{username}"
    # 使用 -Z (Zero) 命令重置计数器
    command = ['iptables', '-t', 'filter', '-Z', QUOTA_CHAIN, '-m', 'comment', '--comment', comment]
    safe_run_command(command) # 忽略错误，因为如果规则不存在，它会报错


def apply_rate_limit(uid, rate_kbps):
    """使用 Traffic Control (tc) 实现用户的下载带宽限制。"""
    
    # NEW: Robustly determine primary network device using pure Python/subprocess logic
    success, output = safe_run_command(['ip', 'route', 'show', 'default'])
    dev = ''
    if success and output:
        parts = output.split()
        try:
            # Find the interface name after the 'dev' keyword
            dev_index = parts.index('dev') + 1
            dev = parts[dev_index]
        except (ValueError, IndexError):
            pass
    
    if not dev:
        print("Error: Could not determine primary network device for tc. Bandwidth limiting disabled.", file=sys.stderr)
        return False, "无法找到网络接口"
    
    dev = dev.strip()
    tc_handle = f"1:{int(uid)}" # Use HTB class ID 1:UID
    mark = int(uid) # Use UID as the firewall mark

    # IPTables command parts to delete the specific rule
    # Added --wait option for stability
    ipt_del_cmd = ['iptables', '-t', 'mangle', '-D', 'POSTROUTING', 
                   '-m', 'owner', '--uid-owner', str(uid), 
                   '-j', 'MARK', '--set-mark', str(mark),
                   '--wait']

    try:
        rate = int(rate_kbps)
        
        # --- 1. CLEANUP (Critical for reliability) ---
        safe_run_command(ipt_del_cmd)
        # Delete TC filter and class (order matters: filter before class)
        safe_run_command(['tc', 'filter', 'del', 'dev', dev, 'parent', '1:', 'protocol', 'ip', 'prio', '100', 'handle', str(mark), 'fw']) # Added 'fw' to specify the filter type
        safe_run_command(['tc', 'class', 'del', 'dev', dev, 'parent', '1:', 'classid', tc_handle])


        if rate > 0:
            # Convert KB/s to Mbit/s (1 KB/s = 8 kbit/s = 0.008 Mbit/s)
            rate_kbit = rate * 8
            rate_str = f"{rate_kbit}kbit" 
            
            # --- 2. ADD TC CLASS (Bandwidth limit container) ---
            tc_class_cmd = ['tc', 'class', 'add', 'dev', dev, 'parent', '1:', 'classid', tc_handle, 'htb', 'rate', rate_str, 'ceil', rate_str]
            
            success_class, output_class = safe_run_command(tc_class_cmd)
            if not success_class:
                print(f"TC Class error for {username}: {output_class}", file=sys.stderr)
                return False, f"TC Class error: {output_class}"

            # --- 3. ADD IPTABLES RULE (Mark packets from this UID) ---
            # Added --wait option for stability
            iptables_add_cmd = ['iptables', '-t', 'mangle', '-A', 'POSTROUTING', 
                                 '-m', 'owner', '--uid-owner', str(uid), 
                                 '-j', 'MARK', '--set-mark', str(mark),
                                 '--wait']

            success_ipt, output_ipt = safe_run_command(iptables_add_cmd)
            if not success_ipt:
                print(f"IPTables error for {username}: {output_ipt}", file=sys.stderr)
                safe_run_command(['tc', 'class', 'del', 'dev', dev, 'parent', '1:', 'classid', tc_handle])
                return False, f"IPTables error: {output_ipt}"

            # --- 4. ADD TC FILTER (Match firewall mark) ---
            tc_filter_cmd = ['tc', 'filter', 'add', 'dev', dev, 'parent', '1:', 'protocol', 'ip', 
                             'prio', '100', 'handle', str(mark), 'fw', 'flowid', tc_handle]
            
            success_filter, output_filter = safe_run_command(tc_filter_cmd)
            if not success_filter:
                print(f"TC Filter error for {username}: {output_filter}", file=sys.stderr)
                safe_run_command(['tc', 'class', 'del', 'dev', dev, 'parent', '1:', 'classid', tc_handle])
                safe_run_command(ipt_del_cmd)
                return False, f"TC Filter error: {output_filter}"
                
            return True, f"已限制速度到 {rate_kbps} KB/s" # 返回 KB/s
            
        else:
            return True, "已清除速度限制"
            
    except Exception as e:
        print(f"TC command execution failed: {e}", file=sys.stderr)
        return False, f"TC command execution failed: {e}"


def get_user_active_connections(username):
    """【新逻辑】获取指定用户的活跃 SSHD 会话数量 (使用 pgrep)。"""
    # 简化：仅返回 SSHD 进程数量
    success, output = safe_run_command(['pgrep', '-c', '-u', username, 'sshd'])
    return int(output) if success and output.isdigit() else 0


def get_user_active_sessions_info(username):
    """
    【基于日志的关联】通过匹配 WSS 日志，来获取用户的客户端 IP。
    (与原脚本逻辑相同，依赖 WSS_LOG_FILE)
    """
    INTERNAL_PORT_STR = str(INTERNAL_FORWARD_PORT)
    
    user_pids = get_user_sshd_pids(username)
    
    # 活跃连接的启发式判断：如果 SSHD 进程数量为 0，则无需查找 IP
    if not user_pids:
        return {'sshd_pids': [], 'active_ips': []}
        
    active_ips = set()
    
    if os.path.exists(WSS_LOG_FILE):
        try:
            # 1. 读取最近 200 行 WSS 日志
            command_tail = ['tail', '-n', '200', WSS_LOG_FILE]
            success_tail, log_output = safe_run_command(command_tail)
            
            # 2. 从日志中提取 IPs
            if success_tail:
                # 正则表达式匹配日志格式: [TIMESTAMP] [CONN_START] CLIENT_IP=X.X.X.X ...
                log_pattern = re.compile(r'CLIENT_IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                ips_from_log = set(log_pattern.findall(log_output))
                
                # 3. 获取当前全局活跃的 ESTAB IP 列表
                global_active_ips = set(item['ip'] for item in get_all_active_external_ips() if not item['is_banned'])
                
                # 4. 关联：返回那些既在日志中出现过，又在当前全局 ESTAB 列表中的 IP
                correlated_ips = ips_from_log.intersection(global_active_ips)
                
                # 5. 格式化输出
                for ip in correlated_ips:
                    is_banned = manage_ip_iptables(ip, 'check')[0]
                    active_ips.add(json.dumps({'ip': ip, 'is_banned': is_banned}))
                    
        except Exception as e:
            print(f"Error during log-based IP association: {e}", file=sys.stderr)
            pass

    # 格式化 IP 列表
    ip_list = [json.loads(s) for s in active_ips]
    
    return {'sshd_pids': user_pids, 'active_ips': ip_list}

def get_user_sshd_pids(username):
    """获取指定用户的活跃 SSHD 进程 ID 列表。"""
    success, output = safe_run_command(['pgrep', '-u', username, 'sshd'])
    if success and output:
        return [int(p) for p in output.split() if p.isdigit()]
    return []

def get_all_active_external_ips():
    """
    获取连接到 WSS/Stunnel 端口的所有外部客户端 IP。
    """
    ss_bin = shutil.which('ss') or '/bin/ss'
    EXTERNAL_PORTS = [WSS_HTTP_PORT, WSS_TLS_PORT, STUNNEL_PORT]
    # 将端口转换为字符串集合
    EXTERNAL_PORTS_STR = set(str(p) for p in EXTERNAL_PORTS)
    active_ips = set()
    
    try:
        success_ss, ss_output = safe_run_command(['ss', '-tan'])
        if not success_ss: 
            return {"error": f"Failed to run ss: {ss_output}"}
        
        for line in ss_output.split('\n'):
            if 'ESTAB' not in line: continue
            
            parts = line.split()
            if len(parts) < 5: continue
            
            local_addr_port = parts[3]
            remote_addr_port = parts[4]
            
            try:
                local_port = local_addr_port.split(':')[-1]
                client_ip = remote_addr_port.split(':')[0]

                is_internal_ssh_conn = remote_addr_port.startswith('127.0.0.1')

                is_on_external_port = local_port in EXTERNAL_PORTS_STR
                
            except Exception:
                continue

            if is_on_external_port and not is_internal_ssh_conn:
                
                if client_ip not in ('127.0.0.1', '::1', '0.0.0.0', '[::]'):
                    active_ips.add(client_ip)
                    
    except Exception as e:
        return {"error": f"Execution error: {str(e)}"}
    
    # 格式化并检查封禁状态
    ip_list = []
    for ip in sorted(list(active_ips)): # 排序以便于前端显示
        is_banned = manage_ip_iptables(ip, 'check')[0]
        ip_list.append({
            'ip': ip,
            'is_banned': is_banned
        })
    return ip_list


def sync_user_status(user):
    """同步用户状态到系统并应用 TC/IPTables 规则。"""
    username = user['username']
    uid = get_user_uid(username)
    if uid is None:
        user['status'] = 'deleted'
        return user
    
    is_expired = False
    
    if user.get('expiration_date'):
        try:
            # 必须使用 datetime.strptime 来解析精确格式，因为 chage -E 会使用精确格式
            expiry_dt = datetime.strptime(user['expiration_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date(): is_expired = True
        except ValueError: pass

    # --- 流量配额检查 ---
    quota_limit_gb = user.get('quota_gb', 0)
    quota_limit_bytes = quota_limit_gb * GIGA_BYTE
    current_bytes = get_user_current_usage_bytes(username, uid)
    is_over_quota = (quota_limit_gb > 0 and current_bytes >= quota_limit_bytes)
    
    # 更新用户对象中的用量数据
    user['usage_gb'] = round(current_bytes / GIGA_BYTE, 2)

    # 账户应被锁定的条件
    should_be_locked = is_expired or is_over_quota or (user.get('status') == 'paused')
    
    # --- 系统锁定状态检查 ---
    system_locked = False
    success_status, output_status = safe_run_command(['passwd', '-S', username])
    if success_status and output_status and ' L ' in output_status: system_locked = True
    
    # --- 状态同步（usermod）---
    if should_be_locked and not system_locked:
        safe_run_command(['usermod', '-L', username])
        # 强制设置一个过期时间，确保系统锁定
        safe_run_command(['chage', '-E', '1970-01-01', username]) 
        kill_user_sessions(username)
        if is_expired: user['status'] = 'expired'
        elif is_over_quota: user['status'] = 'exceeded'
        else: user['status'] = 'paused'
    elif not should_be_locked and system_locked:
        safe_run_command(['usermod', '-U', username])
        # 恢复或设置正确的过期时间
        if user.get('expiration_date'):
             safe_run_command(['chage', '-E', user['expiration_date'], username])
        user['status'] = 'active'
    elif not should_be_locked and not system_locked:
        user['status'] = 'active'

    # --- 规则同步 (始终确保规则状态与配额匹配) ---
    apply_rate_limit(uid, user.get('rate_kbps', '0'))
    
    # 【关键修正】：无论用户是否超额或被暂停，都应该**尝试添加**计数和限制规则
    # manage_quota_iptables_rule 的内部逻辑会处理是添加 RETURN/DROP 还是只添加 RETURN。
    # 唯一不添加规则的情况是用户被删除，但我们在这里已经通过 uid is None 提前处理了。
    if user['status'] == 'exceeded':
        # 如果超额，我们强制添加配额为 0 的规则，确保 DROP 规则生效（如果配额限制已存在）。
        # 如果 quota_limit_bytes > 0，manage_quota_iptables_rule 内部会创建 DROP 规则。
        manage_quota_iptables_rule(username, uid, 'add', 0)
    else:
        # 正常或暂停状态，根据面板配置的配额添加规则
        manage_quota_iptables_rule(username, uid, 'add', quota_limit_bytes)
        
    # --- 活跃连接和流量分配 (面板显示) ---
    active_conns = get_user_active_connections(username)
    user['active_connections'] = active_conns
    user['realtime_speed'] = random.randint(300, 700) * active_conns # 模拟实时速度
    
    return user

def refresh_all_user_status(users):
    """刷新所有用户的状态，并返回统计数据。"""
    updated_users = []
    total_traffic = 0
    active_count = 0
    paused_count = 0
    expired_count = 0
    
    for user in users:
        try:
            user = sync_user_status(user)
        except Exception as e:
            print(f"Error syncing user {user.get('username')}: {e}", file=sys.stderr)
            continue
            
        if user['status'] == 'deleted': continue
        
        # 面板显示所需的字段
        if user['status'] == 'paused':
            user['status_text'] = "暂停 (Manual)"
            user['status_class'] = "bg-yellow-500"
            paused_count += 1
        elif user['status'] == 'expired':
            user['status_text'] = "已到期"
            user['status_class'] = "bg-red-500"
            expired_count += 1
        elif user['status'] == 'exceeded':
            user['status_text'] = "超额 (Quota Exceeded)"
            user['status_class'] = "bg-red-500"
            expired_count += 1
        else: # active
            user['status_text'] = "启用 (Active)"
            user['status_class'] = "bg-green-500"
            active_count += 1
        
        total_traffic += user.get('usage_gb', 0)
        updated_users.append(user)
    
    save_users(updated_users)
    return updated_users, {
        "total": len(updated_users),
        "active": active_count,
        "paused": paused_count,
        "expired": expired_count,
        "total_traffic_gb": total_traffic
    }


# --- Web 路由所需的渲染函数 ---

def render_dashboard():
    """手动读取 HTML 文件并进行 Jinja2 渲染。"""
    try:
        # 这里使用硬编码的路径，因为 Bash 脚本已经替换了该文件
        with open(PANEL_HTML_PATH, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        return "Error: HTML template file (index.html) not found. Check installation script path.", 500

    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(html_content)

    # 刷新所有用户状态以获取最新数据
    users, user_stats = refresh_all_user_status(load_users())

    context = {
        'WSS_HTTP_PORT': WSS_HTTP_PORT,
        'WSS_TLS_PORT': WSS_TLS_PORT,
        'STUNNEL_PORT': STUNNEL_PORT,
        'UDPGW_PORT': UDPGW_PORT,
        'INTERNAL_FORWARD_PORT': INTERNAL_FORWARD_PORT,
        'PANEL_PORT': PANEL_PORT,
    }
    return template.render(**context), 200


# --- Web 路由 ---

@app.route('/', methods=['GET'])
def dashboard():
    # FIX P9: 使用正确的路由端点 'dashboard'
    return decorated_dashboard() 

@login_required
def decorated_dashboard():
    html_content, status_code = render_dashboard()
    return make_response(html_content, status_code)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password_raw = request.form.get('password')
        root_hash = load_root_hash()
        
        authenticated = False

        if not root_hash:
            error = '面板配置错误，Root Hash丢失。'
        elif username == ROOT_USERNAME and password_raw:
            password_bytes = password_raw.encode('utf-8')
            root_hash_bytes = root_hash.encode('utf-8')
            
            # P2 修复: 优先使用 bcrypt 验证，其次尝试 crypt，最后尝试 SHA256
            if HAS_BCRYPT:
                try:
                    authenticated = bcrypt.checkpw(password_bytes, root_hash_bytes)
                except ValueError:
                    # 如果不是 bcrypt 格式，可能为旧的 SHA256/crypt，进行回退校验
                    pass
            
            # P10 FIX: 确保 HAS_CRYPT 已定义
            if not authenticated and HAS_CRYPT and root_hash.startswith('$'):
                    # 尝试 crypt 验证（通常是 $6$ 或 $5$ 开头的）
                    try:
                        if crypt.crypt(password_raw, root_hash) == root_hash:
                            authenticated = True
                            print("Warning: Logged in with crypt hash.", file=sys.stderr)
                    except Exception:
                        pass

            if not authenticated and len(root_hash) == 64:
                # 尝试 SHA256 校验 (如果 hash 长度匹配且之前都没有通过)
                if hashlib.sha256(password_bytes).hexdigest() == root_hash:
                    authenticated = True
                    print("Warning: Logged in with legacy SHA256 hash. Please update the password.", file=sys.stderr)


            if authenticated:
                session['logged_in'] = True
                session['username'] = ROOT_USERNAME
                log_action("LOGIN_SUCCESS", ROOT_USERNAME, "Web UI Login")
                # FIX P9: 将重定向目标改为正确的路由端点名称 'dashboard'
                return redirect(url_for('dashboard')) 
            else:
                error = '用户名或密码错误。'
                log_action("LOGIN_FAILED", username, "Wrong credentials")
        else:
            error = '用户名或密码错误。'
            log_action("LOGIN_FAILED", username, "Invalid username attempt")

    # --- 加载并渲染外部登录模板 ---
    try:
        # 1. 设置模板加载器：从面板目录加载
        template_loader = jinja2.FileSystemLoader(PANEL_DIR)
        template_env = jinja2.Environment(loader=template_loader)
        
        # 2. 加载 login.html (这里我们假设文件名为 login.html)
        template = template_env.get_template('login.html')
        
        # 3. 渲染并返回
        context = {
            'ROOT_USERNAME': ROOT_USERNAME,
            'error': error,
        }
        return template.render(**context), 200
        
    except FileNotFoundError:
        # 如果模板文件丢失，则返回默认的 HTML 错误
        return make_response("Error: Login template file (login.html) not found. Check deployment.", 500)
    except Exception as e:
        return make_response(f"Login rendering error: {str(e)}", 500)


@app.route('/logout')
def logout():
    log_action("LOGOUT_SUCCESS", session.get('username', 'root'), "Web UI Logout")
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# --- API 路由实现 ---

@app.route('/api/system/status', methods=['GET'])
@login_required
def get_system_status():
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        service_statuses = {}
        for service_id, service_name in CORE_SERVICES.items():
            state = get_service_status(service_id)
            service_statuses[service_id] = {
                'name': service_name,
                'status': state,
                'label': "运行中" if state == 'running' else ("失败" if state == 'failed' else "已停止")
            }
        ports = []
        for key, config in [('WSS_HTTP', WSS_HTTP_PORT), ('WSS_TLS', WSS_TLS_PORT), ('STUNNEL', STUNNEL_PORT), ('UDPGW', UDPGW_PORT), ('PANEL', PANEL_PORT), ('SSH_INTERNAL', INTERNAL_FORWARD_PORT)]:
            ports.append({'name': key, 'port': config, 'protocol': 'TCP' if key != 'UDPGW' else 'UDP', 'status': get_port_status(config)})

        _, user_stats = refresh_all_user_status(load_users())
            
        return jsonify({
            "success": True,
            "cpu_usage": cpu_percent,
            "memory_used_gb": round(mem.used / (1024 ** 3), 2),
            "memory_total_gb": round(mem.total / (1024 ** 3), 2),
            "disk_used_percent": disk.percent,
            "services": service_statuses,
            "ports": ports,
            "user_stats": user_stats
        })
    except Exception as e:
        log_action("SYSTEM_STATUS_ERROR", session.get('username', 'root'), f"Status check failed: {str(e)}")
        # API 错误返回 JSON
        return jsonify({"success": False, "message": f"System status check failed: {str(e)}"}), 500

@app.route('/api/system/control', methods=['POST'])
@login_required
def control_system_service():
    data = request.json
    service = data.get('service')
    action = data.get('action')
    if service not in CORE_SERVICES or action != 'restart': return jsonify({"success": False, "message": "无效的服务或操作"}), 400
    command = ['systemctl', action, service]
    success, output = safe_run_command(command)
    if success:
        log_action("SERVICE_CONTROL_SUCCESS", session.get('username', 'root'), f"Successfully executed {action} on {service}")
        return jsonify({"success": True, "message": f"服务 {CORE_SERVICES[service]} 已成功执行 {action} 操作。"})
    else:
        log_action("SERVICE_CONTROL_FAIL", session.get('username', 'root'), f"Failed to {action} {service}: {output}")
        return jsonify({"success": False, "message": f"服务 {CORE_SERVICES[service]} 操作失败: {output}"}), 500

@app.route('/api/system/logs', methods=['POST'])
@login_required
def get_service_logs_api():
    service_name = request.json.get('service')
    if service_name not in CORE_SERVICES: return jsonify({"success": False, "message": "无效的服务名称。"}), 400
    logs = get_service_logs(service_name)
    return jsonify({"success": True, "logs": logs})

@app.route('/api/system/audit_logs', methods=['GET'])
@login_required
def get_audit_logs_api():
    # FIX P8: 确保这个 API 返回审计日志
    logs = get_recent_audit_logs(20)
    return jsonify({"success": True, "logs": logs})

@app.route('/api/system/active_ips', methods=['GET'])
@login_required
def get_system_active_ips_api():
    """返回连接到 WSS/Stunnel 端口的所有外部客户端 IP 列表。"""
    ip_list = get_all_active_external_ips()
    if isinstance(ip_list, dict) and 'error' in ip_list:
        return jsonify({"success": False, "message": ip_list['error']}), 500
    
    return jsonify({"success": True, "active_ips": ip_list})

@app.route('/api/users/list', methods=['GET'])
@login_required
def get_users_list_api():
    users, _ = refresh_all_user_status(load_users())
    # 活跃连接数和模拟速度已在 sync_user_status 中计算并存入 user 对象
    save_users(users)
    return jsonify({"success": True, "users": users})

@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user_api():
    data = request.json
    username = data.get('username')
    password_raw = data.get('password')
    expiration_days = data.get('expiration_days', 365)
    quota_gb = data.get('quota_gb', 0)
    rate_kbps = data.get('rate_kbps', 0)
    
    if not username or not password_raw: return jsonify({"success": False, "message": "缺少用户名或密码"}), 400
    if not re.match(r'^[a-z0-9_]{3,16}$', username): return jsonify({"success": False, "message": "用户名格式不正确 (3-16位小写字母/数字/下划线)"}), 400
    
    try:
        quota = float(quota_gb)
        rate = int(rate_kbps)
    except ValueError: 
        return jsonify({"success": False, "message": "配额或速度限制值必须是数字"}), 400
        
    users = load_users()
    if get_user(username)[0]: return jsonify({"success": False, "message": f"用户组 {username} 已存在于面板"}), 409
    
    # 1. 创建系统用户
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success and "already exists" not in output:
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to create system user {username}: {output}")
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(['chpasswd'], input_data=chpasswd_input)
    if not success:
        safe_run_command(['userdel', '-r', username])
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    # 3. 设置有效期
    expiry_date = (date.today() + timedelta(days=int(expiration_days))).strftime('%Y-%m-%d')
    safe_run_command(['chage', '-E', expiry_date, username])
    
    uid = get_user_uid(username)
    if not uid:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": "无法获取用户UID"}), 500
        
    # 4. 添加到面板 DB
    new_user = {
        "username": username,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "active", 
        "expiration_date": expiry_date, 
        "quota_gb": quota, 
        "usage_gb": 0.0, 
        "rate_kbps": rate, 
        "active_connections": 0
    }
    users.append(new_user)
    save_users(users)
    
    # 5. 初始同步流量/速度规则
    manage_quota_iptables_rule(username, uid, 'add', quota * GIGA_BYTE)
    apply_rate_limit(uid, rate)
    
    log_action("USER_ADD_SUCCESS", session.get('username', 'root'), f"User {username} created, expiry: {expiry_date}, quota: {quota}GB, rate: {rate}KB/s")
    return jsonify({"success": True, "message": f"用户 {username} 创建成功，有效期至 {expiry_date}"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    data = request.json
    username = data.get('username')
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400
    users = load_users()
    user_to_delete, index = get_user(username)
    if not user_to_delete: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    
    uid = get_user_uid(username)
    if uid:
        # 清理系统资源
        kill_user_sessions(username)
        apply_rate_limit(uid, 0)
        manage_quota_iptables_rule(username, uid, 'delete')
        # 删除系统用户
        success, output = safe_run_command(['userdel', '-r', username])
        if not success and "user not found" not in output:
            log_action("USER_DELETE_WARNING", session.get('username', 'root'), f"System user {username} deletion failed (non-fatal): {output}")
    
    users.pop(index)
    save_users(users)
    log_action("USER_DELETE_SUCCESS", session.get('username', 'root'), f"Deleted user {username} and resources cleaned up.")
    return jsonify({"success": True, "message": f"用户组 {username} 已删除，会话已终止"})

@app.route('/api/users/status', methods=['POST'])
@login_required
def toggle_user_status_api():
    data = request.json
    username = data.get('username')
    action = data.get('action')
    user, index = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    users = load_users()
    
    old_status = users[index]['status']
    
    if action == 'enable':
        users[index]['status'] = 'active'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to ACTIVE")
    elif action == 'pause':
        users[index]['status'] = 'paused'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to PAUSED (Locked)")
    else: return jsonify({"success": False, "message": "无效的操作"}), 400
        
    # 如果状态被手动更改，则需要同步系统状态
    if old_status != users[index]['status']:
        users[index] = sync_user_status(users[index])
        save_users(users)
        kill_user_sessions(username)
    
    return jsonify({"success": True, "message": f"用户组 {username} 状态已更新为 {action}，连接已断开。"})

@app.route('/api/users/set_settings', methods=['POST'])
@login_required
def update_user_settings_api():
    data = request.json
    username = data.get('username')
    expiry_date = data.get('expiry_date', '')
    quota_gb = data.get('quota_gb')
    rate_kbps = data.get('rate_kbps')
    new_ssh_password = data.get('new_ssh_password', '')
    user, index = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    users = load_users()
    if not (quota_gb is not None and rate_kbps is not None): return jsonify({"success": False, "message": "缺少配额或速度限制值"}), 400
    
    try:
        quota = float(quota_gb)
        rate = int(rate_kbps)
        if expiry_date: datetime.strptime(expiry_date, '%Y-%m-%d')
    except ValueError: return jsonify({"success": False, "message": "日期/配额/速度格式不正确"}), 400
    
    uid = get_user_uid(username)
    if not uid: return jsonify({"success": False, "message": f"无法获取用户 {username} 的 UID"}), 500
    
    password_log = ""
    if new_ssh_password:
        chpasswd_input = f"{username}:{new_ssh_password}"
        success, output = safe_run_command(['chpasswd'], input_data=chpasswd_input)
        if success:
            password_log = ", SSH password changed. All sessions killed."
            kill_user_sessions(username)
        else:
            log_action("USER_PASS_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
            return jsonify({"success": False, "message": f"设置 SSH 密码失败: {output}"}), 500
            
    # 更新面板数据库
    users[index]['expiration_date'] = expiry_date
    users[index]['quota_gb'] = quota
    users[index]['rate_kbps'] = rate
    
    # 更新系统有效期
    safe_run_command(['chage', '-E', expiry_date, username])
    
    # 同步系统状态和规则
    users[index] = sync_user_status(users[index])
    
    # 重新应用配额和限速规则
    manage_quota_iptables_rule(username, uid, 'add', quota * GIGA_BYTE) # 强制更新配额规则
    apply_rate_limit(uid, rate) # 强制更新限速规则
    
    save_users(users)
    
    log_action("SETTINGS_UPDATE", session.get('username', 'root'),
                f"Updated {username}: Expiry {expiry_date}, Quota {quota}GB, Rate {rate}KB/s{password_log}")
    return jsonify({"success": True, "message": f"用户 {username} 设置已更新{password_log}"})
    
@app.route('/api/users/kill_all', methods=['POST'])
@login_required
def kill_all_user_sessions_api():
    data = request.json
    username = data.get('username')
    user, _ = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    kill_user_sessions(username)
    log_action("USER_KILL_SESSIONS", session.get('username', 'root'), f"Killed all sessions for user {username}")
    return jsonify({"success": True, "message": f"用户 {username} 的所有活跃连接已强制断开"})

@app.route('/api/users/reset_traffic', methods=['POST'])
@login_required
def reset_user_traffic_api():
    data = request.json
    username = data.get('username')
    user, _ = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    
    reset_iptables_counters(username)
    
    # 重新同步状态，让面板显示最新的 0 流量并解锁账户（如果被配额锁定）
    users = load_users()
    user, index = get_user(username) # 重新获取用户
    if user:
        users[index] = sync_user_status(user)
        save_users(users)
    
    log_action("USER_TRAFFIC_RESET", session.get('username', 'root'), f"Traffic counter for user {username} reset to 0.")
    return jsonify({"success": True, "message": f"用户 {username} 的流量计数器已重置，账户已重新激活。"})


@app.route('/api/users/ip_activity', methods=['GET'])
@login_required
def get_user_ip_activity_api():
    """获取用户的 SSHD 活跃会话 IP 列表（基于 PID 关联，但已简化）。"""
    username = request.args.get('username')
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400
    user, _ = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    
    session_info = get_user_active_sessions_info(username)
    
    return jsonify({"success": True, "session_info": session_info})


@app.route('/api/ips/ban_global', methods=['POST'])
@login_required
def ban_ip_global_api():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual Ban')
    if not ip: return jsonify({"success": False, "message": "缺少 IP"}), 400
    ip_bans = load_ip_bans()
    if 'global' not in ip_bans: ip_bans['global'] = {}
    ip_bans['global'][ip] = {'reason': reason, 'added_by': session.get('username', 'root'), 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    save_ip_bans(ip_bans)
    success_iptables, iptables_output = manage_ip_iptables(ip, 'block', BLOCK_CHAIN)
    if success_iptables:
        log_action("IP_BLOCK_GLOBAL_SUCCESS", session.get('username', 'root'), f"Globally blocked IP {ip}")
        return jsonify({"success": True, "message": f"IP {ip} 已被全局封禁 (实时生效)。"})
    else:
        log_action("IP_BLOCK_GLOBAL_WARNING", session.get('username', 'root'), f"Globally blocked IP {ip} in DB, but IPTables failed: {iptables_output}")
        return jsonify({"success": False, "message": f"IP {ip} 已被全局封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})

@app.route('/api/ips/unban_global', methods=['POST'])
@login_required
def unban_ip_global_api():
    data = request.json
    ip = data.get('ip')
    if not ip: return jsonify({"success": False, "message": "缺少 IP"}), 400
    ip_bans = load_ip_bans()
    if 'global' in ip_bans and ip in ip_bans['global']:
        ip_bans['global'].pop(ip)
        save_ip_bans(ip_bans)
    success_iptables, iptables_output = manage_ip_iptables(ip, 'unblock', BLOCK_CHAIN)
    if success_iptables:
        log_action("IP_UNBLOCK_GLOBAL_SUCCESS", session.get('username', 'root'), f"Globally unblocked IP {ip}")
        return jsonify({"success": True, "message": f"IP {ip} 已解除全局封禁 (实时生效)。"})
    else:
        log_action("IP_UNBLOCK_GLOBAL_WARNING", session.get('username', 'root'), f"Globally unblocked IP {ip} in DB, but IPTables failed: {iptables_output}")
        return jsonify({"success": False, "message": f"IP {ip} 已解除全局封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})

@app.route('/api/ips/global_list', methods=['GET'])
@login_required
def get_global_ban_list():
    ip_bans = load_ip_bans()
    return jsonify({"success": True, "global_bans": ip_bans.get('global', {})})

@app.route('/api/users/ip_debug', methods=['GET'])
@login_required
def get_ip_debug_info():
    """新增的调试 API，用于获取 ss -tanp 和 WSS 日志的原始信息。"""
    username = request.args.get('username')
    
    # 1. 获取 ss -tanp 原始输出
    success_ss, ss_output = safe_run_command(['ss', '-tanp'])

    # 2. 获取 WSS 日志 (最近 100 行)
    log_content = "Log file not found or failed to read."
    try:
        command_tail = ['tail', '-n', '100', WSS_LOG_FILE]
        success_tail, log_output = safe_run_command(command_tail)
        if success_tail:
            log_content = log_output
    except Exception as e:
        log_content = f"Error reading log: {str(e)}"
        
    return jsonify({
        "success": True,
        "username": username,
        "ss_output": ss_output,
        "wss_log_tail": log_content
    })


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # FIX (P3): 确保所有配置都是从环境中获取的
    os.environ['PANEL_DIR_ENV'] = PANEL_DIR
    os.environ['WSS_LOG_FILE_ENV'] = WSS_LOG_FILE
    os.environ['WSS_HTTP_PORT_ENV'] = WSS_HTTP_PORT
    os.environ['WSS_TLS_PORT_ENV'] = WSS_TLS_PORT
    os.environ['STUNNEL_PORT_ENV'] = STUNNEL_PORT
    os.environ['UDPGW_PORT_ENV'] = UDPGW_PORT
    os.environ['INTERNAL_FORWARD_PORT_ENV'] = INTERNAL_FORWARD_PORT
    os.environ['PANEL_PORT_ENV'] = PANEL_PORT
    
    print(f"WSS Panel running on port {PANEL_PORT}")
    try:
        app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
    except Exception as e:
        print(f"Flask App failed to run: {e}", file=sys.stderr)
        sys.exit(1)
