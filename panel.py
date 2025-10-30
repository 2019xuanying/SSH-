# panel.py
# -*- coding: utf-8 -*-

import asyncio
import base64
import json
import re
import shutil
import subprocess
import time
import datetime
import os
import sys
import copy
from typing import Tuple, List, Dict, Any

# 从共享模块导入所有需要的变量和函数
from shared_state import (
    ACTIVE_CONNS, DEVICE_USAGE, LOG_BUFFER, CONFIG, SETTINGS, EXECUTOR, START_TIME,
    GLOBAL_BYTES_SENT, GLOBAL_BYTES_RECEIVED, PSUTIL_AVAILABLE,
    save_config_async, print
)

# 仅在此文件中需要 psutil
if PSUTIL_AVAILABLE:
    import psutil

# ------------------ SSH 用户管理模块 (如果需要) ------------------
# 注意: 您的 Python 版本面板似乎是基于 DeviceID 的，
# 但如果您仍想通过面板管理 SSH 系统用户，请取消注释以下函数。
# 否则，您的面板将只管理 ws_config.json 中的 "device_ids"。

# def run_command(command: list) -> Tuple[bool, str]:
#     """执行系统命令并返回结果。"""
#     try:
#         result = subprocess.run(command, capture_output=True, text=True, check=True)
#         return True, result.stdout.strip()
#     except FileNotFoundError:
#         return False, f"命令未找到: {command[0]}"
#     except subprocess.CalledProcessError as e:
#         return False, f"命令执行失败: {command}\n错误: {e.stderr.strip()}"

# def manage_ssh_user(username: str, password: str = None, action: str = 'create') -> Tuple[bool, str]:
#     """管理SSH用户（创建/删除）。"""
#     if os.geteuid() != 0: return False, "此操作需要 root 权限。"
#     if not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', username): return False, "用户名格式无效。"
    
#     if action == 'create':
#         if not password: return False, "创建用户需要密码。"
#         # -m 创建家目录, -s /bin/false 禁用 shell
#         success, output = run_command(['useradd', '-m', '-s', '/bin/false', username])
#         if not success: return False, f"创建用户失败: {output}"
#         success, output = run_command(['chpasswd'], input_data=f"{username}:{password}")
#         if not success:
#             run_command(['userdel', '-r', username]) # 回滚
#             return False, f"设置密码失败: {output}"
#         return True, f"SSH 用户 {username} 创建成功。"
        
#     elif action == 'delete':
#         success, output = run_command(['userdel', '-r', username])
#         if not success: return False, f"删除用户 {username} 失败: {output}"
#         return True, f"SSH 用户 {username} 已删除。"
#     return False, "无效的操作。"


# ------------------ 辅助函数 ------------------
def format_bytes(b: int) -> str:
    """将字节转换为可读格式。"""
    if b < 1024: return f"{b} B"
    elif b < 1024**2: return f"{b/1024:.2f} KB"
    elif b < 1024**3: return f"{b/1024**2:.2f} MB"
    elif b < 1024**4: return f"{b/1024**3:.2f} GB"
    else: return f"{b/1024**4:.2f} TB"

def format_uptime(seconds: float) -> str:
    """将秒数转换为可读的运行时间。"""
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    return f"{int(d)}天 {int(h)}小时 {int(m)}分钟"

def get_system_status() -> Dict[str, Any]:
    """获取系统状态（非阻塞）。"""
    if not PSUTIL_AVAILABLE:
        return {
            "mem_used_gb": 0, "mem_total_gb": 0, "mem_percent": 0,
            "cpu_percent": 0, "cpu_cores": 0,
        }
    
    mem = psutil.virtual_memory()
    cpu_percent = psutil.cpu_percent()
    cpu_cores = psutil.cpu_count()
    return {
        "mem_used_gb": round(mem.used / (1024**3), 2),
        "mem_total_gb": round(mem.total / (1024**3), 2),
        "mem_percent": mem.percent,
        "cpu_percent": cpu_percent,
        "cpu_cores": cpu_cores
    }

async def get_system_status_async() -> Dict[str, Any]:
    """在执行器中异步运行 get_system_status。"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(EXECUTOR, get_system_status)

def check_auth(req_text: str) -> Tuple[bool, str]:
    """检查面板的 Basic Auth。"""
    auth_header = re.search(r'\nAuthorization: Basic ([^\r\n]+)', req_text, re.IGNORECASE)
    if not auth_header:
        return False, "Auth required"
    
    try:
        decoded = base64.b64decode(auth_header.group(1)).decode('utf-8')
        user, pwd = decoded.split(':', 1)
        
        accounts = CONFIG.get("accounts", {})
        if user in accounts and accounts[user] == pwd:
            return True, user
    except Exception as e:
        print(f"[!] Auth decode error: {e}")
        
    return False, "Invalid credentials"

# ------------------ API 处理器 ------------------

async def api_handler(path: str, method: str, data: dict, user: str) -> Tuple[int, dict]:
    """处理所有 /api/ 请求。"""
    
    # --- GET 请求 ---
    if method == 'GET':
        if path == '/api/status':
            sys_status = await get_system_status_async()
            active_list = list(ACTIVE_CONNS.values())
            return 200, {"success": True, "status": sys_status, "active_conns": active_list}
        
        if path == '/api/logs':
            return 200, {"success": True, "logs": list(LOG_BUFFER)}
        
        if path == '/api/settings':
            # 返回除 accounts 之外的所有配置
            current_config = copy.deepcopy(CONFIG)
            current_config.pop('accounts', None)
            return 200, {"success": True, "settings": current_config}
        
        if path == '/api/devices':
            return 200, {"success": True, "devices": CONFIG.get("device_ids", {})}
        
        if path == '/api/device_usage':
            return 200, {"success": True, "usage": DEVICE_USAGE}

    # --- POST 请求 ---
    if method == 'POST':
        # --- 设备管理 ---
        if path == '/api/devices/add':
            did = data.get('id')
            exp = data.get('expiry_days', SETTINGS.get('default_expiry_days', 30))
            lim = data.get('limit_gb', SETTINGS.get('default_limit_gb', 100))
            
            if not did or not re.match(r'^[\w-]{6,32}$', did):
                return 400, {"success": False, "message": "ID 无效 (6-32位字母/数字/_-)"}
            if did in CONFIG['device_ids']:
                return 409, {"success": False, "message": "ID 已存在"}
                
            expiry_date = (datetime.datetime.utcnow() + datetime.timedelta(days=int(exp))).strftime('%Y-%m-%d')
            CONFIG['device_ids'][did] = {
                "status": "active",
                "limit_gb": float(lim),
                "expiry_date": expiry_date,
                "used_bytes": 0,
                "created_at": datetime.datetime.utcnow().isoformat()
            }
            DEVICE_USAGE[did] = 0
            await save_config_async()
            return 200, {"success": True, "message": f"设备 {did} 已添加"}

        if path == '/api/devices/update':
            did = data.get('id')
            if not did or did not in CONFIG['device_ids']:
                return 404, {"success": False, "message": "未找到 ID"}
            
            if 'status' in data: CONFIG['device_ids'][did]['status'] = data['status']
            if 'limit_gb' in data: CONFIG['device_ids'][did]['limit_gb'] = float(data['limit_gb'])
            if 'expiry_date' in data: CONFIG['device_ids'][did]['expiry_date'] = data['expiry_date']
            
            # 如果重置流量
            if data.get('reset_usage') == True:
                CONFIG['device_ids'][did]['used_bytes'] = 0
                DEVICE_USAGE[did] = 0
                
            await save_config_async()
            return 200, {"success": True, "message": f"设备 {did} 已更新"}

        if path == '/api/devices/delete':
            did = data.get('id')
            if not did or did not in CONFIG['device_ids']:
                return 404, {"success": False, "message": "未找到 ID"}
            
            CONFIG['device_ids'].pop(did)
            DEVICE_USAGE.pop(did, None)
            
            # 踢出活跃连接
            kicked = 0
            for k, v in list(ACTIVE_CONNS.items()):
                if v.get('device_id') == did:
                    conn_to_kick = ACTIVE_CONNS.pop(k, None)
                    if conn_to_kick:
                        conn_to_kick['writer'].close() # 触发 pipe 终止
                        kicked += 1
                        
            await save_config_async()
            return 200, {"success": True, "message": f"设备 {did} 已删除 (踢出了 {kicked} 个连接)"}

        # --- 设置管理 ---
        if path == '/api/settings/update':
            new_settings = data.get('settings', {})
            CONFIG['settings'].update(new_settings)
            # 立即应用新设置
            SETTINGS.update(CONFIG['settings'])
            await save_config_async()
            return 200, {"success": True, "message": "设置已更新"}

        if path == '/api/settings/change_password':
            ou = data.get('old_user')
            op = data.get('old_pass')
            nu = data.get('new_user')
            np = data.get('new_pass')
            if not (ou and op and nu and np):
                return 400, {"success": False, "message": "所有字段均为必填项"}
            if CONFIG['accounts'].get(ou) != op:
                return 403, {"success": False, "message": "旧密码或用户名错误"}
            
            CONFIG['accounts'].pop(ou)
            CONFIG['accounts'][nu] = np
            await save_config_async()
            return 200, {"success": True, "message": "管理员密码已更改"}

        # --- 系统控制 ---
        if path == '/api/system/restart':
            print("[!] 面板请求重启...")
            await save_config_async() # 确保在重启前保存所有更改
            await asyncio.sleep(1.0)
            try:
                # 使用 sys.executable 和 sys.argv 重启进程
                os.execl(sys.executable, sys.executable, *sys.argv)
            except Exception as e:
                print(f"[!] 重启失败: {e}")
                return 500, {"success": False, "message": f"重启失败: {e}"}

    return 404, {"success": False, "message": "API 路径未找到"}

# ------------------ 主 HTTP 面板处理器 ------------------

async def admin_interface(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    处理 HTTP 面板请求 (API 或 HTML)。
    这是一个高性能的纯 asyncio HTTP 服务器。
    """
    code = 200
    resp_body = b'{"success": false, "message": "Internal Error"}'
    content_type = "application/json"
    
    try:
        req_text_bytes = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout=5.0)
        req_text = req_text_bytes.decode('latin-1')
        
        # 解析方法和路径
        first_line = req_text.split('\r\n', 1)[0]
        method, path, _ = first_line.split(' ', 2)
        
        # --- 认证 ---
        auth_ok, user = check_auth(req_text)
        if not auth_ok:
            writer.write(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="WSS Panel"\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            return

        # --- API 请求 ---
        if path.startswith('/api/'):
            data = {}
            if method == 'POST':
                content_len_match = re.search(r'\nContent-Length: (\d+)', req_text, re.IGNORECASE)
                if content_len_match:
                    content_len = int(content_len_match.group(1))
                    body_bytes = await asyncio.wait_for(reader.readexactly(content_len), timeout=5.0)
                    try:
                        data = json.loads(body_bytes)
                    except json.JSONDecodeError:
                        code = 400
                        resp_body = b'{"success": false, "message": "Invalid JSON body"}'
                        return # 提前返回
                
            # 将请求分派给 API 处理器
            code, resp_dict = await api_handler(path, method, data, user)
            resp_body = json.dumps(resp_dict).encode('utf-8')

        # --- HTML 页面请求 ---
        elif path == '/':
            content_type = "text/html;charset=utf-8"
            
            # 获取动态数据
            s_status = await get_system_status_async()
            mem_used_gb = s_status.get('mem_used_gb', 0)
            mem_total_gb = s_status.get('mem_total_gb', 0)
            mem_str = f"{mem_used_gb}G / {mem_total_gb}G"
            cpu_str = f"{s_status.get('cpu_percent', 0)}%"
            cpu_cores_str = f"{s_status.get('cpu_cores', 0)} Cores"
            uptime_str = format_uptime(time.time() - START_TIME)
            active_count = len(ACTIVE_CONNS)
            
            # (从 zip 文件中获取的 panel.py 包含一个巨大的 HTML 字符串)
            # (注意: 这是一个简化的示例，您 zip 中的 HTML 更复杂)
            html_template = f"""
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head><title>WSS Panel</title></head>
            <body>
                <h1>WSS Panel (Async)</h1>
                <p>用户: <strong>{user}</strong></p>
                <p>运行时间: {uptime_str}</p>
                <p>CPU: {cpu_str} ({cpu_cores_str}) | 内存: {mem_str}</p>
                <p>全局流量 (Sent/Rcvd): {format_bytes(GLOBAL_BYTES_SENT)} / {format_bytes(GLOBAL_BYTES_RECEIVED)}</p>
                <p>活跃连接: {active_count}</p>
                <div id="app">正在加载...</div>
                <script>
                    // 您的完整 JS 应用程序将在这里
                    console.log("面板已加载");
                </script>
            </body>
            </html>
            """
            resp_body = html_template.encode('utf-8')
            code = 200
        
        else:
            code = 404
            resp_body = b'{"success": false, "message": "Path Not Found"}'
            
    except asyncio.TimeoutError:
        code = 408
        resp_body = b'{"success": false, "message": "Request Timeout"}'
    except Exception as e:
        code = 500
        resp_body = json.dumps({"success": False, "message": f"Server Error: {type(e).__name__} - {e}"}).encode('utf-8')
        print(f"[!] 面板处理失败: {e}")
        
    finally:
        if not writer.is_closing():
            writer.write(f"HTTP/1.1 {code} \r\nContent-Type: {content_type}\r\nContent-Length: {len(resp_body)}\r\nConnection: close\r\n\r\n".encode() + resp_body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
