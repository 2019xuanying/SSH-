# shared_state.py
# -*- coding: utf-8 -*-

import asyncio
import json
import os
import sys
import time
import datetime
from collections import deque
import concurrent.futures
from typing import Dict, Any

# 尝试导入 psutil 用于系统监控
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    # 定义一个回退的 print 函数，以便在模块加载时打印警告
    _original_print_fallback = print
    _original_print_fallback("[!] Warning: 'psutil' library not found. System status monitoring will be disabled. Run 'pip3 install psutil' to enable it.")

# ================ 全局配置与变量 ================\

# --- 动态设置配置文件路径 ---
# 获取当前脚本 (shared_state.py) 所在的目录的绝对路径
_current_dir = os.path.dirname(os.path.abspath(__file__))
# 将配置文件路径设置为与脚本相同的目录，名为 ws_config.json
CONFIG_FILE = os.path.join(_current_dir, 'ws_config.json')
# --- 路径设置结束 ---


CONFIG: Dict[str, Any] = {}
SETTINGS: Dict[str, Any] = {}
ACTIVE_CONNS: Dict[str, Dict[str, Any]] = {}
DEVICE_USAGE: Dict[str, int] = {}
LOG_BUFFER = deque(maxlen=200)
START_TIME = time.time()
GLOBAL_BYTES_SENT = 0
GLOBAL_BYTES_RECEIVED = 0
# 确保在多线程环境中安全地执行阻塞操作
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4)

# --- 扩展print函数以捕获日志 ---
_original_print = print
def print(*args, **kwargs):
    """
    重写内置的 print 函数，以：
    1. 添加 UTC 时间戳。
    2. 将日志消息推送到 LOG_BUFFER 供面板使用。
    3. 调用原始的 print 函数。
    """
    try:
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        msg = f"[{timestamp}] " + " ".join(map(str, args))
        LOG_BUFFER.append(msg)
        _original_print(msg, **kwargs)
    except Exception:
        # 在极少数情况下（如启动/关闭期间），如果出错了，回退到原始 print
        _original_print(*args, **kwargs)

# 如果 psutil 不可用，在重写 print 后再次打印警告
if not PSUTIL_AVAILABLE:
    print("[!] Warning: 'psutil' not found. System status monitoring disabled.")


# ================ 配置管理 ================

def save_config_sync(config_data: dict):
    """同步保存配置（用于启动时）。"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] FATAL: Could not write config file {CONFIG_FILE}: {e}")

async def save_config_async():
    """异步保存当前配置（在执行器中）。"""
    global CONFIG
    loop = asyncio.get_running_loop()
    try:
        # 创建 CONFIG 的深拷贝以安全地传递给线程
        config_copy = copy.deepcopy(CONFIG)
        await loop.run_in_executor(EXECUTOR, save_config_sync, config_copy)
    except Exception as e:
        print(f"[!] Error saving config asynchronously: {e}")

def load_config():
    """
    在启动时加载配置。
    如果配置文件不存在，则创建默认配置。
    """
    global CONFIG, SETTINGS
    
    default_settings = {
        "http_port": 80,
        "tls_port": 443,
        "status_port": 9090, # 管理面板端口
        "default_target_host": "127.0.0.1",
        "default_target_port": 22, # 内部 SSH 端口
        "buffer_size": 8192,
        "timeout": 300, # 连接超时
        "cert_file": "/etc/stunnel/certs/stunnel.pem",
        "key_file": "/etc/stunnel/certs/stunnel.key",
        "ua_keyword_ws": "26.4.0",
        "ua_keyword_probe": "1.0",
        "allow_simultaneous_connections": False,
        "default_expiry_days": 30,
        "default_limit_gb": 100,
        "ip_whitelist": [],
        "ip_blacklist": [],
        "enable_ip_whitelist": False,
        "enable_ip_blacklist": False,
        "enable_device_id_auth": True # 默认启用设备ID认证
    }

    if not os.path.exists(CONFIG_FILE):
        print(f"[!] Config file {CONFIG_FILE} not found. Creating default config.")
        CONFIG = {"settings": default_settings, "accounts": {"admin": "admin"}, "device_ids": {}}
        save_config_sync(CONFIG)
    else:
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                CONFIG = json.load(f)
            # 确保所有默认设置都存在
            settings = CONFIG.setdefault('settings', {})
            for key, value in default_settings.items():
                settings.setdefault(key, value)
            CONFIG.setdefault('accounts', {"admin": "admin"})
            CONFIG.setdefault('device_ids', {})
        except (json.JSONDecodeError, TypeError) as e:
            print(f"[!] FATAL: Could not decode {CONFIG_FILE}: {e}. Please check its format.")
            sys.exit(1)
            
    SETTINGS = CONFIG.get('settings', {})

def load_device_usage():
    """从配置中加载设备流量使用情况。"""
    global DEVICE_USAGE
    DEVICE_USAGE = {did: info.get('used_bytes', 0) for did, info in CONFIG.get('device_ids', {}).items()}

async def save_usage_periodically():
    """每隔5秒周期性地将内存中的流量使用情况保存到配置中。"""
    while True:
        await asyncio.sleep(5)
        is_dirty = False
        # 创建副本以避免在迭代时发生大小变化
        current_usage = dict(DEVICE_USAGE)
        
        try:
            for device_id, used_bytes in current_usage.items():
                if device_id in CONFIG.get('device_ids', {}) and CONFIG['device_ids'][device_id].get('used_bytes') != used_bytes:
                    CONFIG['device_ids'][device_id]['used_bytes'] = used_bytes
                    is_dirty = True
            
            if is_dirty:
                await save_config_async()
                # print("[*] Periodically saved device usage to config.")
        except Exception as e:
            print(f"[!] Error in save_usage_periodically: {e}")
