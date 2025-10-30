#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import ssl
import sys
import os

# 尝试导入 uvloop 以获得更好的性能
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    print("[*] uvloop enabled")
except ImportError:
    print("[*] uvloop not available, using default asyncio loop")

# 从其他模块导入所需的功能
from shared_state import SETTINGS, EXECUTOR, save_usage_periodically, print, load_config, load_device_usage
from forwarder import handle_client
from panel import admin_interface

async def main():
    """主函数，负责初始化并启动所有服务。"""
    
    # 1. 加载配置
    load_config()
    load_device_usage()
    
    listen_addr = '0.0.0.0'
    http_port = SETTINGS.get("http_port", 80)
    tls_port = SETTINGS.get("tls_port", 443)
    status_port = SETTINGS.get("status_port", 9090)
    cert_file = SETTINGS.get("cert_file")
    key_file = SETTINGS.get("key_file")
    
    # --- 配置SSL上下文 ---
    ssl_ctx = None
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        try:
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        except Exception as e:
            print(f"[!] Warning: Could not load SSL context (Cert/Key: {cert_file}/{key_file}). TLS server disabled. Error: {e}")
            ssl_ctx = None
    else:
        print("[!] Warning: SSL cert_file or key_file not specified or not found. TLS server (WSS on 443) will be disabled.")

    servers = []
    
    try:
        # 1. 启动 WS (HTTP) 转发服务器
        ws_server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, tls=False),
            listen_addr, http_port
        )
        servers.append(ws_server)
        print(f"[*] WS Forwarder listening on {listen_addr}:{http_port}")

        # 2. 启动 HTTP 管理面板服务器
        panel_server = await asyncio.start_server(
            admin_interface,
            listen_addr, status_port
        )
        servers.append(panel_server)
        print(f"[*] HTTP Panel listening on {listen_addr}:{status_port}")

        # 3. 如果SSL配置成功，启动 WSS (TLS) 转发服务器
        if ssl_ctx:
            wss_server = await asyncio.start_server(
                lambda r, w: handle_client(r, w, tls=True),
                listen_addr, tls_port, ssl=ssl_ctx
            )
            servers.append(wss_server)
            print(f"[*] WSS Forwarder listening on {listen_addr}:{tls_port}")

    except OSError as e:
        print(f"[!] FATAL: Could not start server. Error: {e}")
        print("[!] Hint: If you see 'permission denied', try running with 'sudo' or use a port number > 1024.")
        return

    # --- 创建并运行所有后台任务 ---
    server_tasks = [asyncio.create_task(s.serve_forever()) for s in servers]
    background_tasks = [
        asyncio.create_task(save_usage_periodically())
    ]
    all_tasks = server_tasks + background_tasks
    
    try:
        await asyncio.gather(*all_tasks)
    finally:
        # 优雅地关闭
        EXECUTOR.shutdown(wait=False, cancel_futures=True)
        for task in all_tasks:
            task.cancel()
        await asyncio.gather(*all_tasks, return_exceptions=True)

if __name__ == "__main__":
    if os.geteuid() != 0 and (SETTINGS.get("http_port", 80) <= 1024 or SETTINGS.get("tls_port", 443) <= 1024):
        print("[!] Warning: Running without root privileges. Binding to ports 80/443 may fail.")
        print("[!] If startup fails, edit ws_config.json to use ports > 1024 or run with 'sudo'.")
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down servers...")
    except Exception as e:
        print(f"[!] Application failed: {e}")
        sys.exit(1)
