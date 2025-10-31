#!/usr/bin/python3
# -*- coding: utf-8 -*-
# WSS 隧道核心代理 (Python AsyncIO)
# 配置通过环境变量和命令行参数传递

import asyncio, ssl, sys
import os
import time
import json
import socket
import re
from datetime import datetime

# 尝试导入 uvloop, 如果没有安装则使用默认 asyncio
try:
    import uvloop
    UVLOOP_AVAILABLE = True
except ImportError:
    UVLOOP_AVAILABLE = False

# --- Python 脚本内部配置 (通过环境变量或命令行参数获取) ---

LISTEN_ADDR = '0.0.0.0'
# 从环境变量获取日志文件路径，用于流量关联
WSS_LOG_FILE = os.environ.get('WSS_LOG_FILE_ENV', '/var/log/wss.log')

# 从命令行参数获取端口 (ExecStart=/usr/bin/python3 /.../wss $WSS_HTTP_PORT $WSS_TLS_PORT $INTERNAL_FORWARD_PORT)
try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80
try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443
try:
    INTERNAL_FORWARD_PORT_PY = int(sys.argv[3])
except (IndexError, ValueError):
    INTERNAL_FORWARD_PORT_PY = 22 # 默认值

DEFAULT_TARGET = ('127.0.0.1', INTERNAL_FORWARD_PORT_PY)
BUFFER_SIZE = 65536
TIMEOUT = 86400  # 连接空闲超时 (24小时)
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

def log_connection(client_ip, client_port, local_port):
    """将连接信息记录到 WSS 日志文件，用于面板的 IP 关联。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [CONN_START] CLIENT_IP={client_ip} CLIENT_PORT={client_port} LOCAL_PORT={local_port}\n"
    try:
        with open(WSS_LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing WSS log: {e}", file=sys.stderr)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    client_ip = peer[0]
    client_port = peer[1]
    local_port = writer.get_extra_info('sockname')[1]
    
    forwarding_started = False
    full_request = b''

    try:
        # --- 1. 握手循环 ---
        while not forwarding_started:
            # 握手阶段的超时
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                break
            
            full_request += data
            
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index == -1:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue

            # 2. 头部解析
            headers_raw = full_request[:header_end_index]
            data_to_forward = full_request[header_end_index + 4:]
            headers = headers_raw.decode(errors='ignore')

            # 兼容 v2ray/Xray 等客户端的 GET-RAY 或 WebSocket 升级头
            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers
            
            # 3. 转发触发
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue
        
        # --- 退出握手循环 ---

        # 4. 连接目标服务器
        target = DEFAULT_TARGET
        target_reader, target_writer = await asyncio.open_connection(*target)

        # NEW LOGGING: 成功建立转发，记录连接信息
        log_connection(client_ip, client_port, local_port) 

        # 5. 转发初始数据
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        # 6. 转发后续数据流
        async def pipe(src_reader, dst_writer):
            try:
                while True:
                    # 数据转发阶段的超时
                    buf = await asyncio.wait_for(src_reader.read(BUFFER_SIZE), timeout=TIMEOUT)
                    if not buf:
                        break
                    dst_writer.write(buf)
                    await dst_writer.drain()
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass
            finally:
                dst_writer.close()

        await asyncio.gather(
            pipe(reader, target_writer),
            pipe(target_reader, writer)
        )

    except Exception as e:
        # print(f"Connection error {client_ip}: {e}", file=sys.stderr) # 过于频繁，改为静默
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # 初始化 TLS 服务器
    tls_task = asyncio.sleep(86400) # 默认禁用，如果证书存在则启用
    try:
        # 证书文件检查
        if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
            ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            tls_server = await asyncio.start_server(
                lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
            print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")
            tls_task = tls_server.serve_forever()
        else:
            print(f"WARNING: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
            
    except FileNotFoundError:
        # 实际加载证书时可能发生的错误
        print(f"WARNING: TLS server setup failed (File Not Found). Disabled.")
    except Exception as e:
        # 捕获其他 SSL 错误
        print(f"WARNING: TLS server setup failed: {e}. Disabled.")

        
    # HTTP 服务器 (始终尝试启动)
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)
    
    print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")

    async with http_server:
        await asyncio.gather(
            tls_task,
            http_server.serve_forever())

if __name__ == '__main__':
    try:
        if UVLOOP_AVAILABLE:
            uvloop.install()
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Proxy Stopped.")
    except Exception as e:
        # 打印启动失败的具体原因，供 systemd 捕获
        print(f"WSS Proxy startup failed: {e}", file=sys.stderr)
        sys.exit(1)
