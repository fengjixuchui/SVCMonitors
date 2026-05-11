#!/usr/bin/env python3
"""
SVC Monitor 实时事件流客户端
连接 SVCMonitors App 的 TCP Socket，获取实时事件流。
可作为 drain 的补充，提供持续监控能力。
"""

import socket
import json
import time
import sys
import argparse
from typing import Generator


def connect_svc_stream(host: str = "127.0.0.1", port: int = 8080,
                        last_seq: int = 0) -> Generator[dict, None, None]:
    """
    连接 SVC App TCP Socket，yield 实时事件。
    使用前需要先: adb forward tcp:8080 tcp:8080
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.settimeout(30)

    # 握手
    sock.sendall(b"PING\n")
    resp = sock.recv(1024).decode().strip()
    if resp != "PONG":
        raise RuntimeError(f"握手失败: {resp}")

    # HELLO 获取从 last_seq 开始的事件
    sock.sendall(f"HELLO {last_seq}\n".encode())

    buffer = ""
    while True:
        try:
            data = sock.recv(4096).decode()
            if not data:
                break
            buffer += data

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    yield event
                except json.JSONDecodeError:
                    # 非JSON行（如控制响应）
                    pass

        except socket.timeout:
            # 超时正常，继续等待
            continue
        except KeyboardInterrupt:
            break

    sock.close()


def collect_events(duration_sec: int = 5, host: str = "127.0.0.1",
                   port: int = 8080) -> list:
    """采集指定时长的事件"""
    events = []
    start = time.time()

    for event in connect_svc_stream(host, port):
        events.append(event)
        if time.time() - start >= duration_sec:
            break

    return events


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SVC事件流客户端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--duration", type=int, default=0, help="采集时长(秒), 0=持续")
    parser.add_argument("--output", "-o", help="输出文件路径")
    args = parser.parse_args()

    print(f"连接 {args.host}:{args.port}...")
    print("提示: 先执行 adb forward tcp:8080 tcp:8080")
    print("Ctrl+C 停止\n")

    events = []
    start = time.time()

    try:
        for event in connect_svc_stream(args.host, args.port):
            events.append(event)
            nr = event.get("nr", "?")
            name = event.get("name", "?")
            tid = event.get("pid", "?")
            comm = event.get("comm", "?")
            print(f"[{len(events):5d}] TID={tid} [{comm}] {name}({nr}) args=({event.get('a0','')},{event.get('a1','')},...)")

            if args.duration and time.time() - start >= args.duration:
                break

    except KeyboardInterrupt:
        print(f"\n\n停止，共采集 {len(events)} 个事件")

    if args.output and events:
        with open(args.output, 'w') as f:
            json.dump(events, f, indent=2, ensure_ascii=False)
        print(f"已保存到 {args.output}")
