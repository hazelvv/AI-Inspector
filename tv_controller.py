"""
AI-Inspector 능동형 스마트 TV 원격 제어 모듈 (Samsung Tizen / LG / UPnP)
- WebSocket (포트 8002 wss / 8001 ws) 기반 채널, 볼륨, 전원 제어
- 외부 라이브러리 없이 표준 라이브러리(socket, ssl, json, base64)만으로 구동
"""

import base64
import json
import os
import socket
import ssl
import time


def _create_ws_mask(data_bytes):
    """WebSocket 클라이언트 텍스트 프레임 생성 (RFC 6455 마스킹)"""
    length = len(data_bytes)
    mask_key = os.urandom(4)
    frame = bytearray([0x81])  # FIN=1, Opcode=0x1 (Text)

    if length <= 125:
        frame.append(0x80 | length)
    elif length <= 65535:
        frame.append(0x80 | 126)
        frame.extend(length.to_bytes(2, "big"))
    else:
        frame.append(0x80 | 127)
        frame.extend(length.to_bytes(8, "big"))

    frame.extend(mask_key)
    # Mask data
    masked_data = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(data_bytes))
    frame.extend(masked_data)
    return frame


def send_samsung_tv_key(tv_ip, key_code="KEY_CHUP", timeout=3.0):
    """
    삼성 스마트 TV로 리모컨 키 패킷 전송 (wss://8002 또는 ws://8001)
    - key_code: KEY_CHUP, KEY_CHDOWN, KEY_VOLUP, KEY_VOLDOWN, KEY_MUTE, KEY_POWER 등
    """
    app_name = base64.b64encode("AI-Inspector".encode("utf-8")).decode("utf-8")
    path = f"/api/v2/channels/samsung.remote.control?name={app_name}"

    payload = json.dumps({
        "method": "ms.remote.control",
        "params": {
            "Cmd": "Click",
            "DataOfCmd": key_code,
            "Option": "false",
            "TypeOfRemote": "SendRemoteKey"
        }
    }).encode("utf-8")

    ws_frame = _create_ws_mask(payload)

    # 포트 8002 (WSS 보안 웹소켓) 먼저 시도 후 8001 (WS) 시도
    for port, use_ssl in [(8002, True), (8001, False)]:
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=tv_ip)
            else:
                sock = raw_sock

            sock.connect((tv_ip, port))

            # WebSocket Handshake
            ws_key = base64.b64encode(os.urandom(16)).decode("utf-8")
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {tv_ip}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            sock.sendall(handshake.encode("utf-8"))

            # 응답 헤더 읽기
            response = sock.recv(1024)
            if b"101 Switching Protocols" in response:
                # 핸드셰이크 성공! 명령 프레임 전송
                sock.sendall(ws_frame)
                time.sleep(0.05)
                sock.close()
                return {
                    "success": True,
                    "ip": tv_ip,
                    "command": key_code,
                    "port": port,
                    "message": f"TV({tv_ip})로 '{key_code}' 제어 명령 전송 완료"
                }
            sock.close()
        except Exception as e:
            continue

    return {
        "success": False,
        "ip": tv_ip,
        "command": key_code,
        "message": f"TV({tv_ip}) 연결 응답 없음 (포트 8001/8002 미응답 또는 전원 대기 모드)"
    }
