"""
스마트기기 탐지 스캐너 모듈
- WiFi 네트워크 스캔 (숨겨진 카메라 / IoT 기기 탐지)
- Bluetooth 기기 탐지
- 로컬 네트워크 기기 스캔
"""
import subprocess
import json
import re
import socket
import struct
import threading
from datetime import datetime

AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

# 의심스러운 카메라/감시기기 관련 키워드
SUSPICIOUS_KEYWORDS = [
    "cam", "camera", "spy", "hidden", "nano", "mini",
    "ipcam", "ipcamera", "wifi cam", "wifia", "eye",
    "reolink", "hikvision", "dahua", "amcrest", "yi-",
    "vstarcam", "foscam", "tp-link", "tapo", "eufy",
    "blink", "arlo", "ring", "nest", "wyze",
    "rcam", "nvr", "dvr", "cctv", "monitor",
    "espcam", "esp32", "esp8266", "tuya", "smartlife",
]

# 알려진 카메라/IoT 기기 제조사 MAC OUI 접두사 (앞 3바이트)
CAMERA_OUI = {
    "00:12:40": "Reolink",
    "7c:dd:90": "Reolink",
    "ec:71:db": "Reolink",
    "00:08:eb": "Hikvision",
    "44:19:b6": "Hikvision",
    "bc:ad:28": "Hikvision",
    "28:57:be": "Hikvision",
    "00:1a:c5": "Dahua",
    "3c:ef:8c": "Dahua",
    "98:ee:cb": "Dahua",
    "30:b4:9e": "Dahua",
    "60:a4:4c": "Foscam",
    "d4:e9:8a": "Foscam",
    "0c:ef:af": "Wyze",
    "2c:aa:8e": "Wyze",
    "d0:3f:27": "Wyze",
    "b4:a9:84": "Eufy",
    "88:71:e5": "Eufy",
    "58:ef:68": "Tapo (TP-Link)",
    "98:48:27": "Tapo (TP-Link)",
    "50:3e:aa": "Arlo",
    "08:9e:08": "Arlo",
    "18:b4:30": "Nest",
    "64:16:66": "Nest",
    "54:60:09": "Blink",
    "f4:f2:6d": "Blink",
    "7c:b7:33": "Tuya/Smartlife",
    "b4:e6:2d": "Tuya/Smartlife",
    "a4:7c:f9": "Tuya/Smartlife",
}

def _run(cmd, timeout=15):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""

def _risk_level(ssid, bssid, security=""):
    """기기의 위험도 판단"""
    score = 0
    reasons = []
    ssid_lower = ssid.lower()

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in ssid_lower:
            score += 3
            reasons.append(f"SSID에 '{kw}' 포함")
            break

    # 보안 없는 개방형 네트워크 (숨겨진 카메라는 종종 개방형)
    if security in ("NONE", "OPEN", ""):
        score += 2
        reasons.append("보안 없음 (개방형 네트워크)")

    # 숨겨진 SSID
    if not ssid or ssid == "":
        score += 1
        reasons.append("숨겨진 SSID")

    # MAC 주소로 제조사 확인
    if bssid:
        oui = bssid[:8].lower()
        for prefix, vendor in CAMERA_OUI.items():
            if oui == prefix.lower():
                score += 4
                reasons.append(f"카메라 제조사 ({vendor})")
                break

    if score >= 4:
        level = "HIGH"
    elif score >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    return level, reasons


def scan_wifi():
    """주변 WiFi 네트워크 스캔 (system_profiler 사용)"""
    output = _run(["system_profiler", "SPAirPortDataType", "-json"], timeout=20)
    networks = []

    if not output:
        return {"error": "WiFi 스캔 실패", "networks": []}

    try:
        data = json.loads(output)
        ifaces = data.get("SPAirPortDataType", [{}])[0].get("spairport_airport_interfaces", [])
    except Exception:
        return {"error": "WiFi 데이터 파싱 실패", "networks": []}

    for iface in ifaces:
        # 현재 연결된 네트워크
        current = iface.get("spairport_current_network_information", {})
        for ssid, info in current.items():
            if ssid == "_name":
                continue
            if isinstance(info, dict):
                networks.append(_parse_wifi_entry(ssid, info, connected=True))

        # 주변 WiFi 네트워크
        others = iface.get("spairport_airport_other_local_wireless_networks", [])
        for net in others:
            ssid = net.get("_name", "")
            networks.append(_parse_wifi_entry(ssid, net, connected=False))

    # 위험도 높은 순 정렬
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    networks.sort(key=lambda x: risk_order.get(x["risk"], 3))

    return {
        "networks": networks,
        "count": len(networks),
        "high_risk": sum(1 for n in networks if n["risk"] == "HIGH"),
        "scanned_at": datetime.now().strftime("%H:%M:%S"),
        "note": "macOS 개인정보 보호로 SSID가 가려질 수 있습니다",
    }


def _parse_wifi_entry(ssid, info, connected=False):
    channel = info.get("spairport_network_channel", "?")
    security_raw = info.get("spairport_security_mode", "")
    signal_noise = info.get("spairport_signal_noise", "")
    rssi = signal_noise.split("/")[0].strip().replace(" dBm", "") if signal_noise else "?"

    # 보안 모드 단순화
    if "none" in security_raw.lower() or security_raw == "":
        security = "NONE"
    elif "wpa3" in security_raw.lower():
        security = "WPA3"
    elif "wpa2" in security_raw.lower():
        security = "WPA2"
    elif "wpa" in security_raw.lower():
        security = "WPA"
    elif "wep" in security_raw.lower():
        security = "WEP"
    else:
        security = security_raw

    # macOS redacted SSID 처리
    display_ssid = ssid if ssid and ssid != "<redacted>" else "(SSID 보호됨)"

    risk, reasons = _risk_level(ssid, "", security)

    if connected:
        reasons.insert(0, "현재 연결된 네트워크")

    return {
        "ssid": display_ssid,
        "bssid": "숨김",
        "rssi": rssi,
        "channel": channel,
        "security": security,
        "vendor": "알 수 없음",
        "risk": risk,
        "reasons": reasons,
        "connected": connected,
    }


def scan_bluetooth():
    """Bluetooth 기기 스캔"""
    output = _run(["system_profiler", "SPBluetoothDataType", "-json"], timeout=10)
    devices = []

    try:
        data = json.loads(output)
        bt_data = data.get("SPBluetoothDataType", [{}])[0]
    except Exception:
        return {"error": "Bluetooth 스캔 실패", "devices": []}

    # 연결된 기기
    for section_key in ["device_connected", "device_not_connected", "devices_list"]:
        section = bt_data.get(section_key, {})
        if isinstance(section, list):
            for item in section:
                if isinstance(item, dict):
                    for name, info in item.items():
                        devices.append(_parse_bt_device(name, info))
        elif isinstance(section, dict):
            for name, info in section.items():
                devices.append(_parse_bt_device(name, info))

    return {
        "devices": devices,
        "count": len(devices),
        "scanned_at": datetime.now().strftime("%H:%M:%S"),
    }


def _parse_bt_device(name, info):
    if not isinstance(info, dict):
        info = {}
    address = info.get("device_address", info.get("Address", "알 수 없음"))
    minor_type = info.get("device_minorType", info.get("Minor Type", ""))
    vendor = info.get("device_vendorID", info.get("Vendor ID", ""))

    # 카메라/영상 기기 여부 체크
    suspicious = any(kw in name.lower() for kw in SUSPICIOUS_KEYWORDS)
    is_av_device = "video" in minor_type.lower() or "camera" in minor_type.lower()

    risk = "HIGH" if (suspicious or is_av_device) else "LOW"
    reasons = []
    if suspicious:
        reasons.append("기기명에 카메라 관련 키워드")
    if is_av_device:
        reasons.append(f"영상/카메라 기기 유형 ({minor_type})")

    return {
        "name": name,
        "address": address,
        "type": minor_type or "알 수 없음",
        "vendor": vendor,
        "risk": risk,
        "reasons": reasons,
    }


def scan_network():
    """로컬 네트워크 기기 스캔 (ARP 테이블)"""
    output = _run(["arp", "-a"])
    devices = []

    for line in output.split("\n"):
        # 형식: hostname (ip) at mac on interface
        match = re.match(r'(\S+)\s+\(([0-9.]+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\S+)', line, re.I)
        if not match:
            continue

        hostname, ip, mac, iface = match.groups()
        if mac in ("(incomplete)", "ff:ff:ff:ff:ff:ff"):
            continue

        # 멀티캐스트 주소 제외
        if ip.startswith("224.") or ip.startswith("239."):
            continue

        oui = mac[:8].lower()
        vendor = next((v for k, v in CAMERA_OUI.items() if oui == k.lower()), None)

        risk = "HIGH" if vendor else "LOW"
        reasons = [f"알려진 카메라 제조사 ({vendor})"] if vendor else []

        # 역방향 DNS
        try:
            hostname_resolved = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname_resolved = hostname if hostname != "?" else ip

        devices.append({
            "hostname": hostname_resolved,
            "ip": ip,
            "mac": mac,
            "interface": iface,
            "vendor": vendor or "알 수 없음",
            "risk": risk,
            "reasons": reasons,
        })

    return {
        "devices": devices,
        "count": len(devices),
        "scanned_at": datetime.now().strftime("%H:%M:%S"),
    }


def full_scan():
    """전체 스캔 실행"""
    results = {}
    errors = []

    def run_wifi():
        results["wifi"] = scan_wifi()

    def run_bt():
        results["bluetooth"] = scan_bluetooth()

    def run_net():
        results["network"] = scan_network()

    threads = [
        threading.Thread(target=run_wifi),
        threading.Thread(target=run_bt),
        threading.Thread(target=run_net),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    # 전체 위험 기기 수
    total_high = 0
    for key in ["wifi", "bluetooth", "network"]:
        data = results.get(key, {})
        items = data.get("networks") or data.get("devices") or []
        total_high += sum(1 for item in items if item.get("risk") == "HIGH")

    results["summary"] = {
        "total_high_risk": total_high,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return results
