"""
스마트기기 탐지기 - Flask 웹 서버
"""
from flask import Flask, render_template, jsonify, request
from scanner import scan_wifi, scan_bluetooth, scan_network, full_scan
import random
import time

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

# 시험 본부 & 고사실 인메모리 데이터베이스 (추후 SQLite DB로 승격 가능)
exam_store = {
    "current_exam": {
        "code": "EXAM-7892",
        "school": "한국고등학교",
        "title": "2026학년도 1학기 중간고사",
        "date": "2026-11-17",
        "status": "IN_PROGRESS"
    },
    "rooms": [
        {
            "id": "room-1",
            "name": "제 1고사실",
            "proctor": "김철수 교사",
            "students": 28,
            "total_seats": 30,
            "absent_seats": ["1-3", "4-5"],
            "detected_count": 0,
            "status": "NORMAL",
            "last_alert": None,
            "updated_at": "방금 전"
        },
        {
            "id": "room-2",
            "name": "제 2고사실",
            "proctor": "이영희 교사",
            "students": 29,
            "total_seats": 30,
            "absent_seats": ["3-2"],
            "detected_count": 1,
            "status": "WARNING",
            "last_alert": "미인가 BLE 무선 이어폰 신호 포착",
            "updated_at": "12초 전"
        },
        {
            "id": "room-3",
            "name": "제 3고사실 (현재 감독실)",
            "proctor": "박감독 교사",
            "students": 27,
            "total_seats": 30,
            "absent_seats": ["2-4", "5-1", "3-2"],
            "detected_count": 2,
            "status": "DANGER",
            "last_alert": "🚨 3행 2열 결시자 좌석에서 스마트폰 신호 포착!",
            "updated_at": "실시간 탐지 중"
        },
        {
            "id": "room-4",
            "name": "제 4고사실",
            "proctor": "정민우 교사",
            "students": 30,
            "total_seats": 30,
            "absent_seats": [],
            "detected_count": 0,
            "status": "NORMAL",
            "last_alert": None,
            "updated_at": "방금 전"
        },
        {
            "id": "room-5",
            "name": "제 5고사실",
            "proctor": "최지은 교사",
            "students": 26,
            "total_seats": 28,
            "absent_seats": ["2-1", "4-4"],
            "detected_count": 0,
            "status": "NORMAL",
            "last_alert": None,
            "updated_at": "방금 전"
        }
    ],
    "dispatches": [
        {
            "id": "disp-1",
            "room_name": "제 3고사실",
            "reason": "결시자 좌석 무선 신호 정밀 탐색 요청",
            "time": "14:22:10",
            "status": "출동 완료 (현장 조사 중)"
        }
    ]
}

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin")
def admin_page():
    return render_template("admin.html")


@app.route("/api/admin/overview")
def api_admin_overview():
    total_rooms = len(exam_store["rooms"])
    danger_rooms = sum(1 for r in exam_store["rooms"] if r["status"] == "DANGER")
    warning_rooms = sum(1 for r in exam_store["rooms"] if r["status"] == "WARNING")
    normal_rooms = sum(1 for r in exam_store["rooms"] if r["status"] == "NORMAL")
    total_detected = sum(r["detected_count"] for r in exam_store["rooms"])

    return jsonify({
        "exam": exam_store["current_exam"],
        "metrics": {
            "total_rooms": total_rooms,
            "danger_rooms": danger_rooms,
            "warning_rooms": warning_rooms,
            "normal_rooms": normal_rooms,
            "total_detected": total_detected
        },
        "rooms": exam_store["rooms"],
        "dispatches": exam_store["dispatches"]
    })


@app.route("/api/admin/exams/create", methods=["POST"])
def api_admin_create_exam():
    data = request.get_json() or {}
    school = data.get("school", "한국고등학교").strip()
    title = data.get("title", "2026학년도 정기 시험").strip()
    code = f"EXAM-{random.randint(1000, 9999)}"

    exam_store["current_exam"] = {
        "code": code,
        "school": school,
        "title": title,
        "date": time.strftime("%Y-%m-%d"),
        "status": "IN_PROGRESS"
    }
    return jsonify({"success": True, "exam": exam_store["current_exam"]})


@app.route("/api/admin/dispatch", methods=["POST"])
def api_admin_dispatch():
    data = request.get_json() or {}
    room_id = data.get("room_id")
    room = next((r for r in exam_store["rooms"] if r["id"] == room_id), None)
    if not room:
        return jsonify({"success": False, "error": "고사실을 찾을 수 없습니다."}), 404

    dispatch_entry = {
        "id": f"disp-{len(exam_store['dispatches']) + 1}",
        "room_name": room["name"],
        "reason": data.get("reason", "본부 긴급 순회 확인 요청"),
        "time": time.strftime("%H:%M:%S"),
        "status": "🚨 순회 감독관 출동 중"
    }
    exam_store["dispatches"].insert(0, dispatch_entry)
    return jsonify({"success": True, "dispatch": dispatch_entry})


@app.route("/api/scan/wifi")
def api_wifi():
    return jsonify(scan_wifi())
    return jsonify(scan_wifi())


@app.route("/api/scan/bluetooth")
def api_bluetooth():
    return jsonify(scan_bluetooth())


@app.route("/api/scan/network")
def api_network():
    return jsonify(scan_network())


@app.route("/api/scan/all")
def api_all():
    return jsonify(full_scan())


if __name__ == "__main__":
    print("=" * 50)
    print("  스마트기기 탐지기 시작")
    print("  브라우저에서 http://localhost:5050 접속")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5050, debug=False)

