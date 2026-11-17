"""
스마트기기 탐지기 - Flask 웹 서버
"""
from flask import Flask, render_template, jsonify, request
from scanner import scan_wifi, scan_bluetooth, scan_network, full_scan
import tv_controller

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

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


@app.route("/api/scan/wifi")
def api_wifi():
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


@app.route("/api/tv/command", methods=["POST"])
def api_tv_command():
    data = request.get_json(silent=True) or {}
    tv_ip = data.get("ip", "").strip()
    command = data.get("command", "KEY_CHUP")
    if not tv_ip:
        return jsonify({"success": False, "message": "TV IP 주소가 지정되지 않았습니다."}), 400
    res = tv_controller.send_samsung_tv_key(tv_ip, command)
    return jsonify(res)


if __name__ == "__main__":
    print("=" * 50)
    print("  스마트기기 탐지기 시작")
    print("  브라우저에서 http://localhost:5050 접속")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5050, debug=False)

