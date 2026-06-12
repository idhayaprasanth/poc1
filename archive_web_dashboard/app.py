import socket

from security_dashboard.dashboard import app


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip


if __name__ == "__main__":
    port = 8050
    ip = get_local_ip()

    print("\nDashboard running on:")
    print(f"http://{ip}:{port}\n")

    app.run(host="0.0.0.0", port=port, debug=True)
