"""Entry point.

Local:   python app.py                       (http://127.0.0.1:5000)
Cloud:   gunicorn "app:app" --workers 1 --threads 4 --bind 0.0.0.0:$PORT
"""
import os

from dotenv import load_dotenv

load_dotenv()

from netwatch import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print(f"\n  Netwatch is running — open http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}\n")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
