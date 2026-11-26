"""Environment-driven configuration (NFR1: no secrets in source code)."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


def _bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def normalize_database_url(url):
    """Make a hosting provider's DATABASE_URL usable by SQLAlchemy with the driver we ship.

    Render/Heroku hand out ``postgres://`` or ``postgresql://`` URLs. SQLAlchemy would pick the
    psycopg2 driver for those, but Netwatch's cloud requirements install psycopg 3, so the driver is
    named explicitly. A URL that already names a driver (``postgresql+psycopg2://``) is left alone."""
    url = (url or "").strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def _database_url():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        return "sqlite:///" + str(INSTANCE_DIR / "netwatch.db")
    return normalize_database_url(url)


def _secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    # Persist a generated key in instance/ so sessions survive restarts
    # without the key ever living in the source tree.
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    key_file = INSTANCE_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


class Config:
    SECRET_KEY = _secret_key()
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Sessions / cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8  # 8 hours
    WTF_CSRF_TIME_LIMIT = None  # token valid for the life of the session

    # Monitoring
    SCHEDULER_ENABLED = _bool("SCHEDULER_ENABLED", True)
    SCHEDULER_TICK_SECONDS = int(os.environ.get("SCHEDULER_TICK_SECONDS", "10"))
    MONITOR_METHOD = os.environ.get("MONITOR_METHOD", "auto").lower()  # auto|icmp|tcp
    PING_COUNT = int(os.environ.get("PING_COUNT", "4"))
    PING_TIMEOUT_SECONDS = float(os.environ.get("PING_TIMEOUT_SECONDS", "2"))
    TCP_PROBE_PORTS = [int(p) for p in os.environ.get("TCP_PROBE_PORTS", "80,443,22").split(",") if p.strip()]
    MAX_PARALLEL_CHECKS = int(os.environ.get("MAX_PARALLEL_CHECKS", "8"))
    # On-site agents (private LAN devices). Inside a LAN, ICMP normally works, so agents use
    # ping first and fall back to TCP; the ports cover web, SSH, RDP, DNS and printer services.
    AGENT_MONITOR_METHOD = os.environ.get("AGENT_MONITOR_METHOD", "auto").lower()  # auto|icmp|tcp
    AGENT_TCP_PORTS = [int(p) for p in os.environ.get("AGENT_TCP_PORTS", "80,443,22,3389,53,9100").split(",")
                       if p.strip()]
    AGENT_POLL_SECONDS = int(os.environ.get("AGENT_POLL_SECONDS", "10"))

    # Email (SMTP) — all optional; alerts still appear in-app without them
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS = _bool("MAIL_USE_TLS", True)
    MAIL_USE_SSL = _bool("MAIL_USE_SSL", False)
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_FROM = os.environ.get("MAIL_FROM", "") or MAIL_USERNAME
    MAIL_TIMEOUT_SECONDS = float(os.environ.get("MAIL_TIMEOUT_SECONDS", "10"))

    DISPLAY_TIMEZONE = os.environ.get("DISPLAY_TIMEZONE", "Africa/Lagos")
    LOG_FILE = os.environ.get("LOG_FILE", str(INSTANCE_DIR / "netwatch.log"))
    APP_NAME = "Netwatch"

    # Login protection
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 5


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = True
    SCHEDULER_ENABLED = False
    PING_COUNT = 2
    PING_TIMEOUT_SECONDS = 1
    MAIL_SERVER = ""
    LOG_FILE = ""
