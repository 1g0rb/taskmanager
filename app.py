# app.py
from __future__ import annotations
import os
import calendar
from ipaddress import ip_address, ip_network
from uuid import uuid4
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta, time
from functools import wraps
import secrets
from sqlalchemy.exc import IntegrityError
from types import SimpleNamespace
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, Date, DateTime,
    ForeignKey, Text, text, select, case, or_, func, Table
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from werkzeug.exceptions import RequestEntityTooLarge
from PIL import Image, ImageOps, UnidentifiedImageError
import requests
from services.manager_dashboard import (
    build_manager_dashboard_data,
    build_manager_done_tasks_data,
    build_manager_reports_data,
    build_manager_tasks_list_data,
)
# ---------------- DB ----------------
DB_URL = os.environ.get("DATABASE_URL")
if not DB_URL:
    # local dev (Windows/Linux) -> db u projektu /data
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    os.makedirs(DATA_DIR, exist_ok=True)
    DB_PATH = os.path.join(DATA_DIR, "taskmanager.db")
    DB_URL = f"sqlite:///{DB_PATH.replace(os.sep,'/')}"


engine = create_engine(DB_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

TELEGRAM_BOT_TOKEN = os.environ.get(
    "TELEGRAM_BOT_TOKEN",
    ""
).strip()

TELEGRAM_ADMIN_CHAT_ID = os.environ.get(
    "TELEGRAM_ADMIN_CHAT_ID",
    "8603880940"
).strip()

TASKMANAGER_URL = "https://task.ordoapps.app/"
TASK_URL = TASKMANAGER_URL + "admin/tasks"
TASK_URL = TASKMANAGER_URL + "worker/dashboard"
WORKDAY_END_HOUR = 15

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)  # email
    password_hash = Column(String, nullable=False)

    display_name = Column(String, nullable=True)  # <-- novo (opcionalno)

    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)
    role = Column(String, default="worker")
    lang = Column(String, default="en")
    is_active = Column(Boolean, default=True)
    telegram_chat_id = Column(String, nullable=True)



class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    module = Column(String, nullable=False)  # horticulture/garden
    status = Column(String, default="open")  # open/in_progress/blocked/done
    carryover_from_task_id = Column(Integer, nullable=True)

    assigned_team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)

    task_date = Column(Date, default=date.today)
    next_action_date = Column(Date, nullable=True)
    is_todo = Column(Boolean, default=False, nullable=False)

    location_id = Column(Integer, ForeignKey("locations.id"), nullable=False)

    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)  # legacy

    notes = Column(String, nullable=True)
    blocked_reason = Column(String, nullable=True)
    blocked_until = Column(Date, nullable=True)
    blocked_at = Column(DateTime, nullable=True)

    blocked_location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)

    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)


class TaskAssignee(Base):
    __tablename__ = "task_assignees"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)


class TaskWorkSession(Base):
    __tablename__ = "task_work_sessions"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    started_at = Column(DateTime, nullable=False, index=True)
    finished_at = Column(DateTime, nullable=True)
    duration_minutes = Column(Integer, nullable=True)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Issue(Base):
    __tablename__ = "issues"

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    category = Column(String, default="equipment")   # equipment/material/irrigation/other
    severity = Column(String, default="low")         # low/medium/high
    status = Column(String, default="open")          # open/ack/in_progress/resolved

    module = Column(String, nullable=False)          # horticulture/garden
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)
    linked_task_id = Column(Integer, ForeignKey("tasks.id"), nullable=True)

    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    notes = Column(String, nullable=True)

    photos = relationship("IssuePhoto", backref="issue", lazy="select")


class Phase(Base):
    __tablename__ = "phases"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)


class Location(Base):
    __tablename__ = "locations"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    module = Column(String, nullable=False)   # horticulture/garden
    kind = Column(String, default="area")     # area/unit
    parent_id = Column(Integer, ForeignKey("locations.id"), nullable=True)

    phase_id = Column(Integer, ForeignKey("phases.id"), nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Location {self.name}>"


class ResidenceBlock(Base):
    __tablename__ = "residence_blocks"

    id = Column(Integer, primary_key=True)

    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)
    residence_id = Column(Integer, ForeignKey("locations.id"), nullable=False)

    reason = Column(String, nullable=False, default="guest")
    until_date = Column(Date, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class TaskPhoto(Base):
    __tablename__ = "task_photos"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class IssuePhoto(Base):
    __tablename__ = "issue_photos"

    id = Column(Integer, primary_key=True)
    issue_id = Column(Integer, ForeignKey("issues.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


observation_workers = Table(
    "observation_workers",
    Base.metadata,
    Column("observation_id", Integer, ForeignKey("observations.id"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class ObservationPhoto(Base):
    __tablename__ = "observation_photos"

    id = Column(Integer, primary_key=True)
    observation_id = Column(Integer, ForeignKey("observations.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Observation(Base):
    __tablename__ = "observations"

    id = Column(Integer, primary_key=True)
    note = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)

    photo_path = Column(String(255), nullable=True)

    module = Column(String(50), nullable=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)

    assigned_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    status = Column(String(20), nullable=False, default="new")  # new / seen / done
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    location = relationship("Location")
    assigned_user = relationship("User", foreign_keys=[assigned_user_id])
    assigned_users = relationship("User", secondary=observation_workers, lazy="select")
    created_by_user = relationship("User", foreign_keys=[created_by_user_id])
    photos = relationship("ObservationPhoto", backref="observation", lazy="select")


class UserActivity(Base):
    __tablename__ = "user_activity"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    user_email = Column(String, nullable=True, index=True)
    user_name = Column(String, nullable=True)
    path = Column(String, nullable=False)
    method = Column(String(10), nullable=False)
    activity_type = Column(String(20), nullable=False, default="view")
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "heic"}

def safe_next_url(default: str):
    nxt = (request.form.get("next") or "").strip()

    if not nxt:
        return default

    p = urlparse(nxt)

    if p.scheme or p.netloc:
        return default

    if not nxt.startswith("/"):
        return default

    return nxt

def allowed_image_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def normalize_static_file_path(path: str | None) -> str:
    normalized = (path or "").strip().replace("\\", "/")
    while normalized.startswith("/"):
        normalized = normalized[1:]
    if normalized.startswith("static/"):
        normalized = normalized[7:]
    return normalized


def save_task_photo_upload(
    task_id: int,
    upload,
    uploaded_by: int | None = None,
    *,
    convert_to_jpeg: bool = False,
) -> TaskPhoto:
    original_name = secure_filename(upload.filename or "")
    if not original_name:
        raise ValueError("Missing file name.")

    if not allowed_image_file(original_name):
        raise ValueError("Unsupported image format.")

    upload_dir = os.path.join(app.static_folder, "uploads", "tasks", str(task_id))
    os.makedirs(upload_dir, exist_ok=True)

    if convert_to_jpeg:
        unique_name = f"{uuid4().hex}.jpg"
    else:
        ext = original_name.rsplit(".", 1)[1].lower()
        unique_name = f"{uuid4().hex}.{ext}"

    abs_path = os.path.join(upload_dir, unique_name)

    if convert_to_jpeg:
        img = Image.open(upload)
        img = ImageOps.exif_transpose(img)

        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        elif img.mode != "RGB":
            img = img.convert("RGB")

        img.thumbnail((1600, 1600))
        img.save(abs_path, "JPEG", quality=82, optimize=True)
    else:
        upload.save(abs_path)

    rel_path = normalize_static_file_path(f"uploads/tasks/{task_id}/{unique_name}")
    return TaskPhoto(
        task_id=task_id,
        filename=original_name,
        file_path=rel_path,
        uploaded_by=uploaded_by,
    )


def save_observation_photo_upload(
    observation_id: int,
    upload,
    uploaded_by: int | None = None,
) -> ObservationPhoto:
    original_name = secure_filename(upload.filename or "")
    if not original_name:
        raise ValueError("Missing file name.")

    if not allowed_image_file(original_name):
        raise ValueError("Unsupported image format.")

    ext = original_name.rsplit(".", 1)[1].lower()
    unique_name = f"{uuid4().hex}.jpg"

    upload_dir = os.path.join(app.static_folder, "uploads", "observations")
    app.logger.info(
        "Observation photo save start observation_id=%s original_name=%s extension=%s content_type=%s content_length=%s upload_dir=%s",
        observation_id,
        original_name,
        ext,
        getattr(upload, "content_type", None),
        request.content_length,
        upload_dir,
    )
    os.makedirs(upload_dir, exist_ok=True)

    abs_path = os.path.join(upload_dir, unique_name)
    try:
        save_optimized_image(upload, abs_path, max_size=(1600, 1600), quality=82)
    except (UnidentifiedImageError, OSError) as exc:
        app.logger.warning(
            "Observation photo unsupported observation_id=%s filename=%s extension=%s content_type=%s error=%s",
            observation_id,
            original_name,
            ext,
            getattr(upload, "content_type", None),
            exc,
        )
        raise ValueError("Image format not supported. Please use JPG or PNG.") from exc
    app.logger.info(
        "Observation photo saved observation_id=%s filename=%s ext=%s abs_path=%s path_exists=%s",
        observation_id,
        original_name,
        ext,
        abs_path,
        os.path.exists(abs_path),
    )

    rel_path = normalize_static_file_path(f"uploads/observations/{unique_name}")
    return ObservationPhoto(
        observation_id=observation_id,
        filename=original_name,
        file_path=rel_path,
        uploaded_by=uploaded_by,
    )

def send_telegram_message(text, chat_id=None):
    token = (TELEGRAM_BOT_TOKEN or "").strip()
    chat_id = str(chat_id or TELEGRAM_ADMIN_CHAT_ID).strip()

    print("=== TELEGRAM SEND START ===")
    print("TEXT:", repr(text))
    print("CHAT_ID:", repr(chat_id))
    

    if not token:
        print("TELEGRAM ERROR: missing TELEGRAM_BOT_TOKEN")
        print("=== TELEGRAM SEND END ===")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    try:
        r = requests.post(
            url,
            json={
                "chat_id": chat_id,
                "text": text,
            },
            timeout=10,
        )

        print("TELEGRAM URL:", url)
        print("TELEGRAM STATUS:", r.status_code)
        print("TELEGRAM RESPONSE:", r.text)
        print("=== TELEGRAM SEND END ===")
        return r.ok

    except Exception as e:
        print("TELEGRAM SEND FAILED:", repr(e))
        print("=== TELEGRAM SEND END ===")
        return False


def send_user_telegram_message(user: User | None, text: str) -> bool:
    if not user:
        return False

    chat_id = (getattr(user, "telegram_chat_id", None) or "").strip()
    if not chat_id:
        print(f"TELEGRAM SKIP: user {getattr(user, 'username', '?')} has no telegram_chat_id")
        return False

    return send_telegram_message(text, chat_id=chat_id)

def test_telegram_bot_token():
    token = (TELEGRAM_BOT_TOKEN or "").strip()
    url = f"https://api.telegram.org/bot{token}/getMe"

    try:
        r = requests.get(url, timeout=10)
        print("TELEGRAM getMe STATUS:", r.status_code)
        print("TELEGRAM getMe RESPONSE:", r.text)
        return r.ok
    except Exception as e:
        print("TELEGRAM getMe FAILED:", repr(e))
        return False
def ensure_task_column_carryover():
    with engine.begin() as conn:
        cols = conn.execute(text("PRAGMA table_info(tasks)")).fetchall()
        names = {c[1] for c in cols}
        if "carryover_from_task_id" not in names:
            conn.execute(text("ALTER TABLE tasks ADD COLUMN carryover_from_task_id INTEGER"))
            print("✅ Added column: tasks.carryover_from_task_id")

def ensure_task_column_is_todo():
    with engine.begin() as conn:
        cols = conn.execute(text("PRAGMA table_info(tasks)")).fetchall()
        names = {c[1] for c in cols}
        if "is_todo" not in names:
            conn.execute(text("ALTER TABLE tasks ADD COLUMN is_todo BOOLEAN NOT NULL DEFAULT 0"))
            print("Added column: tasks.is_todo")

def ensure_user_column_display_name():
    with engine.begin() as conn:
        cols = conn.execute(text("PRAGMA table_info(users)")).fetchall()
        names = {c[1] for c in cols}
        if "display_name" not in names:
            conn.execute(text("ALTER TABLE users ADD COLUMN display_name VARCHAR"))
            print("✅ Added column: users.display_name")


def ensure_user_column_telegram_chat_id():
    with engine.begin() as conn:
        cols = conn.execute(text("PRAGMA table_info(users)")).fetchall()
        names = {c[1] for c in cols}
        if "telegram_chat_id" not in names:
            conn.execute(text("ALTER TABLE users ADD COLUMN telegram_chat_id VARCHAR"))
            print("✅ Added column: users.telegram_chat_id")

def ensure_observation_column_is_read():
    with engine.begin() as conn:
        tables = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='observations'")
        ).fetchall()
        if not tables:
            return

        cols = conn.execute(text("PRAGMA table_info(observations)")).fetchall()
        names = {c[1] for c in cols}
        if "is_read" not in names:
            conn.execute(text("ALTER TABLE observations ADD COLUMN is_read BOOLEAN NOT NULL DEFAULT 0"))
            print("Added column: observations.is_read")


def ensure_observation_schema():
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS observation_workers (
                observation_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (observation_id, user_id),
                FOREIGN KEY(observation_id) REFERENCES observations(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS observation_photos (
                id INTEGER NOT NULL PRIMARY KEY,
                observation_id INTEGER NOT NULL,
                filename VARCHAR NOT NULL,
                file_path VARCHAR NOT NULL,
                uploaded_by INTEGER,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(observation_id) REFERENCES observations(id),
                FOREIGN KEY(uploaded_by) REFERENCES users(id)
            )
        """))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_observation_photos_observation_id ON observation_photos (observation_id)"
        ))

        conn.execute(text("""
            INSERT OR IGNORE INTO observation_workers (observation_id, user_id)
            SELECT id, assigned_user_id
            FROM observations
            WHERE assigned_user_id IS NOT NULL
        """))
        conn.execute(text("""
            INSERT OR IGNORE INTO observation_photos (observation_id, filename, file_path, uploaded_by, created_at)
            SELECT
                id,
                substr(replace(photo_path, '\\', '/'), instr(replace(photo_path, '\\', '/'), '/observations/') + 14),
                CASE
                    WHEN photo_path LIKE '/static/%' THEN substr(photo_path, 9)
                    WHEN photo_path LIKE 'static/%' THEN substr(photo_path, 8)
                    ELSE replace(photo_path, '\\', '/')
                END,
                created_by_user_id,
                created_at
            FROM observations
            WHERE photo_path IS NOT NULL
              AND trim(photo_path) != ''
              AND NOT EXISTS (
                  SELECT 1
                  FROM observation_photos op
                  WHERE op.observation_id = observations.id
              )
        """))


def ensure_user_activity_schema():
    with engine.begin() as conn:
        tables = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='user_activity'")
        ).fetchall()
        if tables:
            cols = conn.execute(text("PRAGMA table_info(user_activity)")).fetchall()
            names = {c[1] for c in cols}
            if "activity_type" not in names:
                conn.execute(
                    text("ALTER TABLE user_activity ADD COLUMN activity_type VARCHAR(20) NOT NULL DEFAULT 'view'")
                )
                print("Added column: user_activity.activity_type")

        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_user_activity_user_id ON user_activity (user_id)")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_user_activity_created_at ON user_activity (created_at)")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_user_activity_user_email ON user_activity (user_email)")
        )


def ensure_task_work_session_schema():
    with engine.begin() as conn:
        tables = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='task_work_sessions'")
        ).fetchall()
        if tables:
            cols = conn.execute(text("PRAGMA table_info(task_work_sessions)")).fetchall()
            names = {c[1] for c in cols}
            if "status" not in names:
                conn.execute(
                    text("ALTER TABLE task_work_sessions ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active'")
                )
                print("Added column: task_work_sessions.status")
            if "duration_minutes" not in names:
                conn.execute(
                    text("ALTER TABLE task_work_sessions ADD COLUMN duration_minutes INTEGER")
                )
                print("Added column: task_work_sessions.duration_minutes")

        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_task_work_sessions_task_id ON task_work_sessions (task_id)")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_task_work_sessions_user_id ON task_work_sessions (user_id)")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_task_work_sessions_started_at ON task_work_sessions (started_at)")
        )

Base.metadata.create_all(engine)
ensure_task_column_carryover()
ensure_task_column_is_todo()
ensure_user_column_display_name()
ensure_user_column_telegram_chat_id()
ensure_observation_column_is_read()
ensure_observation_schema()
ensure_user_activity_schema()
ensure_task_work_session_schema()

# ---------------- App ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["MANAGER_HOST"] = (os.environ.get("MANAGER_HOST") or "manager.ordoapps.app").strip().lower()

# ---------------- Cloudflare Access auth ----------------
CF_EMAIL_HEADER = "Cf-Access-Authenticated-User-Email"
CF_NAME_HEADER  = "Cf-Access-Authenticated-User-Name"

# Admin emailovi (spusti na lower-case!)
ADMIN_EMAILS = {
    "bozicorama@gmail.com",
}
DEV_BYPASS = os.environ.get("DEV_BYPASS", "").lower() in ("1", "true", "yes")
DEV_LAN_BYPASS = os.environ.get("DEV_LAN_BYPASS", "").lower() in ("1", "true", "yes")
IGNORED_ACTIVITY_PATH_PREFIXES = ("/static/", "/cdn-cgi/")
IGNORED_ACTIVITY_PATHS = {"/favicon.ico", "/health"}


def redirect_back(default="admin_tasks"):
    return redirect(safe_next_url(url_for(default)))


def request_host_name() -> str:
    return (request.host.split(":", 1)[0] if request.host else "").strip().lower()


def is_admin_user(user: User | None) -> bool:
    if not user:
        return False
    return (getattr(user, "role", "") == "admin") or ((getattr(user, "username", "") or "").lower() in ADMIN_EMAILS)


def is_manager_user(user: User | None) -> bool:
    return bool(user and getattr(user, "role", "") == "manager")


def can_access_manager_dashboard(user: User | None) -> bool:
    return is_admin_user(user) or is_manager_user(user)


def can_access_worker_area(user: User | None) -> bool:
    return is_admin_user(user) or bool(user and getattr(user, "role", "") == "worker")


def is_manager_request() -> bool:
    manager_host = (app.config.get("MANAGER_HOST") or "").strip().lower()
    return bool(manager_host) and request_host_name() == manager_host


def get_task_ids_from_request() -> list[int]:
    raw_values = request.form.getlist("task_ids")
    task_ids: list[int] = []

    for raw in raw_values:
        for part in (raw or "").split(","):
            part = part.strip()
            if part.isdigit():
                task_ids.append(int(part))

    return task_ids


@app.context_processor
def inject_current_user():
    # cf_user postavljamo u cf_required/admin_required wrapperima
    u = getattr(request, "cf_user", None)

    if u:
        return {
            "current_user": SimpleNamespace(
                is_authenticated=True,
                id=u.id,
                username=u.username,
                role=u.role,
                lang=getattr(u, "lang", "en"),
            ),
            "dev_lan_bypass": DEV_LAN_BYPASS,
        }

    # kad nema auth (npr. /health ili 401 slučajevi)
    return {
        "current_user": SimpleNamespace(is_authenticated=False, role="worker", username=""),
        "dev_lan_bypass": DEV_LAN_BYPASS,
    }


@app.context_processor
def inject_template_helpers():
    return {
        "format_duration_minutes": format_duration_minutes,
    }

def _random_password_hash() -> str:
    return generate_password_hash(secrets.token_urlsafe(32))


def get_cf_email() -> str | None:
    email = request.headers.get(CF_EMAIL_HEADER)
    if not email:
        return None
    email = email.strip().lower()
    return email or None

def get_cf_name() -> str | None:
    name = request.headers.get(CF_NAME_HEADER)
    if not name:
        return None
    name = name.strip()
    return name or None


def get_request_ip() -> str | None:
    cf_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
    if cf_ip:
        return cf_ip

    forwarded_for = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded_for:
        first_ip = forwarded_for.split(",")[0].strip()
        if first_ip:
            return first_ip

    return request.remote_addr


def should_log_user_activity() -> bool:
    if request.method == "OPTIONS":
        return False

    path = request.path or ""
    if path in IGNORED_ACTIVITY_PATHS:
        return False

    if any(path.startswith(prefix) for prefix in IGNORED_ACTIVITY_PATH_PREFIXES):
        return False

    endpoint = request.endpoint or ""
    if endpoint in {"static", "health"}:
        return False

    return bool(endpoint)


def log_user_activity() -> None:
    if not should_log_user_activity():
        return

    user_email = get_cf_email()
    user_name = get_cf_name()

    if not user_email and not user_name:
        return

    db = SessionLocal()
    try:
        matched_user = None
        if user_email:
            matched_user = db.query(User).filter(User.username == user_email).first()

        activity = UserActivity(
            user_id=matched_user.id if matched_user else None,
            user_email=user_email,
            user_name=user_name or (matched_user.display_name if matched_user else None),
            path=request.path,
            method=request.method,
            activity_type="view" if request.method == "GET" else "action",
            ip_address=get_request_ip(),
        )
        db.add(activity)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

def get_current_user(db: Session) -> User | None:
    email = get_cf_email()
    if not email:
        return None

    user = db.query(User).filter(User.username == email).first()

    if not user:
        role = "admin" if email in {e.lower() for e in ADMIN_EMAILS} else "worker"
        name = get_cf_name()

        user = User(
            username=email,
            password_hash=_random_password_hash(),
            role=role,
            lang="en",
            is_active=True,
            display_name=name,
        )
        db.add(user)

        try:
            db.commit()
            db.refresh(user)
        except IntegrityError:
            # ako su 2 requesta došla odjednom prvi put
            db.rollback()
            user = db.query(User).filter(User.username == email).first()

    # update display_name ako prije nije bilo
    if user and not user.display_name:
        name = get_cf_name()
        if name:
            user.display_name = name
            db.commit()

    if not user or not user.is_active:
        return None

    # opcionalno: auto-promote ako je na allowlisti
    if user.username.lower() in ADMIN_EMAILS and user.role != "admin":
        user.role = "admin"
        db.commit()

    return user


@app.before_request
def track_user_activity():
    if not request.path.startswith("/static/"):
        db = SessionLocal()
        try:
            closed_sessions = auto_close_sessions(db)
            if closed_sessions:
                db.commit()
                print(f"Auto-closed {closed_sessions} work session(s) at end of day.")
            else:
                db.rollback()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    log_user_activity()


@app.before_request
def restrict_manager_host_surface():
    if not is_manager_request():
        return None

    if request.path.startswith("/static/"):
        return None

    allowed_endpoints = {
        "index",
        "manager_dashboard",
        "manager_reports",
        "manager_done_tasks",
        "manager_tasks",
        "manager_unfinished_tasks",
        "health",
        "logout",
        "static",
    }
    if (request.endpoint or "") in allowed_endpoints:
        return None

    abort(404)

def get_local_dev_user(db: Session) -> User:
    # probaj uzeti prvog aktivnog admina
    u = db.query(User).filter(User.role == "admin", User.is_active == True).first()
    if u:
        return u

    # ako nema admina, napravi lokalnog
    u = User(
        username="local@dev",
        password_hash=_random_password_hash(),
        role="admin",
        lang="en",
        is_active=True,
        display_name="Local Dev",
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def is_dev_auth_bypass_enabled() -> bool:
    flask_env = (os.environ.get("FLASK_ENV") or "").strip().lower()
    return bool(app.debug or DEV_BYPASS or flask_env == "development")


def can_use_dev_auth_bypass() -> bool:
    # Only use fallback auth when Cloudflare headers are absent.
    if get_cf_email():
        return False

    if not is_dev_auth_bypass_enabled():
        return False

    # Safe default: localhost only.
    if is_local_request():
        return True

    # Optional LAN bypass remains opt-in and unchanged.
    return DEV_LAN_BYPASS and is_private_network_request()


def get_current_user_or_dev(db: Session) -> User | None:
    # normalno: Cloudflare Access user
    user = get_current_user(db)
    if user:
        return user

    # local dev override: ?as_user=email@domain.com
    if can_use_dev_auth_bypass():
        as_user = (request.args.get("as_user") or request.form.get("as_user") or "").strip().lower()
        if as_user:
            u = db.query(User).filter(User.username == as_user, User.is_active == True).first()
            if u:
                return u

        return get_local_dev_user(db)

    return None



def cf_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        db = SessionLocal()
        try:
            user = get_current_user_or_dev(db)
            if not user:
                return redirect("/cdn-cgi/access/login")
            if request.path.startswith("/worker") and not can_access_worker_area(user):
                abort(403)

            request.cf_user = user  # type: ignore[attr-defined]
            return fn(*args, **kwargs)
        finally:
            db.close()
    return wrapper



def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        db = SessionLocal()
        try:
            user = user = get_current_user_or_dev(db)
            if not user:
                abort(401)
            if not is_admin_user(user):
                flash("Admin access required.")
                return redirect(url_for("index"))
            request.cf_user = user  # type: ignore[attr-defined]
            return fn(*args, **kwargs)
        finally:
            db.close()
    return wrapper


def manager_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        db = SessionLocal()
        try:
            user = get_current_user_or_dev(db)
            if not user:
                return redirect("/cdn-cgi/access/login")
            if not can_access_manager_dashboard(user):
                abort(403)
            request.cf_user = user  # type: ignore[attr-defined]
            return fn(*args, **kwargs)
        finally:
            db.close()
    return wrapper


# ---------------- Seeds ----------------
def ensure_admin_seed():
    if not app.debug:
        return  # u produkciji ne seedamo ništa

    db = SessionLocal()
    try:
        exists = db.query(User).first()
        if not exists:
            u = User(
                username="admin@example.com",
                password_hash=_random_password_hash(),
                role="admin",
                lang="en",
                is_active=True
            )
            db.add(u)
            db.commit()
            print("Seeded default admin for DEV only: admin@example.com")
    finally:
        db.close()



def ensure_team_seed():
    db = SessionLocal()
    try:
        names = {"Team A", "Team B"}
        existing = {t.name for t in db.query(Team).all()}
        for n in names - existing:
            db.add(Team(name=n, is_active=True))
        db.commit()
    finally:
        db.close()


def ensure_location_seed():
    defaults = [
        ("Phase 1", "horticulture"),
        ("Phase 2", "horticulture"),
        ("Phase 3", "horticulture"),
        ("Phase 4", "horticulture"),
        ("Winery", "horticulture"),
        ("Tasting room", "horticulture"),
        ("Golf", "horticulture"),
        ("Tennis", "horticulture"),
        ("Beach bar", "horticulture"),
        ("Woodland / buffer", "horticulture"),
        ("Garden - Greenhouse", "garden"),
        ("Garden - Beds", "garden"),
        ("Garden - Nursery", "garden"),
        ("Garden - Perimeter", "garden"),
    ]

    db = SessionLocal()
    try:
        existing = {(l.name, l.module) for l in db.query(Location).all()}
        added = 0
        for name, module in defaults:
            if (name, module) not in existing:
                db.add(Location(name=name, module=module, is_active=True))
                added += 1
        if added:
            db.commit()
            print(f"Seeded locations: {added}")
    finally:
        db.close()


def ensure_residences_seed():
    db = SessionLocal()
    try:
        phase2 = db.query(Location).filter(
            Location.name == "Phase 2",
            Location.kind == "area"
        ).first()

        if not phase2:
            print("WARN: Phase 2 not found (locations). Cannot seed residences.")
            return

        wanted = [f"R{i}" for i in range(26, 41)]
        existing = set(
            r.name for r in db.query(Location).filter(
                Location.kind == "unit",
                Location.parent_id == phase2.id
            ).all()
        )

        added = 0
        for name in wanted:
            if name not in existing:
                db.add(Location(
                    name=name,
                    module="horticulture",
                    kind="unit",
                    parent_id=phase2.id,
                    is_active=True
                ))
                added += 1

        if added:
            db.commit()
            print(f"Seeded residences for Phase 2: {added}")
    finally:
        db.close()


ensure_admin_seed()
ensure_team_seed()
ensure_location_seed()
ensure_residences_seed()

# ---------------- Helpers ----------------
def parse_module_arg() -> tuple[str, str | None]:
    module = (request.args.get("module") or "all").lower()
    if module in ("horticulture", "garden"):
        return module, module
    return "all", None


def get_task_schedule_date(task: Task) -> date | None:
    if getattr(task, "is_todo", False):
        return None
    return task.task_date or task.next_action_date


def build_task_notification_text(task: Task, label: str, location_name: str | None = None) -> str:
    schedule_date = get_task_schedule_date(task)
    schedule_text = schedule_date.isoformat() if schedule_date else "unscheduled"
    location_text = f"\nLocation: {location_name}" if location_name else ""
    return (
        f"📌 Task {label}\n"
        f"{task.title}\n"
        f"Date: {schedule_text}{location_text}\n"
        f"{TASKMANAGER_URL}worker/dashboard"
    )


def notify_task_users(db: Session, task: Task, user_ids: list[int], label: str) -> None:
    schedule_date = get_task_schedule_date(task)
    if not schedule_date:
        return

    today = date.today()
    if schedule_date < today:
        return

    users = db.query(User).filter(User.id.in_(user_ids), User.is_active == True).all() if user_ids else []
    location = db.get(Location, task.location_id) if task.location_id else None
    location_name = location.name if location else None

    for user in users:
        send_user_telegram_message(
            user,
            build_task_notification_text(task, label=label, location_name=location_name)
        )


def notify_task_assignees(db: Session, task: Task, label: str) -> None:
    assignee_ids = [
        row.user_id
        for row in db.query(TaskAssignee).filter(TaskAssignee.task_id == task.id).all()
    ]
    notify_task_users(db, task, assignee_ids, label=label)


def load_worker_task_groups(db: Session, user: User, module_filter: str | None, today: date, until: date):
    query = db.query(Task).filter(Task.status != "done", Task.is_todo == False)
    if module_filter:
        query = query.filter(Task.module == module_filter)
    query = filter_my_and_unassigned(db, query, user)

    status_order = {"in_progress": 0, "open": 1, "blocked": 2}

    def sort_key(task: Task):
        schedule_date = get_task_schedule_date(task) or date.max
        return (
            schedule_date,
            status_order.get(task.status or "open", 3),
            -(task.id or 0),
        )

    all_tasks = sorted(query.all(), key=sort_key)

    overdue_tasks = []
    today_tasks = []
    upcoming_tasks = []

    for task in all_tasks:
        schedule_date = get_task_schedule_date(task)
        if not schedule_date:
            continue
        if schedule_date < today:
            overdue_tasks.append(task)
        elif schedule_date == today:
            today_tasks.append(task)
        elif schedule_date <= until:
            upcoming_tasks.append(task)

    return overdue_tasks, today_tasks, upcoming_tasks


def filter_my_and_unassigned(db, query, user: User):
    if user.role == "admin" or user.username.lower() in ADMIN_EMAILS:
        return query

    return (
        query
        .outerjoin(TaskAssignee, TaskAssignee.task_id == Task.id)
        .filter(
            or_(
                TaskAssignee.user_id == user.id,
                TaskAssignee.task_id.is_(None)
            )
        )
        .distinct()
    )


def pick_worker_priority_task(today_tasks, overdue_tasks, upcoming_tasks, assigned_task_ids: set[int]):
    def first_assigned(tasks):
        for task in tasks:
            if task.id in assigned_task_ids:
                return task
        return None

    return (
        first_assigned(today_tasks)
        or (today_tasks[0] if today_tasks else None)
        or first_assigned(overdue_tasks)
        or (overdue_tasks[0] if overdue_tasks else None)
        or first_assigned(upcoming_tasks)
        or (upcoming_tasks[0] if upcoming_tasks else None)
    )


def is_task_allowed_for_worker(db, task: Task, user: User) -> bool:
    if getattr(task, "is_todo", False):
        return False
    if not can_access_worker_area(user):
        return False
    if is_admin_user(user):
        return True

    rows = db.query(TaskAssignee).filter(TaskAssignee.task_id == task.id).all()
    if not rows:
        return True
    return any(r.user_id == user.id for r in rows)


def copy_assignees(db, src_task_id: int, dst_task_id: int) -> None:
    rows = db.query(TaskAssignee).filter(TaskAssignee.task_id == src_task_id).all()
    for r in rows:
        db.add(TaskAssignee(task_id=dst_task_id, user_id=r.user_id))

def is_local_request() -> bool:
    """
    True only for direct localhost requests in development.
    """
    ra = request.remote_addr or ""

    try:
        ip = ip_address(ra)
    except ValueError:
        return False

    return ip.is_loopback

def is_private_network_request() -> bool:
    ra = request.remote_addr or ""

    try:
        ip = ip_address(ra)
    except ValueError:
        return False

    if ip.is_loopback:
        return False

    private_nets = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
    ]
    return any(ip in n for n in private_nets)

def save_optimized_image(file_storage, abs_path: str, max_size=(1600, 1600), quality=82):
    img = Image.open(file_storage)

    # Ispravi rotaciju s mobitela
    img = ImageOps.exif_transpose(img)

    # Neki formati imaju alpha kanal pa ih pretvori u RGB za JPEG
    if img.mode in ("RGBA", "P"):
        img = img.convert("RGB")
    elif img.mode != "RGB":
        img = img.convert("RGB")

    # Smanji proporcionalno
    img.thumbnail(max_size)

    # Spremi optimizirano
    img.save(abs_path, format="JPEG", quality=quality, optimize=True)

@app.route("/test-telegram")
@admin_required
def test_telegram():
    token_ok = test_telegram_bot_token()
    sent_ok = send_telegram_message(
        f"✅ Test poruka iz TaskManagera.\n{TASKMANAGER_URL}"
    )
    return f"Token OK: {token_ok} | Telegram sent: {sent_ok}"

def get_worker_unread_observation_count(db: Session, user_id: int) -> int:
    return (
        db.query(Observation)
        .filter(
            or_(
                Observation.assigned_user_id == user_id,
                Observation.assigned_users.any(User.id == user_id),
            ),
            Observation.is_read == False,
        )
        .count()
    )

def get_current_db_user(db: Session):
    user = getattr(request, "cf_user", None)
    if not user:
        return None

    email = (
        getattr(user, "email", None)
        or getattr(user, "username", None)
        or getattr(user, "sub", None)
    )

    if not email:
        return None

    return db.query(User).filter(User.username == email).first()


def format_duration_minutes(minutes: int | None) -> str:
    if minutes is None:
        return "In progress"

    total_minutes = max(int(minutes), 0)
    if total_minutes < 60:
        return f"{total_minutes} min"

    hours, rem = divmod(total_minutes, 60)
    if rem == 0:
        return f"{hours} h"
    return f"{hours} h {rem} min"


def _duration_minutes_between(started_at: datetime, finished_at: datetime) -> int:
    delta = finished_at - started_at
    return max(int(delta.total_seconds() // 60), 0)


def _utc_naive_to_local(value: datetime) -> datetime:
    return datetime.fromtimestamp(calendar.timegm(value.timetuple()))


def _local_workday_end_to_utc_naive(local_day: date) -> datetime:
    local_cutoff = datetime.combine(local_day, time(hour=WORKDAY_END_HOUR))
    return datetime.utcfromtimestamp(local_cutoff.timestamp())


def auto_close_sessions(db: Session, now: datetime | None = None) -> int:
    current_time = now or datetime.utcnow()
    active_sessions = (
        db.query(TaskWorkSession)
        .filter(
            TaskWorkSession.status == "active",
            TaskWorkSession.finished_at.is_(None),
        )
        .all()
    )

    closed_sessions = 0
    for session in active_sessions:
        session_local_started_at = _utc_naive_to_local(session.started_at)
        session_cutoff = _local_workday_end_to_utc_naive(session_local_started_at.date())
        if current_time < session_cutoff:
            continue

        finished_at = max(session.started_at, session_cutoff)
        finish_work_session(session, finished_at)
        closed_sessions += 1

    return closed_sessions


def finish_work_session(session: TaskWorkSession, finished_at: datetime | None = None) -> TaskWorkSession:
    finished_value = finished_at or datetime.utcnow()
    session.finished_at = finished_value
    session.duration_minutes = _duration_minutes_between(session.started_at, finished_value)
    session.status = "done"
    return session


def get_active_task_work_session(
    db: Session,
    task_id: int,
    user_id: int,
) -> TaskWorkSession | None:
    return (
        db.query(TaskWorkSession)
        .filter(
            TaskWorkSession.task_id == task_id,
            TaskWorkSession.user_id == user_id,
            TaskWorkSession.status == "active",
            TaskWorkSession.finished_at.is_(None),
        )
        .order_by(TaskWorkSession.started_at.desc(), TaskWorkSession.id.desc())
        .first()
    )


def start_task_work_session(db: Session, task_id: int, user_id: int, started_at: datetime | None = None):
    now = started_at or datetime.utcnow()

    active_same_task = get_active_task_work_session(db, task_id, user_id)
    if active_same_task:
        return active_same_task, False

    session = TaskWorkSession(
        task_id=task_id,
        user_id=user_id,
        started_at=now,
        status="active",
    )
    db.add(session)
    return session, True


def finish_task_work_session(
    db: Session,
    task_id: int,
    user_id: int,
    finished_at: datetime | None = None,
    create_fallback: bool = True,
):
    now = finished_at or datetime.utcnow()
    active_session = get_active_task_work_session(db, task_id, user_id)
    if active_session:
        return finish_work_session(active_session, now), False

    if not create_fallback:
        return None, False

    fallback_session = TaskWorkSession(
        task_id=task_id,
        user_id=user_id,
        started_at=now,
        finished_at=now,
        duration_minutes=0,
        status="done",
    )
    db.add(fallback_session)
    return fallback_session, True


def get_worker_task_finish_validation_error(
    task: Task,
    as_of: datetime | None = None,
) -> str | None:
    now = as_of or datetime.utcnow()
    task_status = (task.status or "open")
    if task_status == "blocked":
        return "Task needs to be restarted after being blocked."
    if task_status != "in_progress" or not task.started_at:
        return "Task must be started before finishing."

    active_task_minutes = _duration_minutes_between(task.started_at, now)
    if active_task_minutes < 1:
        return "You can't finish a task with less than 1 minute worked."

    return None


def finish_active_sessions_for_tasks(db: Session, task_ids: list[int], finished_at: datetime | None = None) -> int:
    if not task_ids:
        return 0

    now = finished_at or datetime.utcnow()
    active_sessions = (
        db.query(TaskWorkSession)
        .filter(
            TaskWorkSession.task_id.in_(task_ids),
            TaskWorkSession.status == "active",
            TaskWorkSession.finished_at.is_(None),
        )
        .all()
    )
    for session in active_sessions:
        finish_work_session(session, now)
    return len(active_sessions)


def build_task_work_session_data(db: Session, task_ids: list[int]):
    sessions_by_task_id: dict[int, list[TaskWorkSession]] = {}
    summary_by_task_id: dict[int, dict[str, object]] = {}
    active_session_by_task_id: dict[int, list[TaskWorkSession]] = {}
    active_session_by_task_user: dict[tuple[int, int], TaskWorkSession] = {}

    if not task_ids:
        return sessions_by_task_id, summary_by_task_id, active_session_by_task_id, active_session_by_task_user

    rows = (
        db.query(TaskWorkSession)
        .filter(TaskWorkSession.task_id.in_(task_ids))
        .order_by(TaskWorkSession.started_at.desc(), TaskWorkSession.id.desc())
        .all()
    )

    for task_id in task_ids:
        summary_by_task_id[task_id] = {
            "total_sessions": 0,
            "total_duration_minutes": 0,
            "worker_count": 0,
            "first_start": None,
            "last_finish": None,
            "active_count": 0,
        }

    worker_sets: dict[int, set[int]] = {task_id: set() for task_id in task_ids}

    for row in rows:
        sessions_by_task_id.setdefault(row.task_id, []).append(row)
        summary = summary_by_task_id.setdefault(row.task_id, {
            "total_sessions": 0,
            "total_duration_minutes": 0,
            "worker_count": 0,
            "first_start": None,
            "last_finish": None,
            "active_count": 0,
        })

        summary["total_sessions"] += 1
        if row.duration_minutes is not None:
            summary["total_duration_minutes"] += row.duration_minutes

        current_first_start = summary["first_start"]
        if current_first_start is None or row.started_at < current_first_start:
            summary["first_start"] = row.started_at

        if row.finished_at:
            current_last_finish = summary["last_finish"]
            if current_last_finish is None or row.finished_at > current_last_finish:
                summary["last_finish"] = row.finished_at

        worker_sets.setdefault(row.task_id, set()).add(row.user_id)

        if row.status == "active" and row.finished_at is None:
            summary["active_count"] += 1
            active_session_by_task_id.setdefault(row.task_id, []).append(row)
            active_session_by_task_user[(row.task_id, row.user_id)] = row

    for task_id, workers in worker_sets.items():
        summary_by_task_id[task_id]["worker_count"] = len(workers)

    return sessions_by_task_id, summary_by_task_id, active_session_by_task_id, active_session_by_task_user


def start_of_current_week(today_value: date) -> date:
    return today_value - timedelta(days=today_value.weekday())


def build_activity_stats(db: Session, users: list[User], today_value: date):
    stats = {
        user.id: {"last_seen": None, "today_count": 0, "week_count": 0}
        for user in users
    }
    if not users:
        return stats

    user_ids = [user.id for user in users]
    email_to_user_id = {
        (user.username or "").strip().lower(): user.id
        for user in users
        if (user.username or "").strip()
    }
    user_emails = list(email_to_user_id.keys())
    start_today = datetime.combine(today_value, datetime.min.time())
    start_week = datetime.combine(start_of_current_week(today_value), datetime.min.time())

    last_seen_rows = (
        db.query(UserActivity.user_id, func.max(UserActivity.created_at))
        .filter(
            UserActivity.user_id.in_(user_ids),
            UserActivity.user_id.isnot(None),
        )
        .group_by(UserActivity.user_id)
        .all()
    )
    for user_id, last_seen in last_seen_rows:
        if user_id in stats:
            stats[user_id]["last_seen"] = last_seen

    email_last_seen_rows = (
        db.query(UserActivity.user_email, func.max(UserActivity.created_at))
        .filter(
            UserActivity.user_id.is_(None),
            UserActivity.user_email.in_(user_emails),
        )
        .group_by(UserActivity.user_email)
        .all()
    )
    for user_email, last_seen in email_last_seen_rows:
        mapped_user_id = email_to_user_id.get((user_email or "").strip().lower())
        if mapped_user_id and (
            not stats[mapped_user_id]["last_seen"] or last_seen > stats[mapped_user_id]["last_seen"]
        ):
            stats[mapped_user_id]["last_seen"] = last_seen

    today_rows = (
        db.query(UserActivity.user_id, func.count(UserActivity.id))
        .filter(
            UserActivity.user_id.in_(user_ids),
            UserActivity.user_id.isnot(None),
            UserActivity.created_at >= start_today,
        )
        .group_by(UserActivity.user_id)
        .all()
    )
    for user_id, count in today_rows:
        if user_id in stats:
            stats[user_id]["today_count"] = count

    today_email_rows = (
        db.query(UserActivity.user_email, func.count(UserActivity.id))
        .filter(
            UserActivity.user_id.is_(None),
            UserActivity.user_email.in_(user_emails),
            UserActivity.created_at >= start_today,
        )
        .group_by(UserActivity.user_email)
        .all()
    )
    for user_email, count in today_email_rows:
        mapped_user_id = email_to_user_id.get((user_email or "").strip().lower())
        if mapped_user_id in stats:
            stats[mapped_user_id]["today_count"] += count

    week_rows = (
        db.query(UserActivity.user_id, func.count(UserActivity.id))
        .filter(
            UserActivity.user_id.in_(user_ids),
            UserActivity.user_id.isnot(None),
            UserActivity.created_at >= start_week,
        )
        .group_by(UserActivity.user_id)
        .all()
    )
    for user_id, count in week_rows:
        if user_id in stats:
            stats[user_id]["week_count"] = count

    week_email_rows = (
        db.query(UserActivity.user_email, func.count(UserActivity.id))
        .filter(
            UserActivity.user_id.is_(None),
            UserActivity.user_email.in_(user_emails),
            UserActivity.created_at >= start_week,
        )
        .group_by(UserActivity.user_email)
        .all()
    )
    for user_email, count in week_email_rows:
        mapped_user_id = email_to_user_id.get((user_email or "").strip().lower())
        if mapped_user_id in stats:
            stats[mapped_user_id]["week_count"] += count

    return stats


def render_manager_dashboard_page(user: User):
    db = SessionLocal()
    try:
        dashboard_data = build_manager_dashboard_data(
            db,
            Task=Task,
            TaskAssignee=TaskAssignee,
            User=User,
            Location=Location,
            Issue=Issue,
            get_task_schedule_date=get_task_schedule_date,
        )
        request.cf_user = user  # type: ignore[attr-defined]
        return render_template(
            "manager/dashboard.html",
            title="Manager Dashboard",
            body_class="manager",
            autorefresh=False,
            active_tab="manager",
            last_updated_label=dashboard_data["generated_at"].strftime("%d %b %Y · %H:%M"),
            **dashboard_data,
        )
    finally:
        db.close()


def render_manager_reports_page(user: User):
    db = SessionLocal()
    try:
        reports_data = build_manager_reports_data(
            db,
            Task=Task,
            TaskAssignee=TaskAssignee,
            User=User,
            Location=Location,
            Issue=Issue,
            get_task_schedule_date=get_task_schedule_date,
        )
        request.cf_user = user  # type: ignore[attr-defined]
        return render_template(
            "manager/reports.html",
            title="Reports",
            body_class="manager",
            autorefresh=False,
            active_tab="manager",
            last_updated_label=reports_data["generated_at"].strftime("%d %b %Y · %H:%M"),
            **reports_data,
        )
    finally:
        db.close()


def render_manager_done_tasks_page(user: User):
    db = SessionLocal()
    try:
        done_tasks_data = build_manager_done_tasks_data(
            db,
            Task=Task,
            TaskAssignee=TaskAssignee,
            User=User,
            Location=Location,
            Issue=Issue,
            get_task_schedule_date=get_task_schedule_date,
        )
        request.cf_user = user  # type: ignore[attr-defined]
        return render_template(
            "manager/done_tasks.html",
            title="Done Tasks",
            body_class="manager",
            autorefresh=False,
            active_tab="manager",
            last_updated_label=done_tasks_data["generated_at"].strftime("%d %b %Y · %H:%M"),
            **done_tasks_data,
        )
    finally:
        db.close()


def render_manager_tasks_page(user: User):
    db = SessionLocal()
    try:
        tasks_data = build_manager_tasks_list_data(
            db,
            Task=Task,
            TaskAssignee=TaskAssignee,
            User=User,
            Location=Location,
            Issue=Issue,
            get_task_schedule_date=get_task_schedule_date,
            filter_key=(request.args.get("filter", "today") or "today").strip().lower(),
        )
        request.cf_user = user  # type: ignore[attr-defined]
        return render_template(
            "manager/tasks_list.html",
            title=tasks_data["page_title"],
            body_class="manager",
            autorefresh=False,
            active_tab="manager",
            last_updated_label=tasks_data["generated_at"].strftime("%d %b %Y Â· %H:%M"),
            **tasks_data,
        )
    finally:
        db.close()


# ---------------- Health ----------------
@app.get("/health")
def health():
    return "ok", 200


@app.get("/manager/dashboard")
@manager_required
def manager_dashboard():
    user = request.cf_user  # type: ignore[attr-defined]
    return render_manager_dashboard_page(user)


@app.get("/reports")
@app.get("/manager/reports")
@manager_required
def manager_reports():
    user = request.cf_user  # type: ignore[attr-defined]
    return render_manager_reports_page(user)


@app.get("/done-tasks")
@app.get("/manager/done-tasks")
@manager_required
def manager_done_tasks():
    user = request.cf_user  # type: ignore[attr-defined]
    return render_manager_done_tasks_page(user)


@app.get("/manager/tasks")
@manager_required
def manager_tasks():
    user = request.cf_user  # type: ignore[attr-defined]
    return render_manager_tasks_page(user)


@app.get("/manager/unfinished-tasks")
@manager_required
def manager_unfinished_tasks():
    return redirect(url_for("manager_tasks", filter="unfinished"))


@app.get("/")
def index():
    db = SessionLocal()
    try:
        user = get_current_user_or_dev(db)
        if not user:
            # ovo pusti Cloudflareu da odradi login
            return redirect("/cdn-cgi/access/login")

        if is_manager_request():
            if not can_access_manager_dashboard(user):
                abort(403)
            return render_manager_dashboard_page(user)

        if is_admin_user(user):
            return redirect(url_for("admin_tasks"))

        if is_manager_user(user):
            manager_host = (app.config.get("MANAGER_HOST") or "").strip().lower()
            if manager_host:
                return redirect(f"https://{manager_host}/")
            return redirect(url_for("manager_dashboard"))

        return redirect(url_for("worker_dashboard"))
    finally:
        db.close()


@app.get("/logout")
def logout():
    # Cloudflare Access radi auth; "logout" se radi u Cloudflare UI-u.
    # Mi ovdje samo vratimo na početnu.
    return redirect(url_for("index"))

# -------- Admin: Locations --------
@app.get("/admin/locations")
@admin_required
def admin_locations():
    with Session(engine) as s:
        locations = s.execute(select(Location).order_by(Location.module, Location.kind, Location.name)).scalars().all()
        areas = s.execute(
            select(Location)
            .where(Location.kind == "area")
            .order_by(Location.module, Location.name)
        ).scalars().all()
        parent_name = {l.id: f"{l.module} · {l.name}" for l in areas}

    return render_template(
        "admin_locations.html",
        locations=locations,
        areas=areas,
        parent_name=parent_name
    )


@app.post("/admin/locations/add")
@admin_required
def admin_locations_add():
    name = (request.form.get("name") or "").strip()
    module = (request.form.get("module") or "horticulture").strip()
    kind = (request.form.get("kind") or "area").strip()
    parent_id_raw = (request.form.get("parent_id") or "").strip()

    if not name:
        flash("Naziv lokacije je obavezan.")
        return redirect(url_for("admin_locations"))

    if module not in ("horticulture", "garden"):
        flash("Neispravan module.")
        return redirect(url_for("admin_locations"))

    if kind not in ("area", "unit"):
        flash("Neispravan kind.")
        return redirect(url_for("admin_locations"))

    parent_id = int(parent_id_raw) if parent_id_raw.isdigit() else None
    if kind == "area":
        parent_id = None

    with Session(engine) as s:
        loc = Location(name=name, module=module, kind=kind, parent_id=parent_id, is_active=True)
        s.add(loc)
        s.commit()

    flash("Lokacija dodana.")
    return redirect(url_for("admin_locations"))


@app.get("/admin/locations/<int:loc_id>/edit")
@admin_required
def admin_locations_edit(loc_id):
    with Session(engine) as s:
        loc = s.get(Location, loc_id)
        if not loc:
            flash("Lokacija ne postoji.")
            return redirect(url_for("admin_locations"))

        areas = s.execute(
            select(Location).where(Location.kind == "area").order_by(Location.module, Location.name)
        ).scalars().all()

    return render_template("admin_locations_edit.html", loc=loc, areas=areas)


@app.post("/admin/locations/<int:loc_id>/edit")
@admin_required
def admin_locations_edit_post(loc_id):
    name = (request.form.get("name") or "").strip()
    module = (request.form.get("module") or "horticulture").strip()
    kind = (request.form.get("kind") or "area").strip()
    parent_id_raw = (request.form.get("parent_id") or "").strip()

    if not name:
        flash("Naziv lokacije je obavezan.")
        return redirect(url_for("admin_locations_edit", loc_id=loc_id))

    if module not in ("horticulture", "garden") or kind not in ("area", "unit"):
        flash("Neispravni podaci.")
        return redirect(url_for("admin_locations_edit", loc_id=loc_id))

    parent_id = int(parent_id_raw) if parent_id_raw.isdigit() else None
    if kind == "area":
        parent_id = None

    with Session(engine) as s:
        loc = s.get(Location, loc_id)
        if not loc:
            flash("Lokacija ne postoji.")
            return redirect(url_for("admin_locations"))

        loc.name = name
        loc.module = module
        loc.kind = kind
        loc.parent_id = parent_id
        s.commit()

    flash("Lokacija ažurirana.")
    return redirect(url_for("admin_locations"))


@app.post("/admin/locations/<int:loc_id>/delete")
@admin_required
def admin_locations_delete(loc_id):
    with Session(engine) as s:
        loc = s.get(Location, loc_id)
        if not loc:
            flash("Lokacija ne postoji.", "error")
            return redirect(url_for("admin_locations"))

        s.delete(loc)
        s.commit()

    flash("Lokacija obrisana.", "ok")
    return redirect(url_for("admin_locations"))

# -------- Admin: Tasks --------

@app.get("/admin/tasks")
@admin_required
def admin_tasks():
    db = SessionLocal()
    try:
        today = date.today().isoformat()
        today_start = datetime.combine(date.today(), datetime.min.time())
        selected_module = (request.args.get("module") or "").strip().lower()
        selected_location_raw = (request.args.get("location_id") or "").strip()
        selected_assignee_raw = (request.args.get("assignee_id") or "").strip()
        selected_location_id = int(selected_location_raw) if selected_location_raw.isdigit() else None
        selected_assignee_id = int(selected_assignee_raw) if selected_assignee_raw.isdigit() else None
        selected_assignee_set = {selected_assignee_id} if selected_assignee_id is not None else set()

        # LOAD TASKS
        all_tasks = db.query(Task).all()

        # SMART SORT (command center order)
        def task_sort_key(t):
            if t.is_todo:
                created_key = t.created_at or datetime.min
                created_stamp = created_key.timestamp() if created_key != datetime.min else 0
                return (-1, -created_stamp, -(t.id or 0))
            d = str(t.task_date) if t.task_date else "9999-99-99"

            if t.status == "done":
                return (3, d)
            if d < today:
                return (0, d)
            if d == today:
                return (1, d)
            return (2, d)

        # LOOKUPS
        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}
        assignee_options = [
            u for u in users.values()
            if getattr(u, "is_active", False)
        ]
        assignee_options = sorted(assignee_options, key=lambda u: (u.display_name or u.username or "").lower())

        rows = db.query(TaskAssignee).all()
        task_to_user_ids = {}
        for r in rows:
            task_to_user_ids.setdefault(r.task_id, []).append(r.user_id)
        all_ids = [t.id for t in all_tasks if t.id]
        task_ids = all_ids

        linked_issues = (
            db.query(Issue)
            .filter(Issue.linked_task_id.in_(task_ids))
            .order_by(Issue.created_at.desc())
            .all()
        ) if task_ids else []

        issue_by_task_id = {}
        for iss in linked_issues:
            if iss.linked_task_id and iss.linked_task_id not in issue_by_task_id:
                issue_by_task_id[iss.linked_task_id] = iss

        linked_issue_photo_by_task_id = {}
        for task_id, iss in issue_by_task_id.items():
            if iss.photos:
                linked_issue_photo_by_task_id[task_id] = normalize_static_file_path(iss.photos[0].file_path)
        
        def matches_admin_filters(task: Task) -> bool:
            if selected_module and (task.module or "").lower() != selected_module:
                return False
            if selected_location_id is not None and task.location_id != selected_location_id:
                return False
            if selected_assignee_set and not selected_assignee_set.intersection(task_to_user_ids.get(task.id, [])):
                return False
            return True

        tasks = [t for t in all_tasks if matches_admin_filters(t)]
        tasks = sorted(tasks, key=task_sort_key)[:200]

        # FILTER PARAM
        flt = request.args.get("filter", "all")

        # URGENT STRIP
        urgent_tasks = [
            t for t in tasks
            if not t.is_todo and t.status != "done" and t.task_date and str(t.task_date) <= today
        ][:4]

        # COUNTS
        counts = {
            "todo": sum(1 for t in tasks if t.is_todo),
            "today": sum(1 for t in tasks if (not t.is_todo and t.task_date and str(t.task_date) == today and t.status != "done")),
            "unfinished": sum(1 for t in tasks if (not t.is_todo and t.task_date and str(t.task_date) < today and t.status != "done")),
            "upcoming": sum(1 for t in tasks if (not t.is_todo and t.task_date and str(t.task_date) > today and t.status != "done")),
            "done": sum(1 for t in tasks if not t.is_todo and t.status == "done"),
        }

        # FILTER LIST
        filtered_tasks = tasks
        if flt == "todo":
            filtered_tasks = [t for t in tasks if t.is_todo]
        elif flt == "today":
            filtered_tasks = [t for t in tasks if (not t.is_todo and t.task_date and str(t.task_date) == today)]
        elif flt == "unfinished":
            filtered_tasks = [t for t in tasks if (not t.is_todo and t.task_date and str(t.task_date) < today and t.status != "done")]
        elif flt == "open":
            filtered_tasks = [t for t in tasks if t.status == "open" and not t.is_todo]
        elif flt == "done":
            filtered_tasks = [t for t in tasks if t.status == "done" and not t.is_todo]
        elif flt == "upcoming":
            filtered_tasks = [t for t in tasks if (not t.is_todo and t.task_date and str(t.task_date) > today and t.status != "done")]

        # GROUPING
        groups = {"todo": [], "unfinished": [], "today": [], "upcoming": [], "done": []}

        for t in filtered_tasks:
            if t.is_todo:
                groups["todo"].append(t)
                continue
            if t.status == "done":
                groups["done"].append(t)
                continue

            if not t.task_date:
                continue

            d = str(t.task_date)
            if d < today:
                groups["unfinished"].append(t)
            elif d == today:
                groups["today"].append(t)
            else:
                groups["upcoming"].append(t)

        done_history_groups = []
        done_bucket = {}

        def done_group_date(task: Task):
            return task.finished_at.date() if task.finished_at else task.task_date

        def done_group_sort_key(task: Task):
            if task.finished_at:
                return task.finished_at
            if task.task_date:
                return datetime.combine(task.task_date, datetime.min.time())
            return datetime.min

        for t in groups["done"]:
            group_date = done_group_date(t)
            if not group_date:
                continue
            done_bucket.setdefault(group_date, []).append(t)

        for group_date in sorted(done_bucket.keys(), reverse=True):
            items = sorted(done_bucket[group_date], key=done_group_sort_key, reverse=True)
            done_history_groups.append({
                "key": group_date.isoformat(),
                "label": group_date.strftime("%A, %Y-%m-%d"),
                "count": len(items),
                "items": items,
            })

        # -----------------------------
        # LINKED ISSUE + ISSUE PHOTO MAP
        # -----------------------------
        task_ids = [t.id for t in tasks]

        linked_issues = (
            db.query(Issue)
            .filter(Issue.linked_task_id.in_(task_ids))
            .order_by(Issue.created_at.desc())
            .all()
        ) if task_ids else []

        issue_by_task_id = {}
        for iss in linked_issues:
            if iss.linked_task_id and iss.linked_task_id not in issue_by_task_id:
                issue_by_task_id[iss.linked_task_id] = iss

        linked_issue_photo_by_task_id = {}
        for task_id, iss in issue_by_task_id.items():
            if iss.photos:
                linked_issue_photo_by_task_id[task_id] = normalize_static_file_path(iss.photos[0].file_path)
        photo_rows = (
            db.query(TaskPhoto)
            .filter(TaskPhoto.task_id.in_(task_ids))
            .order_by(TaskPhoto.created_at.desc())
            .all()
        ) if task_ids else []

        latest_task_photo_by_task_id = {}
        task_photo_paths_by_task_id = {}
        for p in photo_rows:
            normalized_path = normalize_static_file_path(p.file_path)
            if not normalized_path:
                continue
            task_photo_paths_by_task_id.setdefault(p.task_id, []).append(normalized_path)
            if p.task_id not in latest_task_photo_by_task_id:
                latest_task_photo_by_task_id[p.task_id] = normalized_path

        task_work_sessions_by_task_id, task_work_summary_by_task_id, active_work_sessions_by_task_id, _ = (
            build_task_work_session_data(db, task_ids)
        )

        recent_work_sessions = (
            db.query(TaskWorkSession)
            .filter(TaskWorkSession.finished_at.isnot(None))
            .order_by(TaskWorkSession.finished_at.desc(), TaskWorkSession.id.desc())
            .limit(10)
            .all()
        )
        recent_work_session_task_ids = [session.task_id for session in recent_work_sessions]
        recent_work_session_tasks = {
            task.id: task
            for task in db.query(Task).filter(Task.id.in_(recent_work_session_task_ids)).all()
        } if recent_work_session_task_ids else {}

        work_session_stats = {
            "sessions_today": (
                db.query(TaskWorkSession)
                .filter(TaskWorkSession.started_at >= today_start)
                .count()
            ),
            "finished_sessions_today": (
                db.query(TaskWorkSession)
                .filter(TaskWorkSession.finished_at.isnot(None), TaskWorkSession.finished_at >= today_start)
                .count()
            ),
            "active_sessions_now": (
                db.query(TaskWorkSession)
                .filter(TaskWorkSession.status == "active", TaskWorkSession.finished_at.is_(None))
                .count()
            ),
        }
        return render_template(
            "admin_tasks.html",
            title="Tasks",
            tasks=tasks,
            users=users,
            locations=locations,
            task_to_user_ids=task_to_user_ids,
            assignee_options=assignee_options,
            counts=counts,
            flt=flt,
            groups=groups,
            done_history_groups=done_history_groups,
            selected_module=selected_module,
            selected_location_id=selected_location_id,
            selected_assignee_id=selected_assignee_id,
            today=today,
            urgent_tasks=urgent_tasks,
            issue_by_task_id=issue_by_task_id,
            linked_issue_photo_by_task_id=linked_issue_photo_by_task_id,
            latest_task_photo_by_task_id=latest_task_photo_by_task_id,
            task_photo_paths_by_task_id=task_photo_paths_by_task_id,
            task_work_sessions_by_task_id=task_work_sessions_by_task_id,
            task_work_summary_by_task_id=task_work_summary_by_task_id,
            active_work_sessions_by_task_id=active_work_sessions_by_task_id,
            recent_work_sessions=recent_work_sessions,
            recent_work_session_tasks=recent_work_session_tasks,
            work_session_stats=work_session_stats,
        )
    finally:
        db.close()

@app.get("/admin/users")
@admin_required
def admin_users():
    q = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "active").strip().lower()  # active/all/disabled
    team_raw = (request.args.get("team") or "").strip()
    team_id = int(team_raw) if team_raw.isdigit() else None

    db = SessionLocal()
    try:
        teams = db.query(Team).order_by(Team.name.asc()).all()

        query = db.query(User)

        if status == "active":
            query = query.filter(User.is_active == True)
        elif status == "disabled":
            query = query.filter(User.is_active == False)

        if team_id is not None:
            query = query.filter(User.team_id == team_id)

        if q:
            # traži po emailu i imenu
            query = query.filter(
                or_(
                    User.username.ilike(f"%{q}%"),
                    User.display_name.ilike(f"%{q}%"),
                )
            )

        # sort: active prvo, admini gore, email asc
        users = query.order_by(
            User.is_active.desc(),
            case((User.role == "admin", 1), else_=0).desc(),
            case((User.role == "manager", 1), else_=0).desc(),
            User.username.asc()
        ).all()

        return render_template(
            "admin_users.html",
            title="Users",
            users=users,
            teams=teams,
            q=q,
            status=status,
            team_id=team_id,
        )
    finally:
        db.close()


@app.get("/admin/activity")
@admin_required
def admin_activity():
    db = SessionLocal()
    try:
        workers = (
            db.query(User)
            .filter(User.role == "worker")
            .order_by(User.is_active.desc(), func.lower(func.coalesce(User.display_name, User.username)))
            .all()
        )

        today_value = date.today()
        stats_by_user_id = build_activity_stats(db, workers, today_value)

        return render_template(
            "admin_activity.html",
            title="User Activity",
            workers=workers,
            stats_by_user_id=stats_by_user_id,
            today=today_value,
        )
    finally:
        db.close()


@app.get("/admin/activity/<int:user_id>")
@admin_required
def admin_activity_detail(user_id: int):
    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        if not user:
            flash("User not found.")
            return redirect(url_for("admin_activity"))

        today_value = date.today()
        stats = build_activity_stats(db, [user], today_value).get(
            user.id,
            {"last_seen": None, "today_count": 0, "week_count": 0},
        )

        activities = (
            db.query(UserActivity)
            .filter(
                or_(
                    UserActivity.user_id == user.id,
                    (UserActivity.user_id.is_(None) & (UserActivity.user_email == user.username)),
                )
            )
            .order_by(UserActivity.created_at.desc())
            .limit(50)
            .all()
        )

        return render_template(
            "admin_activity_detail.html",
            title="User Activity Detail",
            user=user,
            stats=stats,
            activities=activities,
            today=today_value,
        )
    finally:
        db.close()


@app.post("/admin/users/<int:user_id>/toggle_active")
@admin_required
def admin_user_toggle_active(user_id: int):
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            flash("User not found.")
            return redirect(url_for("admin_users"))
        current = request.cf_user  # type: ignore[attr-defined]
        if u.id == current.id:
            flash("You cannot disable yourself.")
            return redirect(url_for("admin_users"))
        u.is_active = not bool(u.is_active)
        db.commit()
        flash("User updated.")
        return redirect(url_for("admin_users"))
    finally:
        db.close()


@app.post("/admin/users/<int:user_id>/set_role")
@admin_required
def admin_user_set_role(user_id: int):
    role = (request.form.get("role") or "worker").strip().lower()
    if role not in ("admin", "manager", "worker"):
        flash("Invalid role.")
        return redirect(url_for("admin_users"))

    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            flash("User not found.")
            return redirect(url_for("admin_users"))
        u.role = role
        db.commit()
        flash("Role updated.")
        return redirect(url_for("admin_users"))
    finally:
        db.close()


@app.post("/admin/users/<int:user_id>/set_team")
@admin_required
def admin_user_set_team(user_id: int):
    team_id_raw = (request.form.get("team_id") or "").strip()
    team_id = int(team_id_raw) if team_id_raw.isdigit() else None

    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            flash("User not found.")
            return redirect(url_for("admin_users"))

        if team_id is not None:
            t = db.get(Team, team_id)
            if not t or not t.is_active:
                flash("Team not valid.")
                return redirect(url_for("admin_users"))

        u.team_id = team_id
        db.commit()
        flash("Team updated.")
        return redirect(url_for("admin_users"))
    finally:
        db.close()


@app.post("/admin/users/<int:user_id>/set_display_name")
@admin_required
def admin_user_set_display_name(user_id: int):
    display_name = (request.form.get("display_name") or "").strip() or None

    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            flash("User not found.")
            return redirect(url_for("admin_users"))

        u.display_name = display_name
        db.commit()
        flash("Name updated.")
        return redirect(url_for("admin_users"))
    finally:
        db.close()


@app.post("/admin/users/<int:user_id>/set_telegram_chat_id")
@admin_required
def admin_user_set_telegram_chat_id(user_id: int):
    telegram_chat_id = (request.form.get("telegram_chat_id") or "").strip() or None

    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            flash("User not found.")
            return redirect(url_for("admin_users"))

        u.telegram_chat_id = telegram_chat_id
        db.commit()
        flash("Telegram chat ID updated.")
        return redirect(url_for("admin_users"))
    finally:
        db.close()


@app.route("/admin/tasks/new", methods=["GET", "POST"])
@admin_required
def admin_task_new():
    db = SessionLocal()
    try:
        areas = (
            db.query(Location)
            .filter(Location.is_active == True, Location.kind == "area")
            .order_by(Location.module.asc(), Location.name.asc())
            .all()
        )

        units = (
            db.query(Location)
            .filter(Location.is_active == True, Location.kind == "unit")
            .order_by(Location.module.asc(), Location.parent_id.asc(), Location.name.asc())
            .all()
        )

        workers = (
            db.query(User)
            .filter(User.is_active == True)
            .order_by(User.username.asc())
            .all()
        )

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            module = request.form.get("module") or "horticulture"
            notes = (request.form.get("notes") or "").strip()

            area_id_raw = (request.form.get("area_id") or "").strip()
            residence_id_raw = (request.form.get("residence_id") or "").strip()

            assigned_ids = request.form.getlist("assigned_user_ids")
            assigned_ids = [int(x) for x in assigned_ids if x and x.strip().isdigit()]

            task_date_raw = (request.form.get("task_date") or "").strip()
            is_todo = (request.form.get("is_todo") or "").strip() == "1"
            if task_date_raw and not is_todo:
                y, m, d = task_date_raw.split("-")
                task_date_val = date(int(y), int(m), int(d))
            elif is_todo:
                task_date_val = None
            else:
                task_date_val = date.today()

            if not title or not area_id_raw.isdigit():
                flash("Title and location (phase/area) are required.")
                return render_template(
                    "admin_task_new.html",
                    title="Create task",
                    areas=areas,
                    units=units,
                    workers=workers,
                )

            area_id = int(area_id_raw)

            location_id = area_id
            if residence_id_raw and residence_id_raw.isdigit():
                location_id = int(residence_id_raw)

            loc = db.get(Location, location_id)
            if not loc or not loc.is_active:
                flash("Selected location is not valid.")
                return render_template(
                    "admin_task_new.html",
                    title="Create task",
                    areas=areas,
                    units=units,
                    workers=workers,
                )

            # CREATE TASK
            t = Task(
                title=title,
                module=module,
                location_id=location_id,
                notes=notes or None,
                task_date=task_date_val,
                next_action_date=task_date_val,
                is_todo=is_todo,
                status="open",
            )
            db.add(t)
            db.commit()

            # OPTIONAL REFERENCE PHOTOS
            photo_uploads = [
                photo for photo in request.files.getlist("photo")
                if photo and photo.filename
            ]
            invalid_photo = next(
                (photo.filename for photo in photo_uploads if not allowed_image_file(photo.filename)),
                None,
            )
            if invalid_photo:
                flash("Unsupported image format.")
                return redirect(url_for("admin_task_new"))

            for photo in photo_uploads:
                db.add(save_task_photo_upload(
                    t.id,
                    photo,
                    uploaded_by=getattr(request.cf_user, "id", None),
                    convert_to_jpeg=True,
                ))

            if photo_uploads:
                db.commit()

            # ASSIGN WORKERS
            for uid in assigned_ids:
                db.add(TaskAssignee(task_id=t.id, user_id=uid))

            db.commit()
            notify_task_users(db, t, assigned_ids, label="assigned")

            # TELEGRAM NOTIFICATION
                       
            print("ADMIN_TASK_NEW: TASK SAVED, BEFORE TELEGRAM")

            if not t.is_todo:
                telegram_ok = send_telegram_message(
                f"🆕 New task created\n"
                f"{title}\n"
                f"{TASKMANAGER_URL}admin/tasks#{t.id}"
            )
            print("ADMIN_TASK_NEW: TELEGRAM RESULT =", telegram_ok if not t.is_todo else "skipped")
            flash("Task created." if not t.is_todo else "To Do item created.")
            return redirect_back()

        return render_template(
            "admin_task_new.html",
            title="Create task",
            areas=areas,
            units=units,
            workers=workers,
        )

    finally:
        db.close()

# -------- Admin: Teams --------
@app.get("/admin/teams")
@admin_required
def admin_teams():
    db = SessionLocal()
    try:
        teams = db.query(Team).order_by(Team.name.asc()).all()
        return render_template("admin_teams.html", title="Teams", teams=teams)
    finally:
        db.close()


@app.route("/admin/teams/new", methods=["GET", "POST"])
@admin_required
def admin_team_new():
    if request.method == "POST":
        print("ADMIN_TASK_NEW: POST START")
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Name is required.")
            return render_template("admin_team_new.html", title="Create team")

        db = SessionLocal()
        try:
            if db.query(Team).filter(Team.name == name).first():
                flash("Team already exists.")
                return render_template("admin_team_new.html", title="Create team")

            db.add(Team(name=name, is_active=True))
            db.commit()
            flash("Team created.")
            return redirect(url_for("admin_teams"))
        finally:
            db.close()

    return render_template("admin_team_new.html", title="Create team")

def get_or_create_user_from_email(db: Session, email: str) -> User:
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("Missing email from Cloudflare.")

    u = db.query(User).filter(User.username == email).first()
    if u:
        return u

    # Ako ti je password_hash nullable=True, ovu liniju možeš maknuti
    u = User(
        username=email,
        role="worker",
        password_hash=generate_password_hash(secrets.token_hex(16)),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u

@app.get("/worker/home")
@cf_required
def worker_home():
    active_module, _ = parse_module_arg()
    return redirect(url_for("worker_dashboard", module=active_module))
# -------- Worker dashboard --------
@app.get("/worker/dashboard")
@cf_required
def worker_dashboard():
    user = request.cf_user  # type: ignore[attr-defined]

    today = date.today()
    until = today + timedelta(days=7)
    active_module, module_filter = parse_module_arg()
    view = request.args.get("view", "all")

    db = SessionLocal()
    try:
        overdue_tasks, today_tasks, upcoming_tasks = load_worker_task_groups(
            db, user, module_filter, today, until
        )

        # ORIGINALNI COUNTS - uvijek iz punih lista
        overdue_count = len(overdue_tasks)
        today_count = len(today_tasks)
        upcoming_count = len(upcoming_tasks)

        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}

        all_ids = [t.id for t in overdue_tasks] + [t.id for t in today_tasks] + [t.id for t in upcoming_tasks]

        rows = db.query(TaskAssignee).filter(
            TaskAssignee.task_id.in_(all_ids)
        ).all() if all_ids else []

        task_to_user_ids = {}
        for r in rows:
            task_to_user_ids.setdefault(r.task_id, []).append(r.user_id)

        residences_by_parent = {}
        units = db.query(Location).filter(
            Location.kind == "unit",
            Location.is_active == True
        ).order_by(Location.name.asc()).all()

        for u in units:
            residences_by_parent.setdefault(u.parent_id, []).append(u)

        linked_issues = (
            db.query(Issue)
            .filter(Issue.linked_task_id.in_(all_ids))
            .order_by(Issue.created_at.desc())
            .all()
        ) if all_ids else []

        issue_by_task_id = {}
        for iss in linked_issues:
            if iss.linked_task_id and iss.linked_task_id not in issue_by_task_id:
                issue_by_task_id[iss.linked_task_id] = iss

        linked_issue_photo_by_task_id = {}
        for task_id, iss in issue_by_task_id.items():
            if iss.photos:
                linked_issue_photo_by_task_id[task_id] = iss.photos[0].file_path

        photo_rows = (
            db.query(TaskPhoto)
            .filter(TaskPhoto.task_id.in_(all_ids))
            .order_by(TaskPhoto.created_at.desc())
            .all()
        ) if all_ids else []

        latest_task_photo_by_task_id = {}
        for p in photo_rows:
            normalized_path = normalize_static_file_path(p.file_path)
            if not normalized_path:
                continue
            if p.task_id not in latest_task_photo_by_task_id:
                latest_task_photo_by_task_id[p.task_id] = normalized_path

        _, _, _, active_work_session_by_task_user = build_task_work_session_data(db, all_ids)
        worker_active_session_by_task_id = {
            task_id: session
            for (task_id, session_user_id), session in active_work_session_by_task_user.items()
            if session_user_id == user.id
        }

        # DISPLAY liste - samo za ono što se vidi na ekranu
        display_overdue_tasks = overdue_tasks
        display_today_tasks = today_tasks
        display_upcoming_tasks = upcoming_tasks

        if view == "today":
            display_overdue_tasks = []
            display_upcoming_tasks = []
        elif view == "unfinished":
            display_today_tasks = []
            display_upcoming_tasks = []
        elif view == "upcoming":
            display_overdue_tasks = []
            display_today_tasks = []
        else:
            view = "all"

        today_pretty = today.strftime("%A, %B %d, %Y")
        unread_observation_count = get_worker_unread_observation_count(db, user.id)

        return render_template(
            "worker_dashboard.html",
            title="My tasks",
            body_class="worker",
            today_pretty=today_pretty,
            overdue_tasks=display_overdue_tasks,
            today_tasks=display_today_tasks,
            upcoming_tasks=display_upcoming_tasks,
            overdue_count=overdue_count,
            today_count=today_count,
            upcoming_count=upcoming_count,
            locations=locations,
            users=users,
            task_to_user_ids=task_to_user_ids,
            residences_by_parent=residences_by_parent,
            active_module=active_module,
            today=today,
            until=until,
            active_tab="tasks",
            issue_by_task_id=issue_by_task_id,
            linked_issue_photo_by_task_id=linked_issue_photo_by_task_id,
            latest_task_photo_by_task_id=latest_task_photo_by_task_id,
            worker_active_session_by_task_id=worker_active_session_by_task_id,
            view=view,
            unread_observation_count=unread_observation_count,
        )
    finally:
        db.close()

@app.get("/worker/task/<int:task_id>")
@cf_required
def worker_task_detail(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()
    view = (request.args.get("view") or "all").lower()

    if view in {"today", "unfinished", "upcoming"}:
        back_url = url_for("worker_dashboard", module=module, view=view)
    else:
        view = "all"
        back_url = url_for("worker_dashboard", module=module)

    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if not task:
            flash("Task not found.")
            return redirect(back_url)

        if not is_task_allowed_for_worker(db, task, user):
            flash("Not allowed.")
            return redirect(back_url)

        def display_user_name(row: User | None) -> str:
            if not row:
                return "TaskManager"
            return (row.display_name or row.username.split("@")[0]).strip()

        location = db.get(Location, task.location_id)
        assigned_rows = (
            db.query(TaskAssignee)
            .filter(TaskAssignee.task_id == task.id)
            .all()
        )
        assignee_ids = [row.user_id for row in assigned_rows]

        linked_issue = (
            db.query(Issue)
            .filter(Issue.linked_task_id == task.id)
            .order_by(Issue.created_at.desc())
            .first()
        )

        task_photos = (
            db.query(TaskPhoto)
            .filter(TaskPhoto.task_id == task.id)
            .order_by(TaskPhoto.created_at.desc(), TaskPhoto.id.desc())
            .all()
        )
        worker_active_session = get_active_task_work_session(db, task.id, user.id)

        issue_photos = []
        if linked_issue:
            issue_photos = (
                db.query(IssuePhoto)
                .filter(IssuePhoto.issue_id == linked_issue.id)
                .order_by(IssuePhoto.created_at.desc(), IssuePhoto.id.desc())
                .all()
            )

        creator_ids = set(assignee_ids)
        if linked_issue and linked_issue.created_by:
            creator_ids.add(linked_issue.created_by)

        users = {
            row.id: row
            for row in db.query(User).filter(User.id.in_(creator_ids)).all()
        } if creator_ids else {}

        assignee_names = [
            display_user_name(users.get(user_id))
            for user_id in assignee_ids
        ]

        if linked_issue and linked_issue.created_by:
            created_by_name = display_user_name(users.get(linked_issue.created_by))
        elif task.carryover_from_task_id:
            created_by_name = "Carryover task"
        else:
            created_by_name = "TaskManager"

        created_at_label = task.created_at.strftime("%Y-%m-%d %H:%M") if task.created_at else "-"

        priority_label = None
        priority_tone = None
        if linked_issue and linked_issue.severity in {"medium", "high"}:
            priority_label = f"{linked_issue.severity.title()} priority"
            priority_tone = linked_issue.severity

        attachment_items = []
        seen_paths = set()

        for photo in task_photos:
            path = normalize_static_file_path(photo.file_path)
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            attachment_items.append({
                "path": path,
                "label": "Task photo",
                "created_at": photo.created_at.strftime("%Y-%m-%d %H:%M") if photo.created_at else "",
            })

        for photo in issue_photos:
            path = normalize_static_file_path(photo.file_path)
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            attachment_items.append({
                "path": path,
                "label": f"Issue #{linked_issue.id} reference" if linked_issue else "Reference",
                "created_at": photo.created_at.strftime("%Y-%m-%d %H:%M") if photo.created_at else "",
            })

        primary_image = attachment_items[0] if attachment_items else None

        notes_items = []
        if linked_issue and linked_issue.notes:
            notes_items.append({
                "label": f"Issue #{linked_issue.id}",
                "text": linked_issue.notes,
            })
        if task.status == "blocked" and task.blocked_reason:
            blocked_text = task.blocked_reason.replace("_", " ").title()
            if task.blocked_until:
                blocked_text += f" until {task.blocked_until}"
            notes_items.append({
                "label": "Blocked",
                "text": blocked_text,
            })
        if task.carryover_from_task_id:
            notes_items.append({
                "label": "Carryover",
                "text": f"Created from task #{task.carryover_from_task_id}.",
            })

        residences_by_parent = {}
        units = (
            db.query(Location)
            .filter(Location.kind == "unit", Location.is_active == True)
            .order_by(Location.name.asc())
            .all()
        )
        for unit in units:
            residences_by_parent.setdefault(unit.parent_id, []).append(unit)

        unread_observation_count = get_worker_unread_observation_count(db, user.id)

        return render_template(
            "worker_task_detail.html",
            title=task.title,
            body_class="worker",
            active_tab="tasks",
            active_module=module,
            task=task,
            location=location,
            assignee_names=assignee_names,
            created_by_name=created_by_name,
            created_at_label=created_at_label,
            back_url=back_url,
            current_view=view,
            linked_issue=linked_issue,
            worker_has_active_session=worker_active_session is not None,
            primary_image=primary_image,
            attachment_items=attachment_items,
            notes_items=notes_items,
            priority_label=priority_label,
            priority_tone=priority_tone,
            residences_by_parent=residences_by_parent,
            unread_observation_count=unread_observation_count,
        )
    finally:
        db.close()

# -------- Worker actions --------
@app.post("/worker/task/<int:task_id>/start")
@cf_required
def worker_task_start(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()
    now = datetime.utcnow()

    default_url = url_for("worker_dashboard", module=module)
    next_url = safe_next_url(default_url)

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(next_url)

        if not is_task_allowed_for_worker(db, t, user):
            flash("Not allowed.")
            return redirect(next_url)

        if t.status == "done":
            flash("Task already done.")
            return redirect(next_url)

        if t.status == "blocked":
            t.blocked_reason = None
            t.blocked_until = None
            t.blocked_at = None
            t.blocked_location_id = None

        if t.status != "in_progress":
            t.status = "in_progress"
        if not t.started_at:
            t.started_at = now

        start_task_work_session(db, t.id, user.id, started_at=now)

        db.commit()
        return redirect(next_url)
    finally:
        db.close()


@app.post("/worker/task/<int:task_id>/done")
@cf_required
def worker_task_done(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()
    today = date.today()
    now = datetime.utcnow()

    default_url = url_for("worker_dashboard", module=module)
    next_url = safe_next_url(default_url)

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(next_url)

        if not is_task_allowed_for_worker(db, t, user):
            flash("Not allowed.")
            return redirect(next_url)

        finish_validation_error = get_worker_task_finish_validation_error(t, as_of=now)
        if finish_validation_error:
            flash(finish_validation_error)
            return redirect(next_url)

        finish_active_sessions_for_tasks(db, [t.id], finished_at=now)

        if getattr(t, "carryover_from_task_id", None):
            orig_id = t.carryover_from_task_id
            res_id = t.location_id

            db.query(ResidenceBlock).filter(
                ResidenceBlock.task_id == orig_id,
                ResidenceBlock.residence_id == res_id
            ).delete(synchronize_session=False)

            t.status = "done"
            if not t.started_at:
                t.started_at = now
            t.finished_at = now

            db.commit()

            send_telegram_message(
                f"✅ Task completed\n"
                f"{t.title}\n"
                f"{TASKMANAGER_URL}admin/tasks#{t.id}"
            )

            return redirect(next_url)

        blocks = db.query(ResidenceBlock).filter(ResidenceBlock.task_id == t.id).all()

        for b in blocks:
            res = db.get(Location, b.residence_id)
            res_name = res.name if res else f"#{b.residence_id}"

            follow_date = b.until_date if b.until_date else (today + timedelta(days=1))
            until_txt = f" until {follow_date}" if follow_date else ""

            new_task = Task(
                title=f"{t.title} ({res_name})",
                module=t.module,
                status="open",
                task_date=follow_date,
                next_action_date=follow_date,
                location_id=b.residence_id,
                notes=f"[Carryover] Blocked residence {res_name} ({b.reason}){until_txt}",
                carryover_from_task_id=t.id
            )

            db.add(new_task)
            db.flush()
            copy_assignees(db, t.id, new_task.id)

        if blocks:
            db.query(ResidenceBlock).filter(
                ResidenceBlock.task_id == t.id
            ).delete(synchronize_session=False)

        t.status = "done"
        if not t.started_at:
            t.started_at = now
        t.finished_at = now

        t.blocked_reason = None
        t.blocked_until = None
        t.blocked_at = None
        t.blocked_location_id = None

        db.commit()

        send_telegram_message(
            f"✅ Task completed in TaskManager.\n{TASKMANAGER_URL}"
        )

        return redirect(next_url)
    finally:
        db.close()


@app.post("/worker/task/<int:task_id>/blocked")
@cf_required
def worker_task_blocked(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()
    now = datetime.utcnow()

    default_url = url_for("worker_dashboard", module=module)
    next_url = safe_next_url(default_url)

    reason = (request.form.get("reason") or "").strip().lower()

    blocked_loc_raw = (request.form.get("blocked_location_id") or "").strip()
    blocked_location_id = int(blocked_loc_raw) if blocked_loc_raw.isdigit() else None

    until_raw = (request.form.get("blocked_until") or "").strip()
    blocked_until = None
    if until_raw:
        y, m, d = until_raw.split("-")
        blocked_until = date(int(y), int(m), int(d))

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(next_url)

        if not is_task_allowed_for_worker(db, t, user):
            flash("Not allowed.")
            return redirect(next_url)

        if not reason:
            flash("Blocked reason is required.")
            return redirect(next_url)

        if blocked_location_id:
            db.add(ResidenceBlock(
                task_id=t.id,
                residence_id=blocked_location_id,
                reason=reason,
                until_date=blocked_until,
                created_by=user.id
            ))
            db.commit()
            return redirect(next_url)

        t.status = "blocked"
        t.blocked_reason = reason
        t.blocked_until = blocked_until
        t.blocked_at = now
        t.blocked_location_id = None

        if not t.started_at:
            t.started_at = now
        t.finished_at = None
        finish_active_sessions_for_tasks(db, [t.id], finished_at=now)

        db.commit()
        return redirect(next_url)
    finally:
        db.close()


@app.post("/worker/task/<int:task_id>/unblock")
@cf_required
def worker_task_unblock(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()

    default_url = url_for("worker_dashboard", module=module)
    next_url = safe_next_url(default_url)

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(next_url)

        # permission
        is_admin = (user.role == "admin") or (user.username.lower() in ADMIN_EMAILS)
        if not is_admin:
            assigned_user_ids = [
                r.user_id for r in db.query(TaskAssignee).filter(TaskAssignee.task_id == t.id).all()
            ]
            if assigned_user_ids and (user.id not in assigned_user_ids):
                flash("Not allowed.")
                return redirect(next_url)

        t.status = "open"
        t.blocked_reason = None
        t.blocked_until = None
        t.blocked_at = None
        t.finished_at = None
        db.commit()

        flash("Task unblocked.")
        return redirect(next_url)
    finally:
        db.close()


# -------- Worker: Issues --------
@app.route("/worker/issues/new", methods=["GET", "POST"])
@cf_required
def worker_issue_new():
    user = request.cf_user  # type: ignore[attr-defined]
    db = SessionLocal()
    try:
        locations = (
            db.query(Location)
            .filter(Location.is_active == True)
            .order_by(Location.module.asc(), Location.name.asc())
            .all()
        )

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            category = request.form.get("category") or "equipment"
            severity = request.form.get("severity") or "low"
            module = request.form.get("module") or "horticulture"
            notes = (request.form.get("notes") or "").strip()
            loc_raw = (request.form.get("location_id") or "").strip()
            location_id = int(loc_raw) if loc_raw.isdigit() else None

            if not title:
                flash("Title is required.")
                return render_template(
                    "worker_issue_new.html",
                    title="Report issue",
                    locations=locations,
                    active_tab="issues",
                    active_module=module,
                )

            iss = Issue(
                title=title,
                category=category,
                severity=severity,
                status="open",
                module=module,
                location_id=location_id,
                created_by=user.id,
                notes=notes or None
            )
            db.add(iss)
            db.commit()

            photo = request.files.get("photo")
            if photo and photo.filename:
                if not allowed_image_file(photo.filename):
                    flash("Unsupported image format.")
                    return redirect(url_for("worker_issue_new", module=module))

                original_name = secure_filename(photo.filename)
                unique_name = f"{uuid4().hex}.jpg"

                upload_dir = os.path.join(app.static_folder, "uploads", "issues", str(iss.id))
                os.makedirs(upload_dir, exist_ok=True)

                abs_path = os.path.join(upload_dir, unique_name)
                save_optimized_image(photo, abs_path, max_size=(1600, 1600), quality=82)

                rel_path = f"uploads/issues/{iss.id}/{unique_name}"
                db.add(IssuePhoto(
                    issue_id=iss.id,
                    filename=original_name,
                    file_path=rel_path,
                    uploaded_by=getattr(user, "id", None),
                ))
                db.commit()

            send_telegram_message(
                f"⚠️ New issue reported\n"
                f"{title}\n"
                f"{TASKMANAGER_URL}admin/issues"
            )
            flash("Issue reported.")
            return redirect(url_for("worker_home", module=module))

        return render_template(
            "worker_issue_new.html",
            title="Report issue",
            locations=locations,
            active_tab="issues",
            active_module=(request.args.get("module") or "all").lower(),
        )

    finally:
        db.close()

@app.get("/worker/settings")
@cf_required
def worker_settings():
    # samo placeholder da url_for radi
    return render_template(
        "worker_settings.html",
        title="Settings",
        active_tab="settings",
        active_module=(request.args.get("module") or "all").lower(),
    )

# -------- Admin: Issues --------
@app.get("/admin/issues")
@admin_required
def admin_issues():
    db = SessionLocal()
    try:
        issues = db.query(Issue).order_by(Issue.created_at.desc()).limit(200).all()
        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}
        issue_ids = [i.id for i in issues]
        photo_rows = (
            db.query(IssuePhoto)
            .filter(IssuePhoto.issue_id.in_(issue_ids))
            .order_by(IssuePhoto.created_at.desc())
            .all()
        ) if issue_ids else []
        latest_photo_by_issue = {}
        for p in photo_rows:
            if p.issue_id not in latest_photo_by_issue:
                latest_photo_by_issue[p.issue_id] = p.file_path
        return render_template(
            "admin_issues.html",
            title="Issues",
            issues=issues,
            locations=locations,
            users=users,
            latest_photo_by_issue=latest_photo_by_issue,
        )
    finally:
        db.close()


@app.post("/admin/issues/<int:issue_id>/status")
@admin_required
def admin_issue_set_status(issue_id: int):
    new_status = request.form.get("status") or "open"
    allowed = {"open", "ack", "in_progress", "resolved"}
    if new_status not in allowed:
        flash("Invalid status.")
        return redirect(url_for("admin_issues"))

    db = SessionLocal()
    try:
        iss = db.get(Issue, issue_id)
        if not iss:
            flash("Issue not found.")
            return redirect(url_for("admin_issues"))

        iss.status = new_status
        db.commit()
        flash(f"Issue #{iss.id} status → {new_status}")
        return redirect(url_for("admin_issues"))
    finally:
        db.close()

@app.post("/admin/issues/<int:issue_id>/done")
@cf_required
def admin_issue_done(issue_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    if getattr(user, "role", "") != "admin":
        abort(403)

    db = SessionLocal()
    try:
        issue = db.get(Issue, issue_id)
        if not issue:
            abort(404)

        issue.status = "resolved"
        db.commit()
        return redirect(url_for("admin_issues"))
    finally:
        db.close()

@app.post("/admin/issues/<int:issue_id>/convert")
@admin_required
def admin_issue_convert_to_task(issue_id: int):
    db = SessionLocal()
    try:
        issue = db.get(Issue, issue_id)
        print("DEBUG issue:", issue_id)

        if not issue:
            print("DEBUG: issue not found")
            flash("Issue not found.")
            return redirect(url_for("admin_issues"))

        print("DEBUG linked_task_id:", issue.linked_task_id)
        print("DEBUG location_id:", issue.location_id)
        print("DEBUG status:", issue.status)
        print("DEBUG title:", issue.title)

        if issue.linked_task_id:
            print("DEBUG: already linked")
            flash(f"Issue #{issue.id} is already linked to task #{issue.linked_task_id}.")
            return redirect(url_for("admin_issues"))

        if not issue.location_id:
            print("DEBUG: missing location")
            flash("Issue must have a location before converting to task.")
            return redirect(url_for("admin_issues"))

        issue_notes = (issue.notes or "").strip()

        notes_parts = [f"Created from issue #{issue.id}"]

        if issue.category:
            notes_parts.append(f"Category: {issue.category}")

        if issue.severity:
            notes_parts.append(f"Severity: {issue.severity}")

        if issue_notes:
            notes_parts.append("")
            notes_parts.append(issue_notes)

        if issue.photos:
            notes_parts.append("")
            notes_parts.append(f"Issue has {len(issue.photos)} photo(s).")

        task = Task(
            title=issue.title.strip(),
            module=issue.module,
            status="open",
            task_date=date.today(),
            next_action_date=date.today(),
            location_id=issue.location_id,
            notes="\n".join(notes_parts).strip(),
        )

        db.add(task)
        db.flush()

        print("DEBUG created task id:", task.id)

        issue.linked_task_id = task.id

        if issue.status == "open":
            issue.status = "ack"

        db.commit()
        print("DEBUG: commit success")

        flash(f"Issue #{issue.id} converted to task #{task.id}.")
        return redirect(url_for("admin_tasks"))

    except Exception as e:
        db.rollback()
        print("DEBUG EXCEPTION:", repr(e))
        flash(f"Convert failed: {e}")
        return redirect(url_for("admin_issues"))
    finally:
        db.close()

@app.post("/admin/issues/<int:issue_id>/set-location")
@admin_required
def admin_issue_set_location(issue_id: int):
    location_id = request.form.get("location_id", type=int)

    db = SessionLocal()
    try:
        issue = db.get(Issue, issue_id)
        if not issue:
            flash("Issue not found.")
            return redirect(url_for("admin_issues"))

        if not location_id:
            flash("Please select a location.")
            return redirect(url_for("admin_issues"))

        loc = db.get(Location, location_id)
        if not loc:
            flash("Invalid location.")
            return redirect(url_for("admin_issues"))

        issue.location_id = location_id
        db.commit()

        flash(f"Issue #{issue.id} location updated.")
        return redirect(url_for("admin_issues"))
    finally:
        db.close()

@app.post("/worker/task/<int:task_id>/next_day")
@cf_required
def worker_task_next_day(task_id):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all")
    today = date.today()
    now = datetime.utcnow()

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(url_for("worker_dashboard", module=module))

        if not is_task_allowed_for_worker(db, t, user):
            flash("Not allowed.")
            return redirect(url_for("worker_dashboard", module=module))

        moved_to_date = today + timedelta(days=1)
        t.task_date = moved_to_date
        t.next_action_date = moved_to_date

        if t.status == "in_progress":
            t.status = "open"
            finish_task_work_session(db, t.id, user.id, finished_at=now, create_fallback=False)
        if t.notes:
            if "[carryover]" not in t.notes.lower():
                t.notes = f"[Carryover] {t.notes}"
        else:
            t.notes = "[Carryover]"

        db.commit()
        flash("Task moved to next day.")
        return redirect(url_for("worker_dashboard", module=module))
    finally:
        db.close()


@app.post("/worker/task/<int:task_id>/back_today")
@cf_required
def worker_task_back_today(task_id):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all")
    today = date.today()

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(url_for("worker_dashboard", module=module))

        if not is_task_allowed_for_worker(db, t, user):
            flash("Not allowed.")
            return redirect(url_for("worker_dashboard", module=module))

        if t.status == "done":
            flash("Task already done.")
            return redirect(url_for("worker_dashboard", module=module))

        t.task_date = today
        t.next_action_date = today
        db.commit()
        notify_task_assignees(db, t, label="moved to today")
        flash("Task returned to today.")
        return redirect(url_for("worker_dashboard", module=module))
    finally:
        db.close()

@app.post("/worker/task/<int:task_id>/photo")
@cf_required
def worker_task_add_photo(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = request.form.get("module") or "all"
    view = request.form.get("view") or "today"
    default_url = url_for("worker_today", module=module, view=view)

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(default_url)

        if not is_task_allowed_for_worker(db, t, user):
            flash("You are not allowed to add photos to this task.")
            return redirect(default_url)

        f = request.files.get("photo")
        if not f or not f.filename:
            flash("No photo selected.")
            return redirect(default_url)

        if not allowed_image_file(f.filename):
            flash("Unsupported image format.")
            return redirect(default_url)

        db.add(save_task_photo_upload(
            task_id,
            f,
            uploaded_by=getattr(user, "id", None),
            convert_to_jpeg=False,
        ))
        db.commit()

        flash("Photo uploaded.")
        return redirect(default_url)

    finally:
        db.close()

@app.post("/admin/tasks/<int:task_id>/assign")
@admin_required
def admin_task_assign(task_id: int):
    db = SessionLocal()
    try:
        user_id = int(request.form.get("user_id"))

        # spriječi duplikate
        exists = db.query(TaskAssignee).filter_by(
            task_id=task_id,
            user_id=user_id
        ).first()

        if not exists:
            db.add(TaskAssignee(task_id=task_id, user_id=user_id))

        db.commit()
        task = db.get(Task, task_id)
        if task:
            notify_task_users(db, task, [user_id], label="assigned")

        return redirect_back()

    finally:
        db.close()


@app.post("/admin/tasks/batch/done")
@admin_required
def admin_tasks_batch_done():
    db = SessionLocal()
    try:
        task_ids = get_task_ids_from_request()
        if not task_ids:
            return redirect_back()

        now = datetime.utcnow()
        rows = db.query(Task).filter(Task.id.in_(task_ids)).all()
        for task in rows:
            task.status = "done"
            if not task.started_at:
                task.started_at = now
            task.finished_at = now

        finish_active_sessions_for_tasks(db, task_ids, finished_at=now)
        db.commit()

        send_telegram_message(
            f"✅ {len(task_ids)} tasks completed in TaskManager.\n{TASKMANAGER_URL}"
        )

        return redirect_back()
    finally:
        db.close()

@app.post("/admin/tasks/batch/assign")
@admin_required
def admin_tasks_batch_assign():
    db = SessionLocal()
    try:
        task_ids = get_task_ids_from_request()
        user_id = request.form.get("user_id")

        if not task_ids or not user_id:
            return redirect_back()

        user_id = int(user_id)

        # insert if not exists
        existing = set(
            (r.task_id for r in db.query(TaskAssignee)
             .filter(TaskAssignee.user_id == user_id,
                     TaskAssignee.task_id.in_(task_ids))
             .all())
        )

        for tid in task_ids:
            if tid not in existing:
                db.add(TaskAssignee(task_id=tid, user_id=user_id))

        db.commit()
        tasks = db.query(Task).filter(Task.id.in_(task_ids)).all()
        for task in tasks:
            notify_task_users(db, task, [user_id], label="assigned")
        return redirect_back()
    finally:
        db.close()

@app.post("/admin/tasks/batch/next_day")
@admin_required
def admin_tasks_batch_next_day():
    db = SessionLocal()
    try:
        task_ids = get_task_ids_from_request()
        if not task_ids:
            return redirect_back()
        rows = db.query(Task).filter(Task.id.in_(task_ids)).all()

        for t in rows:
            if t.status == "done":
                continue
            moved_to_date = None
            if t.task_date:
                moved_to_date = t.task_date + timedelta(days=1)
                t.task_date = moved_to_date
            elif t.next_action_date:
                moved_to_date = t.next_action_date + timedelta(days=1)

            # Worker dashboard groups tasks by next_action_date, so keep both
            # dates aligned when admin intentionally pushes a task forward.
            if moved_to_date:
                t.next_action_date = moved_to_date


        db.commit()
        for t in rows:
            if t.status == "done":
                continue
            notify_task_assignees(db, t, label="rescheduled")
        return redirect_back()
    finally:
        db.close()


@app.post("/admin/task/<int:task_id>/move_to_today")
@admin_required
def admin_task_move_to_today(task_id: int):
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if not task:
            flash("Task not found.")
            return redirect_back()

        today = date.today()
        task.is_todo = False
        task.task_date = today
        task.next_action_date = today

        db.commit()
        notify_task_assignees(db, task, label="moved to today")
        flash("Task moved to today.")
        return redirect_back()
    finally:
        db.close()


@app.post("/admin/task/<int:task_id>/schedule")
@admin_required
def admin_task_schedule(task_id: int):
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if not task:
            flash("Task not found.")
            return redirect_back()

        schedule_date_raw = (request.form.get("schedule_date") or "").strip()
        if not schedule_date_raw:
            flash("Schedule date is required.")
            return redirect_back()

        y, m, d = schedule_date_raw.split("-")
        scheduled_for = date(int(y), int(m), int(d))

        task.is_todo = False
        task.task_date = scheduled_for
        task.next_action_date = scheduled_for

        db.commit()
        notify_task_assignees(db, task, label="scheduled")
        flash("Task scheduled.")
        return redirect_back()
    finally:
        db.close()


@app.post("/admin/tasks/batch/block")
@admin_required
def admin_tasks_batch_block():
    db = SessionLocal()
    try:
        task_ids = get_task_ids_from_request()
        if not task_ids:
            return redirect_back()
        db.query(Task).filter(
            Task.id.in_(task_ids),
            Task.status != "done"
            ).update({Task.status: "blocked"}, synchronize_session=False)

        db.commit()
        return redirect_back()
    finally:
        db.close()

@app.route("/admin/observations/new", methods=["GET", "POST"])
@cf_required
@admin_required
def admin_observation_new():
    db = SessionLocal()
    try:
        worker_users = (
            db.query(User)
            .filter(User.is_active == True, User.role == "worker")
            .order_by(User.username.asc())
            .all()
        )
        users = worker_users
        user_picker_mode = "workers"

        if not users:
            users = (
                db.query(User)
                .filter(User.is_active == True)
                .order_by(User.username.asc())
                .all()
            )
            user_picker_mode = "all_active"

        locations = (
            db.query(Location)
            .filter(Location.is_active == True)
            .order_by(Location.module.asc(), Location.name.asc())
            .all()
        )

        if request.method == "POST":
            app.logger.info(
                "Observation create POST received method=%s form_keys=%s file_keys=%s content_length=%s",
                request.method,
                sorted(request.form.keys()),
                sorted(request.files.keys()),
                request.content_length,
            )
            try:
                note = (request.form.get("note") or "").strip()
                module = (request.form.get("module") or "").strip() or None
                loc_raw = (request.form.get("location_id") or "").strip()
                assigned_raw_values = request.form.getlist("assigned_user_ids")
                assigned_user_ids = []
                for value in assigned_raw_values:
                    value = (value or "").strip()
                    if value.isdigit():
                        user_id = int(value)
                        if user_id not in assigned_user_ids:
                            assigned_user_ids.append(user_id)

                location_id = int(loc_raw) if loc_raw.isdigit() else None
                assigned_user_id = assigned_user_ids[0] if assigned_user_ids else None
                photo_uploads = [
                    photo for photo in request.files.getlist("photos")
                    if photo and photo.filename
                ]

                app.logger.info(
                    "Observation create parsed worker_ids=%s worker_count=%s photo_count=%s photo_names=%s photo_content_types=%s location_id=%s",
                    assigned_user_ids,
                    len(assigned_user_ids),
                    len(photo_uploads),
                    [photo.filename for photo in photo_uploads],
                    [getattr(photo, "content_type", None) for photo in photo_uploads],
                    location_id,
                )

                if not note:
                    app.logger.warning("Observation create validation failed: missing note")
                    flash("Observation note is required.")
                    return render_template(
                        "admin_observation_new.html",
                        title="New observation",
                        users=users,
                        user_picker_mode=user_picker_mode,
                        locations=locations,
                    )

                if not assigned_user_ids:
                    app.logger.warning("Observation create validation failed: no workers selected")
                    flash("Please select at least one worker.")
                    return render_template(
                        "admin_observation_new.html",
                        title="New observation",
                        users=users,
                        user_picker_mode=user_picker_mode,
                        locations=locations,
                    )

                invalid_photo = next(
                    (photo.filename for photo in photo_uploads if not allowed_image_file(photo.filename)),
                    None,
                )
                if invalid_photo:
                    app.logger.warning(
                        "Observation create validation failed: unsupported photo=%s",
                        invalid_photo,
                    )
                    flash("Image format not supported. Please use JPG or PNG.")
                    return render_template(
                        "admin_observation_new.html",
                        title="New observation",
                        users=users,
                        user_picker_mode=user_picker_mode,
                        locations=locations,
                    )

                current_user = request.cf_user  # type: ignore[attr-defined]
                obs = Observation(
                    note=note,
                    module=module,
                    location_id=location_id,
                    assigned_user_id=assigned_user_id,
                    created_by_user_id=current_user.id if current_user else None,
                    photo_path=None,
                    is_read=False,
                    status="new",
                )

                app.logger.info(
                    "Observation create before db.add assigned_user_id=%s created_by=%s",
                    assigned_user_id,
                    current_user.id if current_user else None,
                )
                db.add(obs)
                app.logger.info("Observation create before db.flush")
                db.flush()
                app.logger.info("Observation create after db.flush observation_id=%s", obs.id)

                assigned_users = (
                    db.query(User)
                    .filter(User.id.in_(assigned_user_ids))
                    .all()
                ) if assigned_user_ids else []
                obs.assigned_users = assigned_users
                app.logger.info(
                    "Observation create resolved assigned_users=%s",
                    [user.id for user in assigned_users],
                )

                if photo_uploads:
                    photo_rows = []
                    for photo in photo_uploads:
                        app.logger.info(
                            "Observation create saving photo filename=%s content_type=%s",
                            photo.filename,
                            getattr(photo, "content_type", None),
                        )
                        photo_row = save_observation_photo_upload(
                            obs.id,
                            photo,
                            uploaded_by=current_user.id if current_user else None,
                        )
                        photo_rows.append(photo_row)
                        db.add(photo_row)
                    if photo_rows:
                        obs.photo_path = f"/static/{photo_rows[0].file_path}"

                app.logger.info("Observation create before db.commit observation_id=%s", obs.id)
                db.commit()
                app.logger.info("Observation create committed observation_id=%s", obs.id)

                location = db.get(Location, location_id) if location_id else None
                location_text = f"\nLocation: {location.name}" if location else ""
                for assigned_user in assigned_users:
                    send_user_telegram_message(
                        assigned_user,
                        (
                            f"New observation\n"
                            f"{note}{location_text}\n"
                            f"{TASKMANAGER_URL}worker/observations"
                        ),
                    )

                flash("Observation created.")
                return redirect(url_for("admin_tasks"))
            except Exception as exc:
                db.rollback()
                app.logger.exception(
                    "Observation create failed form_keys=%s file_keys=%s",
                    sorted(request.form.keys()),
                    sorted(request.files.keys()),
                )
                error_message = "Observation could not be saved. Please try again."
                if isinstance(exc, ValueError):
                    error_message = str(exc)
                elif is_dev_auth_bypass_enabled():
                    error_message = f"{error_message} ({type(exc).__name__}: {exc})"
                flash(error_message)
                return render_template(
                    "admin_observation_new.html",
                    title="New observation",
                    users=users,
                    user_picker_mode=user_picker_mode,
                    locations=locations,
                )

        return render_template(
            "admin_observation_new.html",
            title="New observation",
            users=users,
            user_picker_mode=user_picker_mode,
            locations=locations,
        )

    finally:
        db.close()

@app.route("/worker/observations")
@cf_required
def worker_observations():
    db = SessionLocal()
    try:
        current_user = request.cf_user  # type: ignore[attr-defined]

        observation_ids = [
            row.id
            for row in (
                db.query(Observation.id)
                .filter(
                    or_(
                        Observation.assigned_user_id == current_user.id,
                        Observation.assigned_users.any(User.id == current_user.id),
                    )
                )
                .all()
            )
        ]

        if observation_ids:
            db.query(Observation).filter(
                Observation.id.in_(observation_ids),
                Observation.is_read == False,
            ).update({Observation.is_read: True}, synchronize_session=False)
            db.commit()

        observations = (
            db.query(Observation)
            .filter(Observation.id.in_(observation_ids))
            .order_by(Observation.created_at.desc())
            .all()
        ) if observation_ids else []

        unread_count = get_worker_unread_observation_count(db, current_user.id)

        return render_template(
            "worker_observations.html",
            title="Observations",
            observations=observations,
            unread_count=unread_count,
            active_tab="observations",
        )
    finally:
        db.close()

@app.post("/admin/tasks/batch/unblock")
@admin_required
def admin_tasks_batch_unblock():
    db = SessionLocal()
    try:
        task_ids = get_task_ids_from_request()
        if not task_ids:
            return redirect_back()
        db.query(Task).filter(
            Task.id.in_(task_ids),
            Task.status != "done"
            ).update({Task.status: "open"}, synchronize_session=False)

        db.commit()
        return redirect_back()
    finally:
        db.close()

@app.post("/admin/tasks/<int:task_id>/delete")
@admin_required
def admin_task_delete(task_id: int):
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if not task:
            flash("Task not found.")
            return redirect_back()

        task_photos = db.query(TaskPhoto).filter(TaskPhoto.task_id == task_id).all()
        for photo in task_photos:
            file_path = (photo.file_path or "").strip()
            if file_path:
                abs_path = os.path.join(app.static_folder, file_path)
                if os.path.exists(abs_path):
                    try:
                        os.remove(abs_path)
                    except OSError:
                        pass

        db.query(TaskAssignee).filter(TaskAssignee.task_id == task_id).delete(synchronize_session=False)
        db.query(TaskWorkSession).filter(TaskWorkSession.task_id == task_id).delete(synchronize_session=False)
        db.query(TaskPhoto).filter(TaskPhoto.task_id == task_id).delete(synchronize_session=False)
        db.query(ResidenceBlock).filter(ResidenceBlock.task_id == task_id).delete(synchronize_session=False)
        db.query(Issue).filter(Issue.linked_task_id == task_id).update(
            {Issue.linked_task_id: None},
            synchronize_session=False,
        )
        db.query(Task).filter(Task.carryover_from_task_id == task_id).update(
            {Task.carryover_from_task_id: None},
            synchronize_session=False,
        )

        db.delete(task)
        db.commit()

        flash("Task deleted.")
        return redirect_back()
    finally:
        db.close()

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash("Image is too large. Please choose a smaller photo.")
    if request.path == url_for("admin_observation_new"):
        return redirect(url_for("admin_observation_new"))
    return redirect(request.referrer or url_for("worker_dashboard"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

