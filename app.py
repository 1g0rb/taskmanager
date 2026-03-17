# app.py
from __future__ import annotations
import os
from ipaddress import ip_address, ip_network
from uuid import uuid4
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
from functools import wraps
import secrets
from sqlalchemy.exc import IntegrityError
from types import SimpleNamespace
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Date, or_, text, case
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy import select
from sqlalchemy.orm import relationship
from werkzeug.exceptions import RequestEntityTooLarge
from PIL import Image, ImageOps
import requests
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
    "8723576715:AAFztHilx8IGlIwTibaK9Pg2YGZpZcp0YYQ"
).strip()

TELEGRAM_ADMIN_CHAT_ID = os.environ.get(
    "TELEGRAM_ADMIN_CHAT_ID",
    "8603880940"
).strip()

TASKMANAGER_URL = "https://task.ordoapps.app/"
TASK_URL = TASKMANAGER_URL + "admin/tasks"
TASK_URL = TASKMANAGER_URL + "worker/dashboard"

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

ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "heic"}

def allowed_image_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

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

def ensure_user_column_display_name():
    with engine.begin() as conn:
        cols = conn.execute(text("PRAGMA table_info(users)")).fetchall()
        names = {c[1] for c in cols}
        if "display_name" not in names:
            conn.execute(text("ALTER TABLE users ADD COLUMN display_name VARCHAR"))
            print("✅ Added column: users.display_name")

Base.metadata.create_all(engine)
ensure_task_column_carryover()
ensure_user_column_display_name()

# ---------------- App ----------------
app = Flask(__name__)
app.secret_key = "dev-change-me"  # kasnije prebaci u ENV
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024

# ---------------- Cloudflare Access auth ----------------
CF_EMAIL_HEADER = "Cf-Access-Authenticated-User-Email"
CF_NAME_HEADER  = "Cf-Access-Authenticated-User-Name"

# Admin emailovi (spusti na lower-case!)
ADMIN_EMAILS = {
    "bozicorama@gmail.com",
}
DEV_BYPASS = os.environ.get("DEV_BYPASS", "").lower() in ("1", "true", "yes")


def redirect_back(default="admin_tasks"):
    next_url = request.args.get("next") or request.form.get("next")
    if next_url:
        return redirect(next_url)
    return redirect(url_for(default))


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
            )
        }

    # kad nema auth (npr. /health ili 401 slučajevi)
    return {"current_user": SimpleNamespace(is_authenticated=False, role="worker", username="")}

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


def get_current_user_or_dev(db: Session) -> User | None:
    # normalno: Cloudflare Access user
    user = get_current_user(db)
    if user:
        return user

    # DEV/LAN bypass: ako je lokalni request ili ako je DEV_BYPASS upaljen
    if DEV_BYPASS or is_local_request():
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
            # role iz baze ili allowlist
            is_admin = (user.role == "admin") or (user.username.lower() in ADMIN_EMAILS)
            if not is_admin:
                flash("Admin access required.")
                return redirect(url_for("index"))
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


def is_task_allowed_for_worker(db, task: Task, user: User) -> bool:
    if user.role == "admin" or user.username.lower() in ADMIN_EMAILS:
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
    True if request is coming from localhost/LAN (dev/local testing).
    Works both with and without reverse proxy.
    """
    # 1) direct remote addr
    ra = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not ra:
        ra = request.remote_addr or ""

    try:
        ip = ip_address(ra)
    except ValueError:
        return False

    # localhost + private ranges
    if ip.is_loopback:
        return True

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
def test_telegram():
    token_ok = test_telegram_bot_token()
    sent_ok = send_telegram_message(
        f"✅ Test poruka iz TaskManagera.\n{TASKMANAGER_URL}"
    )
    return f"Token OK: {token_ok} | Telegram sent: {sent_ok}"

# ---------------- Health ----------------
@app.get("/health")
def health():
    return "ok", 200


@app.get("/")
def index():
    db = SessionLocal()
    try:
        user = get_current_user_or_dev(db)
        if not user:
            # ovo pusti Cloudflareu da odradi login
            return redirect("/cdn-cgi/access/login")

        is_admin = (user.role == "admin") or (user.username.lower() in ADMIN_EMAILS)
        if is_admin:
            return redirect(url_for("admin_tasks"))

        return redirect(url_for("worker_home"))
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

        # LOAD TASKS
        tasks = db.query(Task).all()

        # SMART SORT (command center order)
        def task_sort_key(t):
            d = str(t.task_date) if t.task_date else "9999-99-99"

            if t.status == "done":
                return (3, d)
            if d < today:
                return (0, d)
            if d == today:
                return (1, d)
            return (2, d)

        tasks = sorted(tasks, key=task_sort_key)[:200]

        # LOOKUPS
        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}

        rows = db.query(TaskAssignee).all()
        task_to_user_ids = {}
        for r in rows:
            task_to_user_ids.setdefault(r.task_id, []).append(r.user_id)
        all_ids = [t.id for t in tasks if t.id]
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
                linked_issue_photo_by_task_id[task_id] = iss.photos[0].file_path
        
        # FILTER PARAM
        flt = request.args.get("filter", "all")

        # URGENT STRIP
        urgent_tasks = [
            t for t in tasks
            if t.status != "done" and t.task_date and str(t.task_date) <= today
        ][:4]

        # COUNTS
        counts = {
            "today": sum(1 for t in tasks if (t.task_date and str(t.task_date) == today and t.status != "done")),
            "unfinished": sum(1 for t in tasks if (t.task_date and str(t.task_date) < today and t.status != "done")),
            "upcoming": sum(1 for t in tasks if (t.task_date and str(t.task_date) > today and t.status != "done")),
            "done": sum(1 for t in tasks if t.status == "done"),
        }

        # FILTER LIST
        filtered_tasks = tasks
        if flt == "today":
            filtered_tasks = [t for t in tasks if (t.task_date and str(t.task_date) == today)]
        elif flt == "unfinished":
            filtered_tasks = [t for t in tasks if (t.task_date and str(t.task_date) < today and t.status != "done")]
        elif flt == "open":
            filtered_tasks = [t for t in tasks if t.status == "open"]
        elif flt == "done":
            filtered_tasks = [t for t in tasks if t.status == "done"]
        elif flt == "upcoming":
            filtered_tasks = [t for t in tasks if (t.task_date and str(t.task_date) > today and t.status != "done")]

        # GROUPING
        groups = {"unfinished": [], "today": [], "upcoming": [], "done": []}

        for t in filtered_tasks:
            if t.status == "done":
                groups["done"].append(t)
                continue

            if not t.task_date:
                groups["upcoming"].append(t)
                continue

            d = str(t.task_date)
            if d < today:
                groups["unfinished"].append(t)
            elif d == today:
                groups["today"].append(t)
            else:
                groups["upcoming"].append(t)

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
                linked_issue_photo_by_task_id[task_id] = iss.photos[0].file_path

        return render_template(
            "admin_tasks.html",
            title="Tasks",
            tasks=tasks,
            users=users,
            locations=locations,
            task_to_user_ids=task_to_user_ids,
            counts=counts,
            flt=flt,
            groups=groups,
            today=today,
            urgent_tasks=urgent_tasks,
            issue_by_task_id=issue_by_task_id,
            linked_issue_photo_by_task_id=linked_issue_photo_by_task_id,
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
    if role not in ("admin", "worker"):
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
            if task_date_raw:
                y, m, d = task_date_raw.split("-")
                task_date_val = date(int(y), int(m), int(d))
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
                status="open",
            )
            db.add(t)
            db.commit()

            # OPTIONAL REFERENCE PHOTO
            photo = request.files.get("photo")
            if photo and photo.filename:
                if not allowed_image_file(photo.filename):
                    flash("Unsupported image format.")
                    return redirect(url_for("admin_task_new"))

                original_name = secure_filename(photo.filename)
                unique_name = f"{uuid4().hex}.jpg"

                upload_dir = os.path.join(app.static_folder, "uploads", "tasks", str(t.id))
                os.makedirs(upload_dir, exist_ok=True)

                abs_path = os.path.join(upload_dir, unique_name)

                img = Image.open(photo)
                img = ImageOps.exif_transpose(img)

                if img.mode in ("RGBA", "P"):
                    img = img.convert("RGB")
                elif img.mode != "RGB":
                    img = img.convert("RGB")

                img.thumbnail((1600, 1600))
                img.save(abs_path, "JPEG", quality=82, optimize=True)

                rel_path = f"uploads/tasks/{t.id}/{unique_name}"

                db.add(TaskPhoto(
                    task_id=t.id,
                    filename=original_name,
                    file_path=rel_path,
                    uploaded_by=getattr(request.cf_user, "id", None),
                ))
                db.commit()

            # ASSIGN WORKERS
            for uid in assigned_ids:
                db.add(TaskAssignee(task_id=t.id, user_id=uid))

            db.commit()

            # TELEGRAM NOTIFICATION
                       
            print("ADMIN_TASK_NEW: TASK SAVED, BEFORE TELEGRAM")

            telegram_ok = send_telegram_message(
                f"🆕 New task created\n"
                f"{title}\n"
                f"{TASKMANAGER_URL}admin/tasks#{t.id}"
            )
            print("ADMIN_TASK_NEW: TELEGRAM RESULT =", telegram_ok)
            flash("Task created.")
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
    user = request.cf_user  # type: ignore[attr-defined]

    today = date.today()
    until = today + timedelta(days=7)
    today_iso = today.isoformat()

    active_module, module_filter = parse_module_arg()

    db = SessionLocal()
    try:
        def apply_module(q):
            return q.filter(Task.module == module_filter) if module_filter else q

        status_rank = case(
            (Task.status == "in_progress", 0),
            (Task.status == "open", 1),
            (Task.status == "blocked", 2),
            else_=3
        )

        overdue_q = db.query(Task).filter(
            Task.task_date < today,
            Task.status != "done",
            Task.next_action_date <= today
        )
        overdue_q = apply_module(overdue_q)
        overdue_q = filter_my_and_unassigned(db, overdue_q, user)
        overdue_tasks = overdue_q.order_by(
            status_rank.asc(),
            Task.task_date.asc(),
            Task.id.asc()
        ).all()

        today_q = db.query(Task).filter(
            Task.next_action_date == today,
            Task.status != "done"
        )
        today_q = apply_module(today_q)
        today_q = filter_my_and_unassigned(db, today_q, user)
        today_tasks = today_q.order_by(
            status_rank.asc(),
            Task.id.desc()
        ).all()

        upcoming_q = db.query(Task).filter(
            Task.next_action_date > today,
            Task.next_action_date <= until,
            Task.status != "done"
        )
        upcoming_q = apply_module(upcoming_q)
        upcoming_q = filter_my_and_unassigned(db, upcoming_q, user)
        upcoming_tasks = upcoming_q.order_by(
            Task.next_action_date.asc(),
            status_rank.asc(),
            Task.id.asc()
        ).all()

        today_pretty = today.strftime("%A, %B %d, %Y")

        return render_template(
            "worker_home.html",
            title="Worker Home",
            body_class="worker",
            today_pretty=today_pretty,
            overdue_tasks=overdue_tasks,
            today_tasks=today_tasks,
            upcoming_tasks=upcoming_tasks,
            active_module=active_module,
            today=today_iso,
            until=until.isoformat(),
            active_tab="home",
        )
    finally:
        db.close()
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
        def apply_module(q):
            return q.filter(Task.module == module_filter) if module_filter else q

        status_rank = case(
            (Task.status == "in_progress", 0),
            (Task.status == "open", 1),
            (Task.status == "blocked", 2),
            else_=3
        )

        overdue_q = db.query(Task).filter(
            Task.task_date < today,
            Task.status != "done",
            Task.next_action_date <= today
        )
        overdue_q = apply_module(overdue_q)
        overdue_q = filter_my_and_unassigned(db, overdue_q, user)
        overdue_tasks = overdue_q.order_by(
            status_rank.asc(),
            Task.task_date.asc(),
            Task.id.asc()
        ).all()

        today_q = db.query(Task).filter(
            Task.next_action_date == today,
            Task.status != "done"
        )
        today_q = apply_module(today_q)
        today_q = filter_my_and_unassigned(db, today_q, user)
        today_tasks = today_q.order_by(
            status_rank.asc(),
            Task.id.desc()
        ).all()

        upcoming_q = db.query(Task).filter(
            Task.next_action_date > today,
            Task.next_action_date <= until,
            Task.status != "done"
        )
        upcoming_q = apply_module(upcoming_q)
        upcoming_q = filter_my_and_unassigned(db, upcoming_q, user)
        upcoming_tasks = upcoming_q.order_by(
            Task.next_action_date.asc(),
            status_rank.asc(),
            Task.id.asc()
        ).all()

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
        if view == "today":
            overdue_tasks = []
            upcoming_tasks = []
        elif view == "unfinished":
            today_tasks = []
            upcoming_tasks = []
        elif view == "upcoming":
            overdue_tasks = []
            today_tasks = []
        today_pretty = today.strftime("%A, %B %d, %Y")

        return render_template(
            "worker_dashboard.html",
            title="My tasks",
            body_class="worker",
            today_pretty=today_pretty,
            overdue_tasks=overdue_tasks,
            today_tasks=today_tasks,
            upcoming_tasks=upcoming_tasks,
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
            view=view,
        )
    finally:
        db.close()
def safe_next_url(default: str):
    # next dolazi iz POST forme (hidden input)
    nxt = (request.form.get("next") or "").strip()
    if not nxt:
        return default

    # dozvoli samo relative URL (npr. /worker/today?...), zabrani http://...
    p = urlparse(nxt)
    if p.scheme or p.netloc:
        return default

    # minimalna zaštita: mora početi s /
    if not nxt.startswith("/"):
        return default

    return nxt

# -------- Worker actions --------
@app.post("/worker/task/<int:task_id>/start")
@cf_required
def worker_task_start(task_id: int):
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

        t.status = "in_progress"
        if not t.started_at:
            t.started_at = datetime.utcnow()

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

        if getattr(t, "carryover_from_task_id", None):
            orig_id = t.carryover_from_task_id
            res_id = t.location_id

            db.query(ResidenceBlock).filter(
                ResidenceBlock.task_id == orig_id,
                ResidenceBlock.residence_id == res_id
            ).delete(synchronize_session=False)

            t.status = "done"
            if not t.started_at:
                t.started_at = datetime.utcnow()
            t.finished_at = datetime.utcnow()

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
                task_date=today,
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
            t.started_at = datetime.utcnow()
        t.finished_at = datetime.utcnow()

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
        t.blocked_at = datetime.utcnow()
        t.blocked_location_id = None

        if not t.started_at:
            t.started_at = datetime.utcnow()
        t.finished_at = None

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

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(url_for("worker_dashboard", module=module))

        if not is_task_allowed_for_worker(db, t, user):
            flash("Not allowed.")
            return redirect(url_for("worker_dashboard", module=module))

        t.next_action_date = today + timedelta(days=1)

        if t.status == "in_progress":
            t.status = "open"
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

        t.next_action_date = today
        db.commit()
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

        original_name = secure_filename(f.filename)
        ext = original_name.rsplit(".", 1)[1].lower()
        unique_name = f"{uuid4().hex}.{ext}"

        upload_dir = os.path.join(app.static_folder, "uploads", "tasks", str(task_id))
        os.makedirs(upload_dir, exist_ok=True)

        abs_path = os.path.join(upload_dir, unique_name)
        f.save(abs_path)

        rel_path = f"uploads/tasks/{task_id}/{unique_name}"

        db.add(TaskPhoto(
            task_id=task_id,
            filename=original_name,
            file_path=rel_path,
            uploaded_by=getattr(user, "id", None)
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

        return redirect_back()

    finally:
        db.close()


@app.post("/admin/tasks/batch/done")
@admin_required
def admin_tasks_batch_done():
    db = SessionLocal()
    try:
        ids = request.form.getlist("task_ids")
        if not ids:
            return redirect_back()

        task_ids = [int(x) for x in ids]

        db.query(Task).filter(Task.id.in_(task_ids)).update(
            {Task.status: "done"},
            synchronize_session=False
        )
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
        ids = request.form.getlist("task_ids")
        user_id = request.form.get("user_id")

        if not ids or not user_id:
            return redirect_back()

        task_ids = [int(x) for x in ids]
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
        return redirect_back()
    finally:
        db.close()

@app.post("/admin/tasks/batch/next_day")
@admin_required
def admin_tasks_batch_next_day():
    db = SessionLocal()
    try:
        ids = request.form.getlist("task_ids")
        if not ids:
            return redirect_back()

        task_ids = [int(x) for x in ids]
        rows = db.query(Task).filter(Task.id.in_(task_ids)).all()

        for t in rows:
            if t.status == "done":
                continue
            if t.task_date:
                t.task_date = t.task_date + timedelta(days=1)


        db.commit()
        return redirect_back()
    finally:
        db.close()

@app.post("/admin/tasks/batch/block")
@admin_required
def admin_tasks_batch_block():
    db = SessionLocal()
    try:
        ids = request.form.getlist("task_ids")
        if not ids:
            return redirect_back()

        task_ids = [int(x) for x in ids]
        db.query(Task).filter(
            Task.id.in_(task_ids),
            Task.status != "done"
            ).update({Task.status: "blocked"}, synchronize_session=False)

        db.commit()
        return redirect_back()
    finally:
        db.close()

@app.post("/admin/tasks/batch/unblock")
@admin_required
def admin_tasks_batch_unblock():
    db = SessionLocal()
    try:
        ids = request.form.getlist("task_ids")
        if not ids:
            return redirect_back()


        task_ids = [int(x) for x in ids]
        db.query(Task).filter(
            Task.id.in_(task_ids),
            Task.status != "done"
            ).update({Task.status: "open"}, synchronize_session=False)

        db.commit()
        return redirect_back()
    finally:
        db.close()
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash("Image too large. Maximum size is 6MB.")
    return redirect(request.referrer or url_for("worker_today"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
