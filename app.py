# app.py
from __future__ import annotations

from datetime import datetime, date, timedelta
from functools import wraps
import secrets
from types import SimpleNamespace
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from werkzeug.security import generate_password_hash

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Date, or_, text, case
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy import select

# ---------------- DB ----------------
engine = create_engine("sqlite:///taskmanager.db", echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)  # koristimo kao email
    password_hash = Column(String, nullable=False)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)

    role = Column(String, default="worker")  # admin/worker
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


def ensure_task_column_carryover():
    with engine.begin() as conn:
        cols = conn.execute(text("PRAGMA table_info(tasks)")).fetchall()
        names = {c[1] for c in cols}
        if "carryover_from_task_id" not in names:
            conn.execute(text("ALTER TABLE tasks ADD COLUMN carryover_from_task_id INTEGER"))
            print("✅ Added column: tasks.carryover_from_task_id")


Base.metadata.create_all(engine)
ensure_task_column_carryover()

# ---------------- App ----------------
app = Flask(__name__)
app.secret_key = "dev-change-me"  # kasnije prebaci u ENV

# ---------------- Cloudflare Access auth ----------------
CF_EMAIL_HEADER = "Cf-Access-Authenticated-User-Email"

# Admin emailovi (spusti na lower-case!)
ADMIN_EMAILS = {
    "bozicorama@gmail.com",
}


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


def get_current_user(db) -> User | None:
    email = get_cf_email()
    if not email:
        return None

    user = db.query(User).filter(User.username == email).first()

    # AUTO-CREATE user if missing (Cloudflare Access already authenticated)
    if not user:
        role = "admin" if email in {e.lower() for e in ADMIN_EMAILS} else "worker"
        user = User(
            username=email,
            password_hash=_random_password_hash(),  # dummy
            role=role,
            lang="en",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        return None

    # If email is admin but user role isn't, allowlist still grants admin access elsewhere
    return user


def get_current_user_or_dev(db) -> User | None:
    """
    In production: require Cloudflare Access email header.
    In local debug: allow auto-login as first active admin (for UI work).
    """
    user = get_current_user(db)
    if user:
        return user

    # DEV BYPASS (only when Flask debug is ON)
    if app.debug:
        dev_user = db.query(User).filter(User.role == "admin", User.is_active == True).first()
        return dev_user

    return None


def cf_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        db = SessionLocal()
        try:
            user = get_current_user_or_dev(db)
            if not user:
                # Ako Access nije prošao ili user ne postoji u bazi:
                abort(401)
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
    """
    IMPORTANT:
    Cloudflare auth koristi email. Ovaj seed je samo fallback.
    Preporuka: napravi user record u bazi s pravim emailom.
    """
    db = SessionLocal()
    try:
        exists = db.query(User).first()
        if not exists:
            # napravi admin user koji ćeš kasnije zamijeniti emailom
            u = User(
                username="admin@example.com",
                password_hash=_random_password_hash(),
                role="admin",
                lang="en",
                is_active=True
            )
            db.add(u)
            db.commit()
            print("Seeded default admin: admin@example.com (CHANGE THIS TO YOUR EMAIL!)")
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


# ---------------- Health ----------------
@app.get("/health")
def health():
    return "ok", 200


# ---------------- Routes ----------------
@app.get("/")
@cf_required
def index():
    user = request.cf_user  # type: ignore[attr-defined]
    is_admin = (user.role == "admin") or (user.username.lower() in ADMIN_EMAILS)
    if is_admin:
        return redirect_back()
    return redirect_back("worker_dashboard")


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
                return (3, d)  # done last
            if d < today:
                return (0, d)  # overdue first
            if d == today:
                return (1, d)  # today
            return (2, d)      # future

        tasks = sorted(tasks, key=task_sort_key)[:200]

        # LOOKUPS
        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}

        rows = db.query(TaskAssignee).all()
        task_to_user_ids = {}
        for r in rows:
            task_to_user_ids.setdefault(r.task_id, []).append(r.user_id)

        # FILTER PARAM
        flt = request.args.get("filter", "all")

        # URGENT STRIP (always from unfiltered sorted list)
        urgent_tasks = [
            t for t in tasks
            if t.status != "done" and t.task_date and str(t.task_date) <= today
        ][:4]

        # COUNTS (from unfiltered list)
        counts = {
            "today": sum(1 for t in tasks if (t.task_date and str(t.task_date) == today)),
            "overdue": sum(1 for t in tasks if (t.task_date and str(t.task_date) < today and t.status != "done")),
            "open": sum(1 for t in tasks if t.status == "open"),
            "done": sum(1 for t in tasks if t.status == "done"),
        }

        # FILTER LIST (what we display)
        filtered_tasks = tasks
        if flt == "today":
            filtered_tasks = [t for t in tasks if (t.task_date and str(t.task_date) == today)]
        elif flt == "overdue":
            filtered_tasks = [t for t in tasks if (t.task_date and str(t.task_date) < today and t.status != "done")]
        elif flt == "open":
            filtered_tasks = [t for t in tasks if t.status == "open"]
        elif flt == "done":
            filtered_tasks = [t for t in tasks if t.status == "done"]
        elif flt == "upcoming":
            filtered_tasks = [t for t in tasks if (t.task_date and str(t.task_date) > today and t.status != "done")]

        # GROUPING (based on filtered list)
        groups = {"overdue": [], "today": [], "upcoming": [], "done": []}

        for t in filtered_tasks:
            if t.status == "done":
                groups["done"].append(t)
                continue

            if not t.task_date:
                groups["upcoming"].append(t)
                continue

            d = str(t.task_date)
            if d < today:
                groups["overdue"].append(t)
            elif d == today:
                groups["today"].append(t)
            else:
                groups["upcoming"].append(t)

        return render_template(
            "admin_tasks.html",
            title="Tasks",
            tasks=filtered_tasks,
            groups=groups,
            locations=locations,
            users=users,
            task_to_user_ids=task_to_user_ids,
            counts=counts,
            flt=flt,
            urgent_tasks=urgent_tasks,
            today=today,
        )
    finally:
        db.close()




@app.get("/admin/users")
@admin_required
def admin_users():
    # privremeno: dok ne implementiramo Users page
    return redirect_back()



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

            for uid in assigned_ids:
                db.add(TaskAssignee(task_id=t.id, user_id=uid))
            db.commit()

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


# -------- Worker dashboard --------
@app.get("/worker/today")
@cf_required
def worker_today():
    user = request.cf_user  # type: ignore[attr-defined]

    today = date.today()
    until = today + timedelta(days=7)
    active_module, module_filter = parse_module_arg()

    db = SessionLocal()
    try:
        # ---------------- AUTO-UNBLOCK ----------------
        expired_date_tasks = db.query(Task).filter(
            Task.status == "blocked",
            Task.blocked_until != None,
            Task.blocked_until <= today
        ).all()

        for t in expired_date_tasks:
            t.status = "open"
            t.blocked_reason = None
            t.blocked_until = None
            t.blocked_at = None

        rain_tasks = db.query(Task).filter(
            Task.status == "blocked",
            Task.blocked_until.is_(None),
            Task.blocked_at.is_not(None),
            Task.blocked_reason.is_not(None)
        ).all()

        for t in rain_tasks:
            r = (t.blocked_reason or "").strip().lower()
            is_rain = ("rain" in r) or ("kisa" in r) or ("kiša" in r)
            if is_rain and t.blocked_at.date() < today:
                t.status = "open"
                t.blocked_reason = None
                t.blocked_until = None
                t.blocked_at = None

        db.commit()

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
        overdue_tasks = overdue_q.order_by(status_rank.asc(), Task.task_date.asc(), Task.id.asc()).all()

        today_q = db.query(Task).filter(
            Task.next_action_date == today,
            Task.status != "done"
        )
        today_q = apply_module(today_q)
        today_q = filter_my_and_unassigned(db, today_q, user)
        today_tasks = today_q.order_by(status_rank.asc(), Task.id.desc()).all()

        upcoming_q = db.query(Task).filter(
            Task.next_action_date > today,
            Task.next_action_date <= until,
            Task.status != "done"
        )
        upcoming_q = apply_module(upcoming_q)
        upcoming_q = filter_my_and_unassigned(db, upcoming_q, user)
        upcoming_tasks = upcoming_q.order_by(Task.next_action_date.asc(), status_rank.asc(), Task.id.asc()).all()

        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}

        residences_by_parent = {}
        units = db.query(Location).filter(
            Location.kind == "unit",
            Location.is_active == True
        ).order_by(Location.name.asc()).all()

        for u in units:
            residences_by_parent.setdefault(u.parent_id, []).append(u)

        all_ids = [t.id for t in overdue_tasks] + [t.id for t in today_tasks] + [t.id for t in upcoming_tasks]

        blocks = db.query(ResidenceBlock).filter(
            ResidenceBlock.task_id.in_(all_ids)
        ).order_by(ResidenceBlock.created_at.desc()).all() if all_ids else []

        blocks_by_task = {}
        for b in blocks:
            blocks_by_task.setdefault(b.task_id, []).append(b)

        rows = db.query(TaskAssignee).filter(TaskAssignee.task_id.in_(all_ids)).all() if all_ids else []
        task_to_user_ids = {}
        for r in rows:
            task_to_user_ids.setdefault(r.task_id, []).append(r.user_id)

        return render_template(
            "worker_today.html",
            title="My tasks",
            overdue_tasks=overdue_tasks,
            today_tasks=today_tasks,
            upcoming_tasks=upcoming_tasks,
            locations=locations,
            users=users,
            residences_by_parent=residences_by_parent,
            blocks_by_task=blocks_by_task,
            task_to_user_ids=task_to_user_ids,
            active_module=active_module,
            today=today,
            until=until
            

        )
    finally:
        db.close()


@app.get("/worker/dashboard")
@cf_required
def worker_dashboard():
    user = request.cf_user  # type: ignore[attr-defined]

    today = date.today()
    until = today + timedelta(days=7)
    active_module, module_filter = parse_module_arg()

    db = SessionLocal()
    try:
        # isto kao worker_today: upiti
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
        overdue_tasks = overdue_q.order_by(status_rank.asc(), Task.task_date.asc(), Task.id.asc()).all()

        today_q = db.query(Task).filter(
            Task.next_action_date == today,
            Task.status != "done"
        )
        today_q = apply_module(today_q)
        today_q = filter_my_and_unassigned(db, today_q, user)
        today_tasks = today_q.order_by(status_rank.asc(), Task.id.desc()).all()

        upcoming_q = db.query(Task).filter(
            Task.next_action_date > today,
            Task.next_action_date <= until,
            Task.status != "done"
        )
        upcoming_q = apply_module(upcoming_q)
        upcoming_q = filter_my_and_unassigned(db, upcoming_q, user)
        upcoming_tasks = upcoming_q.order_by(Task.next_action_date.asc(), status_rank.asc(), Task.id.asc()).all()

        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}

        all_ids = [t.id for t in overdue_tasks] + [t.id for t in today_tasks] + [t.id for t in upcoming_tasks]
        rows = db.query(TaskAssignee).filter(TaskAssignee.task_id.in_(all_ids)).all() if all_ids else []
        task_to_user_ids = {}
        for r in rows:
            task_to_user_ids.setdefault(r.task_id, []).append(r.user_id)

        # residences_by_parent treba zbog Block forme u "More"
        residences_by_parent = {}
        units = db.query(Location).filter(Location.kind == "unit", Location.is_active == True).order_by(Location.name.asc()).all()
        for u in units:
            residences_by_parent.setdefault(u.parent_id, []).append(u)

        today_pretty = today.strftime("%A, %B %d, %Y")  # Friday, February 6, 2026

        return render_template(
            "worker_dashboard.html",
            title="Worker dashboard",
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
            until=until
        )
    finally:
        db.close()


# -------- Worker actions --------
@app.post("/worker/task/<int:task_id>/start")
@cf_required
def worker_task_start(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()

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

        if t.status == "blocked":
            t.blocked_reason = None
            t.blocked_until = None
            t.blocked_at = None
            t.blocked_location_id = None

        t.status = "in_progress"
        if not t.started_at:
            t.started_at = datetime.utcnow()

        db.commit()
        return redirect(url_for("worker_dashboard", module=module))
    finally:
        db.close()


@app.post("/worker/task/<int:task_id>/done")
@cf_required
def worker_task_done(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()
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
            return redirect(url_for("worker_dashboard", module=module))

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
            db.query(ResidenceBlock).filter(ResidenceBlock.task_id == t.id).delete(synchronize_session=False)

        t.status = "done"
        if not t.started_at:
            t.started_at = datetime.utcnow()
        t.finished_at = datetime.utcnow()

        t.blocked_reason = None
        t.blocked_until = None
        t.blocked_at = None
        t.blocked_location_id = None

        db.commit()
        return redirect(url_for("worker_dashboard", module=module))
    finally:
        db.close()


@app.post("/worker/task/<int:task_id>/blocked")
@cf_required
def worker_task_blocked(task_id: int):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all").lower()
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
            return redirect(url_for("worker_dashboard", module=module))

        if not is_task_allowed_for_worker(db, t, user):
            flash("Not allowed.")
            return redirect(url_for("worker_dashboard", module=module))

        if not reason:
            flash("Blocked reason is required.")
            return redirect(url_for("worker_dashboard", module=module))

        if blocked_location_id:
            db.add(ResidenceBlock(
                task_id=t.id,
                residence_id=blocked_location_id,
                reason=reason,
                until_date=blocked_until,
                created_by=user.id
            ))
            db.commit()
            return redirect(url_for("worker_dashboard", module=module))

        t.status = "blocked"
        t.blocked_reason = reason
        t.blocked_until = blocked_until
        t.blocked_at = datetime.utcnow()
        t.blocked_location_id = None

        if not t.started_at:
            t.started_at = datetime.utcnow()
        t.finished_at = None

        db.commit()
        return redirect(url_for("worker_dashboard", module=module))
    finally:
        db.close()


@app.post("/worker/task/<int:task_id>/unblock")
@cf_required
def worker_task_unblock(task_id):
    user = request.cf_user  # type: ignore[attr-defined]
    module = (request.args.get("module") or "all")

    db = SessionLocal()
    try:
        t = db.get(Task, task_id)
        if not t:
            flash("Task not found.")
            return redirect(url_for("worker_dashboard", module=module))

        # permission
        is_admin = (user.role == "admin") or (user.username.lower() in ADMIN_EMAILS)
        if not is_admin:
            assigned_user_ids = [r.user_id for r in db.query(TaskAssignee).filter(TaskAssignee.task_id == t.id).all()]
            if assigned_user_ids and (user.id not in assigned_user_ids):
                flash("Not allowed.")
                return redirect(url_for("worker_dashboard", module=module))

        t.status = "open"
        t.blocked_reason = None
        t.blocked_until = None
        t.blocked_at = None
        t.finished_at = None
        db.commit()

        flash("Task unblocked.")
        return redirect(url_for("worker_dashboard", module=module))
    finally:
        db.close()


# -------- Worker: Issues --------
@app.route("/worker/issues/new", methods=["GET", "POST"])
@cf_required
def worker_issue_new():
    user = request.cf_user  # type: ignore[attr-defined]
    db = SessionLocal()
    try:
        locations = db.query(Location).filter(Location.is_active == True).order_by(
            Location.module.asc(), Location.name.asc()
        ).all()

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            category = request.form.get("category") or "equipment"
            severity = request.form.get("severity") or "low"
            module = request.form.get("module") or "horticulture"
            notes = (request.form.get("notes") or "").strip()
            loc_raw = request.form.get("location_id") or ""
            location_id = int(loc_raw) if loc_raw else None

            if not title:
                flash("Title is required.")
                return render_template("worker_issue_new.html", title="Report issue", locations=locations)

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
            flash("Issue reported.")
            return redirect_back("worker_today")

        return render_template("worker_issue_new.html", title="Report issue", locations=locations)
    finally:
        db.close()


# -------- Admin: Issues --------
@app.get("/admin/issues")
@admin_required
def admin_issues():
    db = SessionLocal()
    try:
        issues = db.query(Issue).order_by(Issue.created_at.desc()).limit(200).all()
        locations = {l.id: l for l in db.query(Location).all()}
        users = {u.id: u for u in db.query(User).all()}
        return render_template("admin_issues.html", title="Issues", issues=issues, locations=locations, users=users)
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
        db.query(Task).filter(Task.id.in_(task_ids)).update(
            {Task.status: "blocked"},
            synchronize_session=False
        )
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
        db.query(Task).filter(Task.id.in_(task_ids)).update(
            {Task.status: "open"},
            synchronize_session=False
        )
        db.commit()
        return redirect_back()
    finally:
        db.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
