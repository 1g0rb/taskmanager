from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta


def _collect_manager_task_data(
    db,
    *,
    Task,
    TaskAssignee,
    User,
    Location,
    Issue,
    get_task_schedule_date,
    TaskWorkSession=None,
    today: date | None = None,
):
    today_value = today or date.today()
    upcoming_until = today_value + timedelta(days=7)
    recent_window_start = today_value - timedelta(days=6)

    tasks = (
        db.query(Task)
        .filter(Task.is_todo == False)  # noqa: E712
        .order_by(Task.task_date.asc(), Task.created_at.desc())
        .all()
    )

    task_ids = [task.id for task in tasks if getattr(task, "id", None)]
    locations = {row.id: row for row in db.query(Location).all()}
    active_work_session_task_ids = set()
    if TaskWorkSession is not None and task_ids:
        active_work_session_task_ids = {
            task_id
            for (task_id,) in (
                db.query(TaskWorkSession.task_id)
                .filter(
                    TaskWorkSession.task_id.in_(task_ids),
                    TaskWorkSession.status == "active",
                    TaskWorkSession.finished_at.is_(None),
                )
                .distinct()
                .all()
            )
        }

    assignee_rows = (
        db.query(TaskAssignee)
        .filter(TaskAssignee.task_id.in_(task_ids))
        .all()
        if task_ids
        else []
    )
    assignees_by_task_id = defaultdict(list)
    user_ids = set()
    for row in assignee_rows:
        assignees_by_task_id[row.task_id].append(row.user_id)
        user_ids.add(row.user_id)

    for task in tasks:
        legacy_user_id = getattr(task, "assigned_to", None)
        if legacy_user_id:
            user_ids.add(legacy_user_id)

    users = (
        {
            row.id: row
            for row in db.query(User).filter(User.id.in_(user_ids)).all()
        }
        if user_ids
        else {}
    )

    linked_issues = (
        db.query(Issue)
        .filter(Issue.linked_task_id.in_(task_ids))
        .order_by(Issue.created_at.desc())
        .all()
        if task_ids
        else []
    )
    issue_by_task_id = {}
    for issue in linked_issues:
        linked_task_id = getattr(issue, "linked_task_id", None)
        if linked_task_id and linked_task_id not in issue_by_task_id:
            issue_by_task_id[linked_task_id] = issue

    def display_user_name(user) -> str:
        if not user:
            return "Unassigned"
        return ((getattr(user, "display_name", None) or getattr(user, "username", "")).split("@")[0]).strip()

    def compute_priority(task) -> str:
        issue = issue_by_task_id.get(task.id)
        severity = ((getattr(issue, "severity", None) or "")).strip().lower()
        if severity == "high":
            return "urgent"
        if severity == "medium":
            return "high"
        if severity == "low":
            return "low"
        return "normal"

    def is_done(task) -> bool:
        return (getattr(task, "status", "") or "").strip().lower() == "done"

    def is_blocked(task) -> bool:
        return (getattr(task, "status", "") or "").strip().lower() == "blocked"

    def has_active_work_session(task) -> bool:
        return getattr(task, "id", None) in active_work_session_task_ids

    def manager_workflow_status(task) -> str:
        # Manager dashboard status is mutually exclusive:
        # done and blocked win first; in_progress requires an active/open work session.
        if is_done(task):
            return "done"
        if is_blocked(task):
            return "blocked"
        if has_active_work_session(task):
            return "in_progress"
        return "open"

    def is_in_progress(task) -> bool:
        status = (getattr(task, "status", "") or "").strip().lower()
        return status == "in_progress"

    def completed_on(task) -> date | None:
        finished_at = getattr(task, "finished_at", None)
        if not finished_at:
            return None
        return finished_at.date() if hasattr(finished_at, "date") else None

    def short_description(task) -> str | None:
        notes = (getattr(task, "notes", None) or "").strip()
        if not notes:
            return None
        return notes if len(notes) <= 160 else f"{notes[:157].rstrip()}..."

    def task_sort_key(item: dict) -> tuple:
        raw_date = item.get("_schedule_date")
        schedule_key = raw_date or date.max
        status_weight = {"blocked": 0, "in_progress": 1, "open": 2, "done": 3}.get(
            item.get("workflow_status", item["status"]),
            9,
        )
        return (schedule_key, status_weight, item["title"].lower(), item["id"])

    def completion_sort_key(item: dict) -> tuple:
        completion = item.get("completed_at") or datetime.min
        return (completion, item["title"].lower(), item["id"])

    def prepare_task(task) -> dict:
        schedule_date = get_task_schedule_date(task)
        location = locations.get(getattr(task, "location_id", None))
        explicit_assignees = [users.get(user_id) for user_id in assignees_by_task_id.get(task.id, [])]
        assignee_names = [display_user_name(user) for user in explicit_assignees if user]
        if not assignee_names and getattr(task, "assigned_to", None):
            assignee_names = [display_user_name(users.get(task.assigned_to))]

        item = {
            "id": task.id,
            "title": task.title,
            "short_description": short_description(task),
            "location_name": getattr(location, "name", "Unknown location"),
            "assigned_user_display_names": assignee_names,
            "status": (getattr(task, "status", "open") or "open").strip().lower(),
            "workflow_status": manager_workflow_status(task),
            "has_active_work_session": has_active_work_session(task),
            "priority": compute_priority(task),
            "created_at": getattr(task, "created_at", None),
            "scheduled_date": schedule_date,
            "started_at": getattr(task, "started_at", None),
            "completed_at": getattr(task, "finished_at", None),
            "days_overdue": None,
            "_schedule_date": schedule_date,
        }
        if schedule_date and schedule_date < today_value and not is_done(task):
            item["days_overdue"] = (today_value - schedule_date).days
        return item

    prepared_tasks = [prepare_task(task) for task in tasks]

    today_tasks = []
    aging_tasks = []
    upcoming_tasks = []
    completed_today = []
    completed_task_items = []
    recent_completed_tasks = []
    open_task_items = []
    in_progress_tasks = []
    blocked_tasks = []
    urgent_tasks = []

    status_counter = Counter()
    priority_counter = Counter()
    completion_counter = Counter()
    location_summary = defaultdict(
        lambda: {
            "location_name": "Unknown location",
            "open": 0,
            "unfinished": 0,
            "blocked": 0,
            "done_recent": 0,
        }
    )

    for task, item in zip(tasks, prepared_tasks):
        schedule_date = item["_schedule_date"]
        completion_date = completed_on(task)
        done_today = completion_date == today_value
        aging = bool(schedule_date and schedule_date < today_value and not is_done(task))
        due_today = bool(schedule_date == today_value and not is_done(task))
        upcoming = bool(schedule_date and today_value < schedule_date <= upcoming_until and not is_done(task))
        completed_recently = bool(completion_date and recent_window_start <= completion_date <= today_value)
        workflow_status = item["workflow_status"]

        location_row = location_summary[getattr(task, "location_id", None)]
        location_row["location_name"] = item["location_name"]

        if not is_done(task):
            open_task_items.append(item)
            status_counter[workflow_status] += 1
            priority_counter[item["priority"]] += 1
            location_row["open"] += 1
            if aging:
                location_row["unfinished"] += 1
            if workflow_status == "in_progress":
                in_progress_tasks.append(item)
            if workflow_status == "blocked":
                blocked_tasks.append(item)
                location_row["blocked"] += 1
            if item["priority"] == "urgent":
                urgent_tasks.append(item)

        if due_today:
            today_tasks.append(item)
        if aging:
            aging_tasks.append(item)
        if upcoming:
            upcoming_tasks.append(item)
        if is_done(task):
            completed_task_items.append(item)
        if done_today:
            completed_today.append(item)
        if completed_recently:
            recent_completed_tasks.append(item)
            completion_counter[completion_date] += 1
            location_row["done_recent"] += 1

    location_items = []
    for location_id, summary in location_summary.items():
        score = (summary["unfinished"] * 3) + (summary["blocked"] * 2) + summary["open"] + summary["done_recent"]
        if summary["open"] or summary["unfinished"] or summary["blocked"] or summary["done_recent"]:
            location_items.append(
                {
                    "location_id": location_id,
                    "location_name": summary["location_name"],
                    "open_count": summary["open"],
                    "unfinished_count": summary["unfinished"],
                    "aging_count": summary["unfinished"],
                    "blocked_count": summary["blocked"],
                    "done_recent_count": summary["done_recent"],
                    "activity_score": score,
                }
            )

    location_items.sort(
        key=lambda item: (
            -item["activity_score"],
            -item["unfinished_count"],
            -item["blocked_count"],
            -item["open_count"],
            -item["done_recent_count"],
            item["location_name"].lower(),
        )
    )

    status_order = ["open", "in_progress", "blocked", "done"]
    status_labels = {
        "open": "Open",
        "in_progress": "In Progress",
        "blocked": "Blocked",
        "done": "Done Today",
    }
    status_summary = []
    status_snapshot = dict(status_counter)
    status_snapshot["done"] = len(completed_today)
    for key in status_order:
        status_summary.append({"key": key, "label": status_labels[key], "count": status_snapshot.get(key, 0)})

    priority_order = ["urgent", "high", "normal", "low"]
    priority_labels = {
        "urgent": "Urgent",
        "high": "High",
        "normal": "Normal",
        "low": "Low",
    }
    priority_summary = [
        {"key": key, "label": priority_labels[key], "count": priority_counter.get(key, 0)}
        for key in priority_order
    ]

    kpis = [
        {"key": "today", "label": "Today Tasks", "value": len(today_tasks)},
        {"key": "in_progress", "label": "In Progress", "value": len(in_progress_tasks)},
        {"key": "blocked", "label": "Blocked Issues", "value": len(blocked_tasks)},
        {"key": "done_today", "label": "Done Today", "value": len(completed_today)},
        {"key": "urgent", "label": "Urgent", "value": len(urgent_tasks)},
        {"key": "upcoming", "label": "Upcoming", "value": len(upcoming_tasks)},
    ]

    completion_trend = []
    trend_max = 1
    for day_offset in range(6, -1, -1):
        trend_day = today_value - timedelta(days=day_offset)
        count = completion_counter.get(trend_day, 0)
        completion_trend.append(
            {
                "date": trend_day,
                "date_label": trend_day.strftime("%d %b"),
                "weekday_label": trend_day.strftime("%a"),
                "count": count,
            }
        )
        trend_max = max(trend_max, count)

    return {
        "generated_at": datetime.now(),
        "today": today_value,
        "today_tasks": sorted(today_tasks, key=task_sort_key),
        "overdue_tasks": sorted(aging_tasks, key=task_sort_key),
        "aging_tasks": sorted(aging_tasks, key=task_sort_key),
        "unfinished_tasks": sorted(aging_tasks, key=task_sort_key),
        "upcoming_tasks": sorted(upcoming_tasks, key=task_sort_key),
        "in_progress_tasks": sorted(in_progress_tasks, key=task_sort_key),
        "blocked_tasks": sorted(blocked_tasks, key=task_sort_key),
        "urgent_tasks": sorted(urgent_tasks, key=task_sort_key),
        "status_summary": status_summary,
        "priority_summary": priority_summary,
        "location_summary": location_items[:8],
        "done_today_tasks": sorted(completed_today, key=completion_sort_key, reverse=True),
        "recent_completions_today": sorted(completed_today, key=completion_sort_key, reverse=True)[:8],
        "completed_tasks": sorted(completed_task_items, key=completion_sort_key, reverse=True),
        "recent_completed_tasks": sorted(recent_completed_tasks, key=completion_sort_key, reverse=True)[:10],
        "completion_trend": completion_trend,
        "completion_trend_max": trend_max,
        "kpis": kpis,
        "open_tasks": sorted(open_task_items, key=task_sort_key),
        "open_task_count": len(open_task_items),
        "aging_count": len(aging_tasks),
        "unfinished_count": len(aging_tasks),
        "in_progress_count": len(in_progress_tasks),
        "blocked_count": len(blocked_tasks),
        "done_today_count": len(completed_today),
        "done_last_7_days_count": len(recent_completed_tasks),
        "active_locations_count": len(location_items),
    }


def build_manager_dashboard_data(
    db,
    *,
    Task,
    TaskAssignee,
    User,
    Location,
    Issue,
    get_task_schedule_date,
    TaskWorkSession=None,
    today: date | None = None,
):
    base = _collect_manager_task_data(
        db,
        Task=Task,
        TaskAssignee=TaskAssignee,
        User=User,
        Location=Location,
        Issue=Issue,
        get_task_schedule_date=get_task_schedule_date,
        TaskWorkSession=TaskWorkSession,
        today=today,
    )
    return {
        "generated_at": base["generated_at"],
        "today": base["today"],
        "kpis": base["kpis"],
        "today_tasks": base["today_tasks"],
        "overdue_tasks": base["overdue_tasks"],
        "upcoming_tasks": base["upcoming_tasks"],
        "status_summary": base["status_summary"],
        "priority_summary": base["priority_summary"],
        "location_summary": base["location_summary"],
        "recent_completions_today": base["recent_completions_today"],
        "operational_status": _build_operational_status(base["aging_count"], base["blocked_count"]),
        "key_problems": _build_key_problems(base["open_tasks"]),
    }


def build_manager_reports_data(
    db,
    *,
    Task,
    TaskAssignee,
    User,
    Location,
    Issue,
    get_task_schedule_date,
    TaskWorkSession=None,
    today: date | None = None,
):
    base = _collect_manager_task_data(
        db,
        Task=Task,
        TaskAssignee=TaskAssignee,
        User=User,
        Location=Location,
        Issue=Issue,
        get_task_schedule_date=get_task_schedule_date,
        TaskWorkSession=TaskWorkSession,
        today=today,
    )
    return {
        "generated_at": base["generated_at"],
        "today": base["today"],
        "report_kpis": [
            {"key": "open", "label": "Open Tasks", "value": base["open_task_count"]},
            {"key": "aging", "label": "Aging", "value": base["aging_count"]},
            {"key": "blocked", "label": "Blocked", "value": base["blocked_count"]},
            {"key": "done_today", "label": "Done Today", "value": base["done_today_count"]},
            {"key": "done_last_7_days", "label": "Done Last 7 Days", "value": base["done_last_7_days_count"]},
            {"key": "active_locations", "label": "Active Locations", "value": base["active_locations_count"]},
        ],
        "completion_trend": base["completion_trend"],
        "completion_trend_max": base["completion_trend_max"],
        "location_performance": base["location_summary"],
        "status_summary": base["status_summary"],
        "priority_summary": base["priority_summary"],
        "recent_completed_tasks": base["recent_completed_tasks"],
    }


def build_manager_done_tasks_data(
    db,
    *,
    Task,
    TaskAssignee,
    User,
    Location,
    Issue,
    get_task_schedule_date,
    TaskWorkSession=None,
    today: date | None = None,
):
    base = _collect_manager_task_data(
        db,
        Task=Task,
        TaskAssignee=TaskAssignee,
        User=User,
        Location=Location,
        Issue=Issue,
        get_task_schedule_date=get_task_schedule_date,
        TaskWorkSession=TaskWorkSession,
        today=today,
    )

    grouped = defaultdict(list)
    for task in base["completed_tasks"]:
        completed_at = task.get("completed_at")
        completed_date = completed_at.date() if completed_at and hasattr(completed_at, "date") else None
        if not completed_date:
            continue

        duration_minutes = None
        started_at = task.get("started_at")
        if started_at and completed_at:
            delta = completed_at - started_at
            duration_minutes = max(0, int(delta.total_seconds() // 60))

        grouped[completed_date].append(
            {
                **task,
                "completed_date": completed_date,
                "completed_date_label": completed_date.strftime("%A, %d %b %Y"),
                "completed_time_label": completed_at.strftime("%H:%M") if hasattr(completed_at, "strftime") else None,
                "duration_minutes": duration_minutes,
            }
        )

    grouped_items = []
    for completed_date in sorted(grouped.keys(), reverse=True):
        items = sorted(
            grouped[completed_date],
            key=lambda item: item.get("completed_at") or datetime.min,
            reverse=True,
        )
        grouped_items.append(
            {
                "date": completed_date,
                "date_label": completed_date.strftime("%A, %d %b %Y"),
                "count": len(items),
                "tasks": items,
            }
        )

    return {
        "generated_at": base["generated_at"],
        "today": base["today"],
        "done_task_groups": grouped_items,
        "done_task_count": sum(group["count"] for group in grouped_items),
    }


def build_manager_unfinished_tasks_data(
    db,
    *,
    Task,
    TaskAssignee,
    User,
    Location,
    Issue,
    get_task_schedule_date,
    TaskWorkSession=None,
    today: date | None = None,
):
    base = _collect_manager_task_data(
        db,
        Task=Task,
        TaskAssignee=TaskAssignee,
        User=User,
        Location=Location,
        Issue=Issue,
        get_task_schedule_date=get_task_schedule_date,
        TaskWorkSession=TaskWorkSession,
        today=today,
    )

    return {
        "generated_at": base["generated_at"],
        "today": base["today"],
        "unfinished_tasks": base["open_tasks"],
        "unfinished_task_count": base["open_task_count"],
    }


def build_manager_tasks_list_data(
    db,
    *,
    Task,
    TaskAssignee,
    User,
    Location,
    Issue,
    get_task_schedule_date,
    filter_key: str = "today",
    TaskWorkSession=None,
    today: date | None = None,
):
    base = _collect_manager_task_data(
        db,
        Task=Task,
        TaskAssignee=TaskAssignee,
        User=User,
        Location=Location,
        Issue=Issue,
        get_task_schedule_date=get_task_schedule_date,
        TaskWorkSession=TaskWorkSession,
        today=today,
    )

    filter_config = {
        "today": {
            "title": "Today Tasks",
            "label": "Today",
            "tasks": base["today_tasks"],
        },
        "unfinished": {
            "title": "Aging Tasks",
            "label": "Aging",
            "tasks": base["aging_tasks"],
        },
        "aging": {
            "title": "Aging Tasks",
            "label": "Aging",
            "tasks": base["aging_tasks"],
        },
        "in_progress": {
            "title": "In Progress Tasks",
            "label": "In Progress",
            "tasks": base["in_progress_tasks"],
        },
        "blocked": {
            "title": "Blocked Issues",
            "label": "Blocked",
            "tasks": base["blocked_tasks"],
        },
        "done_today": {
            "title": "Done Today",
            "label": "Done Today",
            "tasks": base["done_today_tasks"],
        },
        "urgent": {
            "title": "Urgent Tasks",
            "label": "Urgent",
            "tasks": base["urgent_tasks"],
        },
        "upcoming": {
            "title": "Upcoming Tasks",
            "label": "Upcoming",
            "tasks": base["upcoming_tasks"],
        },
    }

    active_filter = filter_key if filter_key in filter_config else "today"
    active_config = filter_config[active_filter]

    return {
        "generated_at": base["generated_at"],
        "today": base["today"],
        "active_filter": active_filter,
        "active_filter_label": active_config["label"],
        "page_title": active_config["title"],
        "tasks": active_config["tasks"],
        "task_count": len(active_config["tasks"]),
    }


def _build_operational_status(aging_count: int, blocked_count: int) -> dict:
    if blocked_count >= 2 or aging_count >= 8:
        label = "Critical attention"
        tone = "critical"
    elif blocked_count >= 1 or aging_count >= 4:
        label = "Needs attention"
        tone = "attention"
    else:
        label = "Under control"
        tone = "control"

    fragments = []
    if blocked_count:
        fragments.append(f"{blocked_count} blocked task{'s' if blocked_count != 1 else ''}")
    if aging_count:
        fragments.append(f"{aging_count} aging task{'s' if aging_count != 1 else ''}")

    if fragments:
        message = f"{label} · {' and '.join(fragments)} need review"
    else:
        message = f"{label} · no immediate operational risks are visible"

    return {"label": label, "tone": tone, "message": message}


def _build_key_problems(open_tasks: list[dict]) -> list[dict]:
    candidates = []
    for item in open_tasks:
        is_blocked = item.get("workflow_status") == "blocked"
        is_urgent = item.get("priority") == "urgent"
        is_high_priority = item.get("priority") == "high"
        is_aging = item.get("days_overdue") is not None
        if not (is_blocked or is_urgent or is_high_priority or is_aging):
            continue

        candidates.append(
            {
                **item,
                "_blocked_rank": 0 if is_blocked else 1,
                "_priority_rank": 0 if is_urgent else (1 if is_high_priority else 2),
                "_aging_rank": -(item.get("days_overdue") or 0),
            }
        )

    candidates.sort(
        key=lambda item: (
            item["_blocked_rank"],
            item["_priority_rank"],
            item["_aging_rank"],
            item["title"].lower(),
            item["id"],
        )
    )

    key_problems = []
    for item in candidates[:3]:
        problem_note = None
        if item.get("workflow_status") == "blocked":
            if item.get("days_overdue"):
                problem_note = f"Blocked - {item['days_overdue']}d aging"
            else:
                problem_note = "Blocked"
        elif item.get("priority") == "urgent":
            problem_note = "Urgent"
        elif item.get("priority") == "high":
            problem_note = "High priority"
        elif item.get("days_overdue"):
            problem_note = f"{item['days_overdue']}d aging"

        key_problems.append(
            {
                "id": item["id"],
                "title": item["title"],
                "location_name": item["location_name"],
                "assigned_user_display_names": item.get("assigned_user_display_names", []),
                "status": item.get("workflow_status", item["status"]),
                "priority": item["priority"],
                "problem_note": problem_note,
            }
        )

    return key_problems
