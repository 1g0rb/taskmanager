from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta


def build_manager_dashboard_data(
    db,
    *,
    Task,
    TaskAssignee,
    User,
    Location,
    Issue,
    get_task_schedule_date,
    today: date | None = None,
):
    today_value = today or date.today()
    upcoming_until = today_value + timedelta(days=7)

    tasks = (
        db.query(Task)
        .filter(Task.is_todo == False)  # noqa: E712
        .order_by(Task.task_date.asc(), Task.created_at.desc())
        .all()
    )

    task_ids = [task.id for task in tasks if getattr(task, "id", None)]
    locations = {
        row.id: row
        for row in db.query(Location).all()
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

    users = {
        row.id: row
        for row in db.query(User).filter(User.id.in_(user_ids)).all()
    } if user_ids else {}

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

    def is_in_progress(task) -> bool:
        status = (getattr(task, "status", "") or "").strip().lower()
        return status == "in_progress" or (bool(getattr(task, "started_at", None)) and not is_done(task))

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
        status_weight = {"blocked": 0, "in_progress": 1, "open": 2, "done": 3}.get(item["status"], 9)
        return (schedule_key, status_weight, item["title"].lower(), item["id"])

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
            "priority": compute_priority(task),
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
    overdue_tasks = []
    upcoming_tasks = []
    completed_today = []
    open_tasks = []

    status_counter = Counter()
    priority_counter = Counter()
    location_summary = defaultdict(lambda: {"location_name": "Unknown location", "open": 0, "overdue": 0, "blocked": 0})

    for task, item in zip(tasks, prepared_tasks):
        schedule_date = item["_schedule_date"]
        done_today = completed_on(task) == today_value
        overdue = bool(schedule_date and schedule_date < today_value and not is_done(task))
        due_today = bool(schedule_date == today_value and not is_done(task))
        upcoming = bool(
            schedule_date
            and today_value < schedule_date <= upcoming_until
            and not is_done(task)
        )

        if not is_done(task):
            open_tasks.append(task)
            status_counter[item["status"]] += 1
            priority_counter[item["priority"]] += 1

            location_row = location_summary[getattr(task, "location_id", None)]
            location_row["location_name"] = item["location_name"]
            location_row["open"] += 1
            if overdue:
                location_row["overdue"] += 1
            if is_blocked(task):
                location_row["blocked"] += 1

        if due_today:
            today_tasks.append(item)
        if overdue:
            overdue_tasks.append(item)
        if upcoming:
            upcoming_tasks.append(item)
        if done_today:
            completed_today.append(item)

    location_items = []
    for location_id, summary in location_summary.items():
        score = (summary["overdue"] * 3) + (summary["blocked"] * 2) + summary["open"]
        location_items.append(
            {
                "location_id": location_id,
                "location_name": summary["location_name"],
                "open_count": summary["open"],
                "overdue_count": summary["overdue"],
                "blocked_count": summary["blocked"],
                "problem_score": score,
            }
        )

    location_items.sort(
        key=lambda item: (
            -item["problem_score"],
            -item["overdue_count"],
            -item["blocked_count"],
            -item["open_count"],
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
        {"key": "overdue", "label": "Overdue", "value": len(overdue_tasks)},
        {"key": "in_progress", "label": "In Progress", "value": sum(1 for task in open_tasks if is_in_progress(task))},
        {"key": "blocked", "label": "Blocked", "value": sum(1 for task in open_tasks if is_blocked(task))},
        {"key": "done_today", "label": "Done Today", "value": len(completed_today)},
        {"key": "urgent", "label": "Urgent", "value": sum(1 for task in open_tasks if compute_priority(task) == "urgent")},
    ]

    return {
        "generated_at": datetime.now(),
        "today": today_value,
        "kpis": kpis,
        "today_tasks": sorted(today_tasks, key=task_sort_key),
        "overdue_tasks": sorted(overdue_tasks, key=task_sort_key),
        "upcoming_tasks": sorted(upcoming_tasks, key=task_sort_key),
        "status_summary": status_summary,
        "priority_summary": priority_summary,
        "location_summary": location_items[:8],
        "recent_completions_today": sorted(completed_today, key=lambda item: item["completed_at"] or datetime.min, reverse=True)[:8],
    }
