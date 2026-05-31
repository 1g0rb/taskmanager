from __future__ import annotations

import calendar
from datetime import date, datetime, time, timedelta, timezone, tzinfo

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None


UTC = timezone.utc


def _last_sunday(year: int, month: int) -> date:
    last_day = date(year, month, calendar.monthrange(year, month)[1])
    return last_day - timedelta(days=(last_day.weekday() + 1) % 7)


class ZagrebTimezone(tzinfo):
    def _dst_start_local(self, year: int) -> datetime:
        return datetime.combine(_last_sunday(year, 3), time(hour=2))

    def _dst_end_local(self, year: int) -> datetime:
        return datetime.combine(_last_sunday(year, 10), time(hour=3))

    def _dst_start_utc(self, year: int) -> datetime:
        return datetime.combine(_last_sunday(year, 3), time(hour=1))

    def _dst_end_utc(self, year: int) -> datetime:
        return datetime.combine(_last_sunday(year, 10), time(hour=1))

    def utcoffset(self, dt):
        return timedelta(hours=1) + self.dst(dt)

    def dst(self, dt):
        if dt is None:
            return timedelta(0)
        local_value = dt.replace(tzinfo=None)
        if self._dst_start_local(local_value.year) <= local_value < self._dst_end_local(local_value.year):
            return timedelta(hours=1)
        return timedelta(0)

    def tzname(self, dt):
        return "CEST" if self.dst(dt) else "CET"

    def fromutc(self, dt):
        utc_value = dt.replace(tzinfo=None)
        if self._dst_start_utc(utc_value.year) <= utc_value < self._dst_end_utc(utc_value.year):
            return (utc_value + timedelta(hours=2)).replace(tzinfo=self)
        return (utc_value + timedelta(hours=1)).replace(tzinfo=self)


ZAGREB_TZ = ZoneInfo("Europe/Zagreb") if ZoneInfo else ZagrebTimezone()


def utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def zagreb_now() -> datetime:
    return datetime.now(ZAGREB_TZ)


def zagreb_today() -> date:
    return zagreb_now().date()


def utc_naive_to_zagreb(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC).astimezone(ZAGREB_TZ)
    return value.astimezone(ZAGREB_TZ)


def zagreb_datetime_to_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=ZAGREB_TZ)
    return value.astimezone(UTC).replace(tzinfo=None)


def zagreb_day_start_utc_naive(day: date) -> datetime:
    return zagreb_datetime_to_utc_naive(datetime.combine(day, time.min, tzinfo=ZAGREB_TZ))


def format_zagreb_datetime(value, fmt: str = "%Y-%m-%d %H:%M", default: str = "-") -> str:
    if value is None:
        return default
    if isinstance(value, datetime):
        local_value = utc_naive_to_zagreb(value)
        return local_value.strftime(fmt) if local_value else default
    if isinstance(value, date):
        return value.strftime(fmt)
    return str(value)
