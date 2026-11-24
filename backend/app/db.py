from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    return engine


engine = _make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if settings.database_url.startswith("sqlite:///"):
        db_path = settings.database_url.removeprefix("sqlite:///")
        if db_path and db_path != ":memory:":
            from pathlib import Path

            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(engine)
    _add_missing_columns()


def _add_missing_columns() -> None:
    """Add columns introduced after a database was created (SQLite only).

    create_all() creates new tables but never alters existing ones, so a
    database from an earlier version would miss new columns. Only simple
    additive changes are handled; nothing is dropped or renamed.
    """
    if not settings.database_url.startswith("sqlite"):
        return
    from sqlalchemy import Boolean, Integer, String, Text, inspect, text
    from sqlalchemy.exc import OperationalError

    # Pooled connections can hold a stale copy of the schema; start fresh.
    engine.dispose()
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                default = col.default.arg if col.default is not None and not callable(col.default.arg) else None
                if isinstance(col.type, Boolean):
                    ddl, lit = "BOOLEAN", "1" if default else "0"
                elif isinstance(col.type, Integer):
                    ddl, lit = "INTEGER", str(default) if default is not None else "NULL"
                elif isinstance(col.type, (String, Text)):
                    ddl, lit = "TEXT", "'" + str(default or "").replace("'", "''") + "'"
                else:
                    ddl, lit = col.type.compile(engine.dialect), "NULL"
                try:
                    conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl} DEFAULT {lit}'))
                except OperationalError as exc:
                    if "duplicate column" not in str(exc):
                        raise


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Session for background work outside a request."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
