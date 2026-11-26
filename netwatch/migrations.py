"""Small, idempotent schema upgrades for databases created by an earlier version.

``db.create_all()`` creates missing *tables* but never adds *columns* to a table that already
exists. The live deployment's ``devices`` table predates on-site agents, so the columns they need
are added here. Every step checks first, so running it on every start is safe on SQLite,
PostgreSQL and MySQL.
"""
import logging

from sqlalchemy import inspect, text

from .extensions import db

log = logging.getLogger(__name__)

# (table, column, SQL type + constraints) — added in order if missing
COLUMNS = [
    ("devices", "site_id", "INTEGER REFERENCES sites(site_id) ON DELETE SET NULL"),
    ("devices", "check_requested_at", "TIMESTAMP"),
]


def upgrade():
    """Add any missing columns. Returns the list of 'table.column' names that were added."""
    added = []
    insp = inspect(db.engine)
    tables = set(insp.get_table_names())
    for table, column, ddl in COLUMNS:
        if table not in tables:
            continue  # create_all() will create it with every column
        existing = {c["name"] for c in insp.get_columns(table)}
        if column in existing:
            continue
        with db.engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        added.append(f"{table}.{column}")
        log.info("Schema upgrade: added column %s.%s", table, column)
    if "devices.site_id" in added:
        try:
            with db.engine.begin() as conn:
                conn.execute(text("CREATE INDEX ix_devices_site_id ON devices (site_id)"))
        except Exception:  # index already exists, or the engine words it differently: not essential
            log.info("Index ix_devices_site_id not created (it may already exist)")
    return added
