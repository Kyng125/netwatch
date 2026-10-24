"""Cloud deployment — hosting providers' DATABASE_URL values must map to the shipped PostgreSQL driver."""
import pytest

from netwatch.config import normalize_database_url


@pytest.mark.parametrize("given,expected", [
    ("postgres://u:p@host:5432/db", "postgresql+psycopg://u:p@host:5432/db"),
    ("postgresql://u:p@host/db", "postgresql+psycopg://u:p@host/db"),
    ("postgresql+psycopg2://u:p@host/db", "postgresql+psycopg2://u:p@host/db"),  # explicit driver is respected
    ("mysql+pymysql://u:p@host/db", "mysql+pymysql://u:p@host/db"),
    ("sqlite:///x.db", "sqlite:///x.db"),
    ("  postgres://u:p@h/db  ", "postgresql+psycopg://u:p@h/db"),
])
def test_normalize_database_url(given, expected):
    assert normalize_database_url(given) == expected
