"""
database/db_connection.py
--------------------------
PostgreSQL connection pool manager for the Backend API (Service 3).

Every route and the Kafka consumer in app.py goes through
get_db_cursor() so connections are always safely returned to the
pool, even on error.

Env vars (match the `postgres` service defined in docker-compose.yml):
    DB_HOST      default: postgres
    DB_PORT      default: 5432
    DB_NAME      default: midnight_protocol
    DB_USER      default: midnight_admin
    DB_PASSWORD  default: midnight_pass
    DB_MIN_CONN  default: 1
    DB_MAX_CONN  default: 10
"""

import os
import logging
from contextlib import contextmanager

from psycopg2 import pool
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("db_connection")

DB_HOST = os.environ.get("DB_HOST", "postgres")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "midnight_protocol")
DB_USER = os.environ.get("DB_USER", "midnight_admin")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "midnight_pass")
DB_MIN_CONN = int(os.environ.get("DB_MIN_CONN", 1))
DB_MAX_CONN = int(os.environ.get("DB_MAX_CONN", 10))

_connection_pool = None


def init_pool():
    """Creates the threaded connection pool once at app startup."""
    global _connection_pool
    if _connection_pool is not None:
        return _connection_pool
    try:
        _connection_pool = pool.ThreadedConnectionPool(
            DB_MIN_CONN,
            DB_MAX_CONN,
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        logger.info(
            f"PostgreSQL pool ready ({DB_MIN_CONN}-{DB_MAX_CONN} conns) -> "
            f"{DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
    except Exception as exc:
        logger.error(f"Failed to create PostgreSQL connection pool: {exc}")
        raise
    return _connection_pool


def get_pool():
    if _connection_pool is None:
        return init_pool()
    return _connection_pool


@contextmanager
def get_db_cursor(commit: bool = False):
    """
    Yields a RealDictCursor (rows come back as dicts, ready for jsonify)
    and guarantees the connection is returned to the pool.

    Usage:
        with get_db_cursor(commit=True) as cur:
            cur.execute("INSERT INTO alerts (...) VALUES (...) RETURNING *")
            row = cur.fetchone()
    """
    conn_pool = get_pool()
    conn = conn_pool.getconn()
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        yield cur
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cur is not None:
            cur.close()
        conn_pool.putconn(conn)


def close_pool():
    """Call on graceful shutdown."""
    global _connection_pool
    if _connection_pool is not None:
        _connection_pool.closeall()
        _connection_pool = None
        logger.info("PostgreSQL connection pool closed")
