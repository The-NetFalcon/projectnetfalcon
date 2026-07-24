import os
import sqlite3


def get_connection(database_path: str) -> sqlite3.Connection:
    return sqlite3.connect(database_path, detect_types=sqlite3.PARSE_DECLTYPES)


def init_db(database_path: str) -> None:
    db_dir = os.path.dirname(database_path)
    os.makedirs(db_dir, exist_ok=True)

    with sqlite3.connect(database_path) as connection:
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, 'r', encoding='utf-8') as schema_file:
            connection.executescript(schema_file.read())
