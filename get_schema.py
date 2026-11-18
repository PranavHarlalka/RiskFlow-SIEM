import os
import json
import sqlite3
import argparse
from dotenv import load_dotenv

load_dotenv()


def get_db_path():
    return os.getenv('DB_PATH', 'securityriskdb.db')


def init_database(sql_file_path='schema.sql'):
    if not os.path.exists(sql_file_path):
        raise FileNotFoundError(f"Schema file not found: {sql_file_path}")

    with open(sql_file_path, 'r', encoding='utf-8') as f:
        sql_script = f.read()

    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.executescript(sql_script)
    conn.commit()
    conn.close()
    print(f"Successfully initialized SQLite database '{db_path}' from {sql_file_path}.")


def inspect_schema():
    db_path = get_db_path()
    if not os.path.exists(db_path):
        print(f"Database '{db_path}' not found. Run: python get_schema.py --init")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    tables = [row[0] for row in cursor.fetchall()]

    schema = {}
    for table in tables:
        cursor.execute(f"PRAGMA table_info({table})")
        schema[table] = [f"{col[1]} ({col[2]}, pk:{col[5]})" for col in cursor.fetchall()]

    conn.close()
    print(json.dumps(schema, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RiskFlow SQLite Schema Initializer & Inspector')
    parser.add_argument('--init', action='store_true', help='Initialize SQLite tables and seed data from schema.sql')
    args = parser.parse_args()

    if args.init:
        init_database()
    else:
        inspect_schema()
