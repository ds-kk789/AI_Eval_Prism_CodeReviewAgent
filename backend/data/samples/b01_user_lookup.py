import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    cursor = conn.cursor()
    query = f"SELECT id, email FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
