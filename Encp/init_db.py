import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / 'users.db'

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.commit()
    print("✅ Initialized database:", DB_PATH)

if __name__ == '__main__':
    init_db()
