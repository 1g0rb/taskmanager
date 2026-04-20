import sqlite3

DB = "taskmanager.db"

con = sqlite3.connect(DB)
cur = con.cursor()

try:
    cur.execute("ALTER TABLE tasks ADD COLUMN is_todo BOOLEAN NOT NULL DEFAULT 0")
    print("Added column: is_todo")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e).lower():
        print("Column already exists: is_todo")
    else:
        raise

con.commit()
con.close()

print("DONE")
