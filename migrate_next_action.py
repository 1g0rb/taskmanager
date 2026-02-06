import sqlite3

DB = "taskmanager.db"

con = sqlite3.connect(DB)
cur = con.cursor()

# 1) add column (if not exists)
try:
    cur.execute("ALTER TABLE tasks ADD COLUMN next_action_date DATE")
    print("Added column: next_action_date")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e).lower():
        print("Column already exists: next_action_date")
    else:
        raise

# 2) backfill
cur.execute("UPDATE tasks SET next_action_date = task_date WHERE next_action_date IS NULL")
print("Backfilled next_action_date from task_date")

con.commit()
con.close()

print("DONE")
