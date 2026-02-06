import sqlite3

DB = "taskmanager.db"

con = sqlite3.connect(DB)
cur = con.cursor()

def add_col(sql):
    try:
        cur.execute(sql)
        print("OK:", sql)
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("SKIP (exists):", sql)
        else:
            raise

add_col("ALTER TABLE tasks ADD COLUMN blocked_until DATE")
add_col("ALTER TABLE tasks ADD COLUMN blocked_at DATETIME")

con.commit()
con.close()
print("DONE")
