import sqlite3

DB = "taskmanager.db"

con = sqlite3.connect(DB)
cur = con.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    photo_path VARCHAR(255),
    module VARCHAR(50),
    location_id INTEGER,
    assigned_user_id INTEGER,
    created_by_user_id INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'new',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(location_id) REFERENCES locations(id),
    FOREIGN KEY(assigned_user_id) REFERENCES users(id),
    FOREIGN KEY(created_by_user_id) REFERENCES users(id)
)
""")

con.commit()
con.close()

print("DONE: observations table created")
