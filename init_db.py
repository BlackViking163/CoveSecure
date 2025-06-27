import sqlite3
import os
from werkzeug.security import generate_password_hash

# Create DB Connection
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
)
''')

# Create risks table
cursor.execute('''
CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT NOT NULL,
    impact INTEGER NOT NULL,
    likelihood INTEGER NOT NULL,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    control TEXT,
    status TEXT NOT NULL
)
''')

# Create audit log table
cursor.execute('''
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user TEXT NOT NULL,
    action TEXT NOT NULL
)
''')

# Insert default admin user with hashed password
hashed_pw = generate_password_hash('admin123')
cursor.execute('''
INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)
''', ('admin', hashed_pw, 'admin'))

conn.commit()
conn.close()

# Create logs directory and audit file if not exist
os.makedirs('logs', exist_ok=True)
if not os.path.exists('logs/audit_log.csv'):
    with open('logs/audit_log.csv', 'w') as f:
        f.write('timestamp, user, action\n')

print(" Database initialised successfully.")