from flask import Flask, render_template, request, redirect, url_for, session, send_file
import sqlite3
import os
from datetime import datetime
import pandas as pd
from fpdf import FPDF
import secrets
from werkzeug.security import  generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Secure session key

DB_NAME = 'database.db'
LOG_FILE = 'logs/audit_log.csv'

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def calculate_risk_level(score):
    if score >= 15:
        return "High"
    elif score >= 8:
        return "Medium"
    else:
        return "Low"

def log_action(user, action):
    os.makedirs('logs', exist_ok=True)
    with open(LOG_FILE, 'a') as log:
        log.write(f"{datetime.now()}, {user}, {action}\n")

# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        conn = get_db_connection()
        usr = conn.execute('SELECT * FROM users WHERE username = ?', (user,)).fetchone()
        conn.close()
        if usr and check_password_hash(usr['password'], pw):
            session['username'] = usr['username']
            session['role'] = usr['role']
            log_action(user, "Logged in")
            return redirect('/')
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_action(session.get('username', 'unknown'), "Logged out")
    session.clear()
    return redirect('/login')

# --- Dashboard with Filtering ---
@app.route('/')
def index():
    if 'username' not in session:
        return redirect('/login')

    level = str(request.args.get('level') or '').strip()
    status = str(request.args.get('status') or '').strip()
    min_score = request.args.get('min_score', type=int)
    max_score = request.args.get('max_score', type=int)

    query = "SELECT * FROM risks WHERE 1=1"
    params = []

    if level:
        query += " AND level = ?"
        params.append(level)

    if status:
        query += " AND status = ?"
        params.append(status)

    if min_score is not None:
        query += " AND score >= ?"
        params.append(min_score)

    if max_score is not None:
        query += " AND score <= ?"
        params.append(max_score)

    conn = get_db_connection()
    risks = conn.execute(query, params).fetchall() if params else conn.execute("SELECT * FROM risks").fetchall()

    level_data, status_data, control_data = {}, {}, {}
    for r in risks:
        level = r['level'] or 'Unknown'
        status = r['status'] or 'Unknown'
        control = r['control'] or 'None'

        level_data[level] = level_data.get(level, 0) + 1
        status_data[status] = status_data.get(status, 0) + 1
        control_data[control] = control_data.get(control, 0) + 1

    conn.close()
    return render_template(
        'index.html',
        risks=risks,
        level_data=level_data,
        status_data=status_data,
        control_data=control_data,
        selected_level=level,
        selected_status=status,
        selected_min_score=min_score,
        selected_max_score=max_score
    )

# --- Add Risk ---
@app.route('/add', methods=['GET', 'POST'])
def add_risk():
    if 'username' not in session:
        return redirect('/login')
    if request.method == 'POST':
        desc = request.form['description']
        impact = int(request.form['impact'])
        likelihood = int(request.form['likelihood'])
        score = impact * likelihood
        level = calculate_risk_level(score)
        control = request.form['control']
        status = request.form['status']

        conn = get_db_connection()
        conn.execute('INSERT INTO risks (description, impact, likelihood, score, level, control, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (desc, impact, likelihood, score, level, control, status))
        conn.commit()
        conn.close()
        log_action(session['username'], f"Added risk: {desc}")
        return redirect('/')
    return render_template('add_edit.html', action='Add', risk=None)

# --- Edit Risk ---
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_risk(id):
    if 'username' not in session:
        return redirect('/login')

    conn = get_db_connection()
    risk = conn.execute('SELECT * FROM risks WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        desc = request.form['description']
        impact = int(request.form['impact'])
        likelihood = int(request.form['likelihood'])
        score = impact * likelihood
        level = calculate_risk_level(score)
        control = request.form['control']
        status = request.form['status']

        conn.execute('UPDATE risks SET description=?, impact=?, likelihood=?, score=?, level=?, control=?, status=? WHERE id=?',
                     (desc, impact, likelihood, score, level, control, status, id))
        conn.commit()
        conn.close()
        log_action(session['username'], f"Edited risk ID: {id}")
        return redirect('/')
    conn.close()
    return render_template('add_edit.html', action='Edit', risk=risk)

# --- Delete Risk (Admin Only) ---
@app.route('/delete/<int:id>')
def delete_risk(id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect('/login')
    conn = get_db_connection()
    conn.execute('DELETE FROM risks WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    log_action(session['username'], f"Deleted risk ID: {id}")
    return redirect('/')

# --- Export to Excel ---
@app.route('/export/excel')
def export_excel():
    conn = get_db_connection()
    df = pd.read_sql_query('SELECT * FROM risks', conn)
    conn.close()
    df.to_excel('risks.xlsx', index=False)
    return send_file('risks.xlsx', as_attachment=True)

# --- Export to PDF ---
@app.route('/export/pdf')
def export_pdf():
    conn = get_db_connection()
    risks = conn.execute('SELECT * FROM risks').fetchall()
    conn.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    for r in risks:
        pdf.cell(200, 10, txt=f"{r['id']}: {r['description']} ({r['level']})", ln=1)

    pdf.output("risks.pdf")
    return send_file("risks.pdf", as_attachment=True)

# --- View Logs (Admin Only) ---
@app.route('/logs')
def view_logs():
    if 'role' not in session or session['role'] != 'admin':
        return redirect('/')
    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()
    return "<br>".join(lines)

# --- User Mangement ---
@app.route('/users')
def manage_users():
    if session.get('role') != 'admin':
        return redirect('/')
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
def add_user():
    if session.get('role') != 'admin':
        return redirect('/')
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']
        hashed_pw = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                (username, hashed_pw, role)
            )
            conn.commit()
            conn.close()
            log_action(session['username'], f"Created user {username}")
            return redirect('/users')
        except sqlite3.Error as e:
            return f"Database error: {e}"
    return render_template('add_edit_user.html', action="Add", user=None)

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if session.get('role') != 'admin':
        return redirect('/')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    if request.method == 'PSOT':
        role = request.form['role']
        password = request.form['password']
        if password: hashed_pw = generate_password_hash(password)
        conn.execute('UPDATE users SET role = ?, password = ?, WHERE id = ?', (role, hashed_pw, id))
    else: conn.execute('UPDATE users SET role = ? WHERE id = ?', (role, id))
    conn.commit()
    conn.close()

    log_action(session['username'], f"Updated user {user['username']}")
    return render_template('add_edit_user.html', action="Edit", user=user)

@app.route('/users/delete/<int:id>')
def delete_user(id):
    if session.get('role') != 'admin':
        return redirect('/')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    if user['username'] == session['username']:
        conn.close()
        return "You can't delete yourself."
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    log_action(session['username'], f"Deleted user {user['username']}")
    return redirect('/users')

# --- Run App ---
if __name__ == '__main__':
    app.run(debug=True)