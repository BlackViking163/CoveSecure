from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import sqlite3
import os
from datetime import datetime
import pandas as pd
from fpdf import FPDF
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
import time
import sys

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))

DB_NAME = os.environ.get("DATABASE_NAME", "database.db")
LOG_FILE = os.environ.get("LOG_FILE_PATH", "logs/audit_log.csv")

# Configure comprehensive logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Create formatters
detailed_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
simple_formatter = logging.Formatter('%(asctime)s, %(message)s')

# Configure application logger
app_logger = logging.getLogger('grc_app')
app_logger.setLevel(logging.INFO)

# File handler for application logs
app_handler = logging.FileHandler('logs/app.log')
app_handler.setLevel(logging.INFO)
app_handler.setFormatter(detailed_formatter)
app_logger.addHandler(app_handler)

# Console handler for development
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(detailed_formatter)
app_logger.addHandler(console_handler)

# Audit logger for user actions
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(LOG_FILE)
audit_handler.setFormatter(simple_formatter)
audit_logger.addHandler(audit_handler)

# Performance monitoring
class PerformanceMonitor:
    def __init__(self):
        self.request_count = 0
        self.total_response_time = 0
        self.slow_requests = []
    
    def record_request(self, endpoint, response_time, status_code):
        self.request_count += 1
        self.total_response_time += response_time
        
        if response_time > 1.0:  # Log slow requests (>1 second)
            self.slow_requests.append({
                'endpoint': endpoint,
                'response_time': response_time,
                'status_code': status_code,
                'timestamp': datetime.now()
            })
            app_logger.warning(f"Slow request detected: {endpoint} took {response_time:.2f}s")
    
    def get_average_response_time(self):
        return self.total_response_time / self.request_count if self.request_count > 0 else 0

performance_monitor = PerformanceMonitor()

# Request timing middleware
@app.before_request
def before_request():
    request.start_time = time.time()
    app_logger.info(f"Request started: {request.method} {request.path}")

@app.after_request
def after_request(response):
    response_time = time.time() - request.start_time
    performance_monitor.record_request(request.endpoint, response_time, response.status_code)
    app_logger.info(f"Request completed: {request.method} {request.path} - {response.status_code} - {response_time:.3f}s")
    return response

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    app_logger.warning(f"404 error: {request.path}")
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    app_logger.error(f"500 error: {str(error)}")
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

# Health check endpoint for monitoring
@app.route('/health')
def health_check():
    try:
        # Check database connectivity
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        
        # Check log file accessibility
        os.path.exists(LOG_FILE)
        
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'logging': 'operational',
            'request_count': performance_monitor.request_count,
            'avg_response_time': round(performance_monitor.get_average_response_time(), 3)
        }
        
        app_logger.info("Health check passed")
        return health_status, 200
        
    except Exception as e:
        app_logger.error(f"Health check failed: {str(e)}")
        return {
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }, 503

# Metrics endpoint for monitoring
@app.route('/metrics')
def metrics():
    if session.get('role') != 'admin':
        return {'error': 'Unauthorized'}, 403
    
    try:
        conn = get_db_connection()
        
        # Get database statistics
        risk_count = conn.execute('SELECT COUNT(*) as count FROM risks').fetchone()['count']
        user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        
        # Get risk distribution
        risk_levels = conn.execute('''
            SELECT level, COUNT(*) as count 
            FROM risks 
            GROUP BY level
        ''').fetchall()
        
        conn.close()
        
        metrics_data = {
            'timestamp': datetime.now().isoformat(),
            'database': {
                'total_risks': risk_count,
                'total_users': user_count,
                'risk_distribution': {row['level']: row['count'] for row in risk_levels}
            },
            'performance': {
                'total_requests': performance_monitor.request_count,
                'average_response_time': round(performance_monitor.get_average_response_time(), 3),
                'slow_requests_count': len(performance_monitor.slow_requests)
            }
        }
        
        return metrics_data, 200
        
    except Exception as e:
        app_logger.error(f"Metrics collection failed: {str(e)}")
        return {'error': 'Metrics collection failed'}, 500

# Helper function to get database connection
def get_db_connection():
    """Establishes a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        app_logger.error(f"Database connection failed: {str(e)}")
        raise

# Helper function to calculate risk level based on score
def calculate_risk_level(score):
    """Calculates the risk level (High, Medium, Low) based on the given score."""
    if score >= 15:
        return "High"
    elif score >= 8:
        return "Medium"
    else:
        return "Low"

# Helper function to log user actions
def log_action(user, action):
    """Logs user actions to an audit log file."""
    try:
        audit_logger.info(f"{user}, {action}")
        app_logger.info(f"User action logged: {user} - {action}")
    except Exception as e:
        app_logger.error(f"Failed to log user action: {str(e)}")

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            app_logger.warning(f"Unauthorized access attempt to {request.endpoint}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator for admin required
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            app_logger.warning(f"Non-admin user {session.get('username', 'unknown')} attempted to access {request.endpoint}")
            flash('Access denied: Admin privileges required.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login and session management."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        app_logger.info(f"Login attempt for user: {username}")
        
        try:
            conn = get_db_connection()
            user_record = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            conn.close()
            
            if user_record and check_password_hash(user_record["password"], password):
                session["username"] = user_record["username"]
                session["role"] = user_record["role"]
                log_action(username, "Logged in")
                app_logger.info(f"Successful login for user: {username}")
                return redirect("/")
            else:
                app_logger.warning(f"Failed login attempt for user: {username}")
                flash("Invalid username or password")
                
        except Exception as e:
            app_logger.error(f"Login error: {str(e)}")
            flash("An error occurred during login")
            
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Handles user logout and session clearing."""
    username = session.get("username", "unknown")
    log_action(username, "Logged out")
    app_logger.info(f"User logged out: {username}")
    session.clear()
    return redirect("/login")

# --- Dashboard and Filtering ---
@app.route("/")
@login_required
def index():
    """Displays the risk dashboard with filtering capabilities."""
    try:
        # Get filter parameters from request arguments
        level_filter = str(request.args.get("level") or "").strip()
        status_filter = str(request.args.get("status") or "").strip()
        min_score_filter = request.args.get("min_score", type=int)
        max_score_filter = request.args.get("max_score", type=int)

        query = "SELECT * FROM risks WHERE 1=1"
        params = []

        # Build query based on provided filters
        if level_filter:
            query += " AND level = ?"
            params.append(level_filter)

        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)

        if min_score_filter is not None:
            query += " AND score >= ?"
            params.append(min_score_filter)

        if max_score_filter is not None:
            query += " AND score <= ?"
            params.append(max_score_filter)

        conn = get_db_connection()
        risks = conn.execute(query, params).fetchall() if params else conn.execute("SELECT * FROM risks").fetchall()
        conn.close()

        # Prepare data for charts
        level_data, status_data, control_data = {}, {}, {}
        for risk in risks:
            level = risk["level"] or "Unknown"
            status = risk["status"] or "Unknown"
            control = risk["control"] or "None"

            level_data[level] = level_data.get(level, 0) + 1
            status_data[status] = status_data.get(status, 0) + 1
            control_data[control] = control_data.get(control, 0) + 1

        app_logger.info(f"Dashboard loaded with {len(risks)} risks for user: {session['username']}")

        return render_template(
            "index.html",
            risks=risks,
            level_data=level_data,
            status_data=status_data,
            control_data=control_data,
            selected_level=level_filter,
            selected_status=status_filter,
            selected_min_score=min_score_filter,
            selected_max_score=max_score_filter
        )
        
    except Exception as e:
        app_logger.error(f"Dashboard error: {str(e)}")
        flash("An error occurred while loading the dashboard")
        return render_template("index.html", risks=[])

# --- Risk Management Routes ---
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_risk():
    """Handles adding new risks to the system."""
    if request.method == "POST":
        try:
            description = request.form["description"]
            if not description.strip():
                flash("Description cannot be empty.")
                return render_template("add_edit.html", action="Add", risk=None)
                
            impact = int(request.form["impact"])
            likelihood = int(request.form["likelihood"])
            
            if not (1 <= impact <= 5 and 1 <= likelihood <= 5):
                flash("Impact and Likelihood must be between 1 and 5.")
                return render_template("add_edit.html", action="Add", risk=None)

            score = impact * likelihood
            level = calculate_risk_level(score)
            control = request.form["control"]
            status = request.form["status"]

            conn = get_db_connection()
            conn.execute("INSERT INTO risks (description, impact, likelihood, score, level, control, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (description, impact, likelihood, score, level, control, status))
            conn.commit()
            conn.close()
            
            log_action(session["username"], f"Added risk: {description}")
            app_logger.info(f"Risk added by {session['username']}: {description}")
            return redirect("/")
            
        except ValueError:
            flash("Impact and Likelihood must be integers.")
            app_logger.warning(f"Invalid input in add_risk by {session['username']}")
        except Exception as e:
            app_logger.error(f"Error adding risk: {str(e)}")
            flash("An error occurred while adding the risk")
            
    return render_template("add_edit.html", action="Add", risk=None)

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_risk(id):
    """Handles editing existing risks in the system."""
    try:
        conn = get_db_connection()
        risk = conn.execute("SELECT * FROM risks WHERE id = ?", (id,)).fetchone()

        if request.method == "POST":
            description = request.form["description"]
            if not description.strip():
                flash("Description cannot be empty.")
                return render_template("add_edit.html", action="Edit", risk=risk)
                
            impact = int(request.form["impact"])
            likelihood = int(request.form["likelihood"])
            
            if not (1 <= impact <= 5 and 1 <= likelihood <= 5):
                flash("Impact and Likelihood must be between 1 and 5.")
                return render_template("add_edit.html", action="Edit", risk=risk)

            score = impact * likelihood
            level = calculate_risk_level(score)
            control = request.form["control"]
            status = request.form["status"]

            conn.execute("UPDATE risks SET description=?, impact=?, likelihood=?, score=?, level=?, control=?, status=? WHERE id=?",
                         (description, impact, likelihood, score, level, control, status, id))
            conn.commit()
            conn.close()
            
            log_action(session["username"], f"Edited risk ID: {id}")
            app_logger.info(f"Risk {id} edited by {session['username']}")
            return redirect("/")
            
        conn.close()
        return render_template("add_edit.html", action="Edit", risk=risk)
        
    except ValueError:
        flash("Impact and Likelihood must be integers.")
        app_logger.warning(f"Invalid input in edit_risk by {session['username']}")
    except Exception as e:
        app_logger.error(f"Error editing risk {id}: {str(e)}")
        flash("An error occurred while editing the risk")
        return redirect("/")

@app.route("/delete/<int:id>")
@login_required
@admin_required
def delete_risk(id):
    """Handles deleting risks (admin only)."""
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM risks WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        
        log_action(session["username"], f"Deleted risk ID: {id}")
        app_logger.info(f"Risk {id} deleted by {session['username']}")
        
    except Exception as e:
        app_logger.error(f"Error deleting risk {id}: {str(e)}")
        flash("An error occurred while deleting the risk")
        
    return redirect("/")

# --- Export Functionality ---
@app.route("/export/excel")
@login_required
def export_excel():
    """Exports risk data to an Excel file."""
    try:
        conn = get_db_connection()
        df = pd.read_sql_query("SELECT * FROM risks", conn)
        conn.close()
        
        excel_file_path = "risks.xlsx"
        df.to_excel(excel_file_path, index=False)
        
        log_action(session["username"], "Exported data to Excel")
        app_logger.info(f"Excel export by {session['username']}")
        
        return send_file(excel_file_path, as_attachment=True)
        
    except Exception as e:
        app_logger.error(f"Excel export error: {str(e)}")
        flash("An error occurred during Excel export")
        return redirect("/")

@app.route("/export/pdf")
@login_required
def export_pdf():
    """Exports risk data to a PDF file."""
    try:
        conn = get_db_connection()
        risks = conn.execute("SELECT * FROM risks").fetchall()
        conn.close()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        for risk in risks:
            pdf.cell(200, 10, txt=f"{risk['id']}: {risk['description']} ({risk['level']})", ln=1)

        pdf_file_path = "risks.pdf"
        pdf.output(pdf_file_path)
        
        log_action(session["username"], "Exported data to PDF")
        app_logger.info(f"PDF export by {session['username']}")
        
        return send_file(pdf_file_path, as_attachment=True)
        
    except Exception as e:
        app_logger.error(f"PDF export error: {str(e)}")
        flash("An error occurred during PDF export")
        return redirect("/")

# --- Logging and User Management ---
@app.route("/logs")
@login_required
@admin_required
def view_logs():
    """Displays the audit logs (admin only)."""
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        app_logger.info(f"Logs viewed by {session['username']}")
        return "<br>".join(lines)
    except FileNotFoundError:
        app_logger.warning("Log file not found")
        flash("Log file not found.")
        return redirect("/")

@app.route("/users")
@login_required
@admin_required
def manage_users():
    """Displays the user management page (admin only)."""
    try:
        conn = get_db_connection()
        users = conn.execute("SELECT id, username, role FROM users").fetchall()
        conn.close()
        
        app_logger.info(f"User management accessed by {session['username']}")
        return render_template("manage_users.html", users=users)
        
    except Exception as e:
        app_logger.error(f"User management error: {str(e)}")
        flash("An error occurred while loading users")
        return redirect("/")

@app.route("/users/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_user():
    """Handles adding new users to the system (admin only)."""
    if request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]
            role = request.form["role"]
            
            if not username.strip() or not password.strip():
                flash("Username and password cannot be empty.")
                return render_template("add_edit_user.html", action="Add", user=None)
                
            if role not in ["admin", "user"]:
                flash("Invalid role specified.")
                return render_template("add_edit_user.html", action="Add", user=None)

            hashed_pw = generate_password_hash(password)

            conn = get_db_connection()
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (username, hashed_pw, role))
            conn.commit()
            conn.close()
            
            log_action(session["username"], f"Created user {username}")
            app_logger.info(f"User {username} created by {session['username']}")
            return redirect("/users")
            
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            app_logger.warning(f"Attempt to create duplicate user {username}")
        except Exception as e:
            app_logger.error(f"Error creating user: {str(e)}")
            flash("An error occurred while creating the user")
            
    return render_template("add_edit_user.html", action="Add", user=None)

@app.route("/users/edit/<int:id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(id):
    """Handles editing existing user details (admin only)."""
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (id,)).fetchone()
        
        if request.method == "POST":
            role = request.form["role"]
            password = request.form["password"]
            
            if role not in ["admin", "user"]:
                flash("Invalid role specified.")
                return render_template("add_edit_user.html", action="Edit", user=user)

            if password.strip():
                hashed_pw = generate_password_hash(password)
                conn.execute("UPDATE users SET role = ?, password = ? WHERE id = ?", (role, hashed_pw, id))
            else:
                conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, id))
                
            conn.commit()
            conn.close()
            
            log_action(session["username"], f"Updated user {user['username']}")
            app_logger.info(f"User {user['username']} updated by {session['username']}")
            return redirect("/users")
            
        conn.close()
        return render_template("add_edit_user.html", action="Edit", user=user)
        
    except Exception as e:
        app_logger.error(f"Error editing user {id}: {str(e)}")
        flash("An error occurred while editing the user")
        return redirect("/users")

@app.route("/users/delete/<int:id>")
@login_required
@admin_required
def delete_user(id):
    """Handles deleting users (admin only)."""
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (id,)).fetchone()
        
        if user["username"] == session["username"]:
            conn.close()
            flash("You can't delete yourself.")
            return redirect("/users")
            
        conn.execute("DELETE FROM users WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        
        log_action(session["username"], f"Deleted user {user['username']}")
        app_logger.info(f"User {user['username']} deleted by {session['username']}")
        
    except Exception as e:
        app_logger.error(f"Error deleting user {id}: {str(e)}")
        flash("An error occurred while deleting the user")
        
    return redirect("/users")

# --- Run App ---
if __name__ == "__main__":
    app_logger.info("GRC Risk Register application starting...")
    app.run(host="0.0.0.0", debug=False)

