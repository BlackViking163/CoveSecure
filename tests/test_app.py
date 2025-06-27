import unittest
import tempfile
import os
import sqlite3
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, get_db_connection, calculate_risk_level, log_action

class GRCRiskRegisterTestCase(unittest.TestCase):
    """Test cases for the GRC Risk Register application."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a temporary database file
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Set environment variables for testing
        os.environ['DATABASE_NAME'] = app.config['DATABASE']
        os.environ['LOG_FILE_PATH'] = tempfile.mktemp()
        
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Initialize test database
        self.init_test_db()
    
    def tearDown(self):
        """Clean up after each test method."""
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])
        if os.path.exists(os.environ.get('LOG_FILE_PATH', '')):
            os.unlink(os.environ['LOG_FILE_PATH'])
        self.app_context.pop()
    
    def init_test_db(self):
        """Initialize the test database with required tables and test data."""
        conn = sqlite3.connect(app.config['DATABASE'])
        
        # Create tables
        conn.execute('''
            CREATE TABLE risks (
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
        
        conn.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        
        # Insert test data
        from werkzeug.security import generate_password_hash
        
        # Test users
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin")
        )
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("user", generate_password_hash("user123"), "user")
        )
        
        # Test risks
        conn.execute(
            "INSERT INTO risks (description, impact, likelihood, score, level, control, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("Test High Risk", 5, 5, 25, "High", "Test Control", "Open")
        )
        conn.execute(
            "INSERT INTO risks (description, impact, likelihood, score, level, control, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("Test Medium Risk", 3, 3, 9, "Medium", "Test Control", "In Progress")
        )
        conn.execute(
            "INSERT INTO risks (description, impact, likelihood, score, level, control, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("Test Low Risk", 2, 2, 4, "Low", "Test Control", "Closed")
        )
        
        conn.commit()
        conn.close()
    
    def login(self, username, password):
        """Helper method to log in a user."""
        return self.app.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)
    
    def logout(self):
        """Helper method to log out a user."""
        return self.app.get('/logout', follow_redirects=True)

class TestUtilityFunctions(GRCRiskRegisterTestCase):
    """Test utility functions."""
    
    def test_calculate_risk_level_high(self):
        """Test risk level calculation for high risk."""
        self.assertEqual(calculate_risk_level(25), "High")
        self.assertEqual(calculate_risk_level(15), "High")
    
    def test_calculate_risk_level_medium(self):
        """Test risk level calculation for medium risk."""
        self.assertEqual(calculate_risk_level(14), "Medium")
        self.assertEqual(calculate_risk_level(8), "Medium")
    
    def test_calculate_risk_level_low(self):
        """Test risk level calculation for low risk."""
        self.assertEqual(calculate_risk_level(7), "Low")
        self.assertEqual(calculate_risk_level(1), "Low")
    
    @patch('app.audit_logger')
    def test_log_action(self, mock_logger):
        """Test logging functionality."""
        log_action("testuser", "test action")
        mock_logger.info.assert_called_once_with("testuser, test action")

class TestAuthentication(GRCRiskRegisterTestCase):
    """Test authentication functionality."""
    
    def test_login_page_loads(self):
        """Test that login page loads correctly."""
        rv = self.app.get('/login')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Welcome Back', rv.data)
    
    def test_valid_login_admin(self):
        """Test valid admin login."""
        rv = self.login('admin', 'admin123')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'GRC Risk Register', rv.data)
    
    def test_valid_login_user(self):
        """Test valid user login."""
        rv = self.login('user', 'user123')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'GRC Risk Register', rv.data)
    
    def test_invalid_login(self):
        """Test invalid login credentials."""
        rv = self.login('admin', 'wrongpassword')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Invalid username or password', rv.data)
    
    def test_logout(self):
        """Test user logout."""
        self.login('admin', 'admin123')
        rv = self.logout()
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Welcome Back', rv.data)
    
    def test_login_required_redirect(self):
        """Test that protected routes redirect to login."""
        rv = self.app.get('/')
        self.assertEqual(rv.status_code, 302)
        self.assertIn('/login', rv.location)

class TestDashboard(GRCRiskRegisterTestCase):
    """Test dashboard functionality."""
    
    def test_dashboard_loads_for_authenticated_user(self):
        """Test that dashboard loads for authenticated users."""
        self.login('admin', 'admin123')
        rv = self.app.get('/')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Test High Risk', rv.data)
        self.assertIn(b'Test Medium Risk', rv.data)
        self.assertIn(b'Test Low Risk', rv.data)
    
    def test_dashboard_filtering_by_level(self):
        """Test dashboard filtering by risk level."""
        self.login('admin', 'admin123')
        rv = self.app.get('/?level=High')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Test High Risk', rv.data)
        self.assertNotIn(b'Test Medium Risk', rv.data)
    
    def test_dashboard_filtering_by_status(self):
        """Test dashboard filtering by status."""
        self.login('admin', 'admin123')
        rv = self.app.get('/?status=Open')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Test High Risk', rv.data)
        self.assertNotIn(b'Test Medium Risk', rv.data)
    
    def test_dashboard_filtering_by_score_range(self):
        """Test dashboard filtering by score range."""
        self.login('admin', 'admin123')
        rv = self.app.get('/?min_score=10&max_score=30')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Test High Risk', rv.data)
        self.assertNotIn(b'Test Low Risk', rv.data)

class TestRiskManagement(GRCRiskRegisterTestCase):
    """Test risk management functionality."""
    
    def test_add_risk_page_loads(self):
        """Test that add risk page loads."""
        self.login('admin', 'admin123')
        rv = self.app.get('/add')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Add Risk', rv.data)
    
    def test_add_risk_valid_data(self):
        """Test adding a risk with valid data."""
        self.login('admin', 'admin123')
        rv = self.app.post('/add', data=dict(
            description='New Test Risk',
            impact=4,
            likelihood=3,
            control='New Control',
            status='Open'
        ), follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'New Test Risk', rv.data)
    
    def test_add_risk_invalid_impact(self):
        """Test adding a risk with invalid impact value."""
        self.login('admin', 'admin123')
        rv = self.app.post('/add', data=dict(
            description='Invalid Risk',
            impact=6,  # Invalid: should be 1-5
            likelihood=3,
            control='Control',
            status='Open'
        ), follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Impact and Likelihood must be between 1 and 5', rv.data)
    
    def test_add_risk_empty_description(self):
        """Test adding a risk with empty description."""
        self.login('admin', 'admin123')
        rv = self.app.post('/add', data=dict(
            description='',
            impact=3,
            likelihood=3,
            control='Control',
            status='Open'
        ), follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Description cannot be empty', rv.data)
    
    def test_edit_risk_page_loads(self):
        """Test that edit risk page loads."""
        self.login('admin', 'admin123')
        rv = self.app.get('/edit/1')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Edit Risk', rv.data)
        self.assertIn(b'Test High Risk', rv.data)
    
    def test_edit_risk_valid_data(self):
        """Test editing a risk with valid data."""
        self.login('admin', 'admin123')
        rv = self.app.post('/edit/1', data=dict(
            description='Updated Test Risk',
            impact=3,
            likelihood=2,
            control='Updated Control',
            status='In Progress'
        ), follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Updated Test Risk', rv.data)
    
    def test_delete_risk_admin(self):
        """Test that admin can delete risks."""
        self.login('admin', 'admin123')
        rv = self.app.get('/delete/1', follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertNotIn(b'Test High Risk', rv.data)
    
    def test_delete_risk_non_admin(self):
        """Test that non-admin users cannot delete risks."""
        self.login('user', 'user123')
        rv = self.app.get('/delete/1', follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Access denied', rv.data)

class TestExportFunctionality(GRCRiskRegisterTestCase):
    """Test export functionality."""
    
    @patch('app.send_file')
    def test_export_excel(self, mock_send_file):
        """Test Excel export functionality."""
        mock_send_file.return_value = "mocked_response"
        self.login('admin', 'admin123')
        rv = self.app.get('/export/excel')
        self.assertEqual(rv.status_code, 200)
        mock_send_file.assert_called_once()
    
    @patch('app.send_file')
    def test_export_pdf(self, mock_send_file):
        """Test PDF export functionality."""
        mock_send_file.return_value = "mocked_response"
        self.login('admin', 'admin123')
        rv = self.app.get('/export/pdf')
        self.assertEqual(rv.status_code, 200)
        mock_send_file.assert_called_once()

class TestUserManagement(GRCRiskRegisterTestCase):
    """Test user management functionality."""
    
    def test_manage_users_admin_access(self):
        """Test that admin can access user management."""
        self.login('admin', 'admin123')
        rv = self.app.get('/users')
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'admin', rv.data)
        self.assertIn(b'user', rv.data)
    
    def test_manage_users_non_admin_denied(self):
        """Test that non-admin users cannot access user management."""
        self.login('user', 'user123')
        rv = self.app.get('/users', follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Access denied', rv.data)
    
    def test_add_user_valid_data(self):
        """Test adding a user with valid data."""
        self.login('admin', 'admin123')
        rv = self.app.post('/users/add', data=dict(
            username='newuser',
            password='newpass123',
            role='user'
        ), follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'newuser', rv.data)
    
    def test_add_user_duplicate_username(self):
        """Test adding a user with duplicate username."""
        self.login('admin', 'admin123')
        rv = self.app.post('/users/add', data=dict(
            username='admin',  # Already exists
            password='newpass123',
            role='user'
        ), follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b'Username already exists', rv.data)
    
    def test_edit_user_role(self):
        """Test editing user role."""
        self.login('admin', 'admin123')
        rv = self.app.post('/users/edit/2', data=dict(
            role='admin',
            password=''  # No password change
        ), follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
    
    def test_delete_user_admin(self):
        """Test that admin can delete other users."""
        self.login('admin', 'admin123')
        rv = self.app.get('/users/delete/2', follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
    
    def test_admin_cannot_delete_self(self):
        """Test that admin cannot delete themselves."""
        self.login('admin', 'admin123')
        rv = self.app.get('/users/delete/1', follow_redirects=True)
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b"You can't delete yourself", rv.data)

class TestHealthAndMetrics(GRCRiskRegisterTestCase):
    """Test health check and metrics endpoints."""
    
    def test_health_check_endpoint(self):
        """Test health check endpoint."""
        rv = self.app.get('/health')
        self.assertEqual(rv.status_code, 200)
        data = rv.get_json()
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('timestamp', data)
        self.assertIn('database', data)
    
    def test_metrics_endpoint_admin(self):
        """Test metrics endpoint for admin users."""
        self.login('admin', 'admin123')
        rv = self.app.get('/metrics')
        self.assertEqual(rv.status_code, 200)
        data = rv.get_json()
        self.assertIn('database', data)
        self.assertIn('performance', data)
    
    def test_metrics_endpoint_non_admin(self):
        """Test metrics endpoint denies non-admin users."""
        self.login('user', 'user123')
        rv = self.app.get('/metrics')
        self.assertEqual(rv.status_code, 403)
        data = rv.get_json()
        self.assertEqual(data['error'], 'Unauthorized')

class TestErrorHandling(GRCRiskRegisterTestCase):
    """Test error handling."""
    
    def test_404_error_handler(self):
        """Test 404 error handling."""
        self.login('admin', 'admin123')
        rv = self.app.get('/nonexistent-page')
        self.assertEqual(rv.status_code, 404)

if __name__ == '__main__':
    unittest.main()

