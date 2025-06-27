import unittest
import tempfile
import os
import sqlite3
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
from selenium.webdriver.chrome.options import Options
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

class IntegrationTestCase(unittest.TestCase):
    """Base class for integration tests."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures for the entire test class."""
        # Set up Chrome options for headless testing
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        
        try:
            cls.driver = webdriver.Chrome(options=chrome_options)
        except Exception:
            # Fallback to Firefox if Chrome is not available
            from selenium.webdriver.firefox.options import Options as FirefoxOptions
            firefox_options = FirefoxOptions()
            firefox_options.add_argument("--headless")
            cls.driver = webdriver.Firefox(options=firefox_options)
        
        cls.driver.implicitly_wait(10)
        
        # Create temporary database
        cls.db_fd, cls.db_path = tempfile.mkstemp()
        cls.log_path = tempfile.mktemp()
        
        # Set environment variables
        os.environ['DATABASE_NAME'] = cls.db_path
        os.environ['LOG_FILE_PATH'] = cls.log_path
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key'
        
        # Configure Flask app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Initialize test database
        cls.init_test_db()
        
        # Start Flask app in a separate thread
        import threading
        cls.app_thread = threading.Thread(target=cls.run_app)
        cls.app_thread.daemon = True
        cls.app_thread.start()
        
        # Wait for app to start
        time.sleep(2)
        
        cls.base_url = "http://localhost:5000"
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after all tests."""
        cls.driver.quit()
        os.close(cls.db_fd)
        os.unlink(cls.db_path)
        if os.path.exists(cls.log_path):
            os.unlink(cls.log_path)
    
    @classmethod
    def run_app(cls):
        """Run the Flask app for testing."""
        app.run(host='localhost', port=5000, debug=False, use_reloader=False)
    
    @classmethod
    def init_test_db(cls):
        """Initialize the test database with required tables and test data."""
        conn = sqlite3.connect(cls.db_path)
        
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
        test_risks = [
            ("Critical Security Vulnerability", 5, 5, 25, "High", "Immediate patching required", "Open"),
            ("Data Backup Failure", 4, 3, 12, "Medium", "Automated backup monitoring", "In Progress"),
            ("Minor UI Bug", 2, 2, 4, "Low", "User training provided", "Closed"),
            ("Network Outage Risk", 5, 2, 10, "Medium", "Redundant connections", "Open"),
            ("Compliance Gap", 3, 4, 12, "Medium", "Policy updates needed", "In Progress")
        ]
        
        for risk in test_risks:
            conn.execute(
                "INSERT INTO risks (description, impact, likelihood, score, level, control, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                risk
            )
        
        conn.commit()
        conn.close()
    
    def login(self, username, password):
        """Helper method to log in via the web interface."""
        self.driver.get(f"{self.base_url}/login")
        
        username_field = WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.ID, "username"))
        )
        password_field = self.driver.find_element(By.ID, "password")
        login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        
        username_field.clear()
        username_field.send_keys(username)
        password_field.clear()
        password_field.send_keys(password)
        login_button.click()
        
        # Wait for redirect
        WebDriverWait(self.driver, 10).until(
            lambda driver: driver.current_url != f"{self.base_url}/login"
        )
    
    def logout(self):
        """Helper method to log out via the web interface."""
        logout_link = self.driver.find_element(By.LINK_TEXT, "Logout")
        logout_link.click()

class TestUserAuthenticationFlow(IntegrationTestCase):
    """Test complete user authentication flows."""
    
    def test_complete_login_logout_flow(self):
        """Test complete login and logout flow."""
        # Navigate to login page
        self.driver.get(f"{self.base_url}/login")
        self.assertIn("Login", self.driver.title)
        
        # Perform login
        self.login("admin", "admin123")
        
        # Verify successful login
        self.assertIn("GRC Risk Register", self.driver.title)
        self.assertTrue(self.driver.find_element(By.LINK_TEXT, "Logout"))
        
        # Perform logout
        self.logout()
        
        # Verify successful logout
        self.assertIn("Login", self.driver.title)
    
    def test_invalid_login_flow(self):
        """Test invalid login attempt."""
        self.driver.get(f"{self.base_url}/login")
        
        # Attempt login with invalid credentials
        username_field = self.driver.find_element(By.ID, "username")
        password_field = self.driver.find_element(By.ID, "password")
        login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        
        username_field.send_keys("admin")
        password_field.send_keys("wrongpassword")
        login_button.click()
        
        # Verify error message
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "flash-message"))
        )
        error_message = self.driver.find_element(By.CLASS_NAME, "flash-message")
        self.assertIn("Invalid username or password", error_message.text)
    
    def test_protected_route_redirect(self):
        """Test that protected routes redirect to login."""
        self.driver.get(f"{self.base_url}/")
        
        # Should be redirected to login page
        WebDriverWait(self.driver, 10).until(
            lambda driver: "/login" in driver.current_url
        )
        self.assertIn("/login", self.driver.current_url)

class TestRiskManagementFlow(IntegrationTestCase):
    """Test complete risk management workflows."""
    
    def setUp(self):
        """Set up for each test method."""
        self.login("admin", "admin123")
    
    def tearDown(self):
        """Clean up after each test method."""
        try:
            self.logout()
        except:
            pass  # Ignore logout errors in teardown
    
    def test_complete_risk_creation_flow(self):
        """Test complete risk creation workflow."""
        # Navigate to add risk page
        add_risk_link = self.driver.find_element(By.LINK_TEXT, "Add Risk")
        add_risk_link.click()
        
        # Verify we're on the add risk page
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.ID, "description"))
        )
        self.assertIn("Add Risk", self.driver.page_source)
        
        # Fill out the risk form
        description_field = self.driver.find_element(By.ID, "description")
        impact_select = Select(self.driver.find_element(By.ID, "impact"))
        likelihood_select = Select(self.driver.find_element(By.ID, "likelihood"))
        control_field = self.driver.find_element(By.ID, "control")
        status_select = Select(self.driver.find_element(By.ID, "status"))
        submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        
        description_field.send_keys("Integration Test Risk")
        impact_select.select_by_value("4")
        likelihood_select.select_by_value("3")
        control_field.send_keys("Integration Test Control")
        status_select.select_by_value("Open")
        
        # Submit the form
        submit_button.click()
        
        # Verify redirect to dashboard and risk appears
        WebDriverWait(self.driver, 10).until(
            lambda driver: driver.current_url == f"{self.base_url}/"
        )
        self.assertIn("Integration Test Risk", self.driver.page_source)
    
    def test_risk_editing_flow(self):
        """Test complete risk editing workflow."""
        # Find and click edit link for first risk
        edit_link = WebDriverWait(self.driver, 10).until(
            EC.element_to_be_clickable((By.LINK_TEXT, "Edit"))
        )
        edit_link.click()
        
        # Verify we're on the edit page
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.ID, "description"))
        )
        self.assertIn("Edit Risk", self.driver.page_source)
        
        # Modify the risk
        description_field = self.driver.find_element(By.ID, "description")
        description_field.clear()
        description_field.send_keys("Updated Integration Test Risk")
        
        # Submit the changes
        submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_button.click()
        
        # Verify redirect and updated risk appears
        WebDriverWait(self.driver, 10).until(
            lambda driver: driver.current_url == f"{self.base_url}/"
        )
        self.assertIn("Updated Integration Test Risk", self.driver.page_source)
    
    def test_risk_filtering_flow(self):
        """Test risk filtering functionality."""
        # Test level filtering
        level_select = Select(self.driver.find_element(By.NAME, "level"))
        level_select.select_by_value("High")
        
        apply_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        apply_button.click()
        
        # Verify filtering works
        WebDriverWait(self.driver, 10).until(
            lambda driver: "level=High" in driver.current_url
        )
        self.assertIn("Critical Security Vulnerability", self.driver.page_source)
        
        # Reset filters
        reset_link = self.driver.find_element(By.LINK_TEXT, "Reset")
        reset_link.click()
        
        # Verify all risks are shown again
        WebDriverWait(self.driver, 10).until(
            lambda driver: driver.current_url == f"{self.base_url}/"
        )

class TestUserManagementFlow(IntegrationTestCase):
    """Test complete user management workflows."""
    
    def setUp(self):
        """Set up for each test method."""
        self.login("admin", "admin123")
    
    def tearDown(self):
        """Clean up after each test method."""
        try:
            self.logout()
        except:
            pass
    
    def test_user_management_access(self):
        """Test accessing user management as admin."""
        # Navigate to user management
        users_link = self.driver.find_element(By.LINK_TEXT, "Manage Users")
        users_link.click()
        
        # Verify we're on the user management page
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "table"))
        )
        self.assertIn("admin", self.driver.page_source)
        self.assertIn("user", self.driver.page_source)
    
    def test_add_user_flow(self):
        """Test complete user creation workflow."""
        # Navigate to user management
        users_link = self.driver.find_element(By.LINK_TEXT, "Manage Users")
        users_link.click()
        
        # Click add user button
        add_user_link = WebDriverWait(self.driver, 10).until(
            EC.element_to_be_clickable((By.LINK_TEXT, "Add User"))
        )
        add_user_link.click()
        
        # Fill out user form
        username_field = WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.ID, "username"))
        )
        password_field = self.driver.find_element(By.ID, "password")
        role_select = Select(self.driver.find_element(By.ID, "role"))
        submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        
        username_field.send_keys("testuser")
        password_field.send_keys("testpass123")
        role_select.select_by_value("user")
        submit_button.click()
        
        # Verify redirect and new user appears
        WebDriverWait(self.driver, 10).until(
            lambda driver: "/users" in driver.current_url and "add" not in driver.current_url
        )
        self.assertIn("testuser", self.driver.page_source)

class TestExportFlow(IntegrationTestCase):
    """Test export functionality workflows."""
    
    def setUp(self):
        """Set up for each test method."""
        self.login("admin", "admin123")
    
    def tearDown(self):
        """Clean up after each test method."""
        try:
            self.logout()
        except:
            pass
    
    def test_excel_export_flow(self):
        """Test Excel export functionality."""
        # Click Excel export button
        excel_link = self.driver.find_element(By.LINK_TEXT, "Export Excel")
        excel_link.click()
        
        # Wait a moment for download to initiate
        time.sleep(2)
        
        # Verify we're still on the dashboard (download should not redirect)
        self.assertEqual(self.driver.current_url, f"{self.base_url}/")
    
    def test_pdf_export_flow(self):
        """Test PDF export functionality."""
        # Click PDF export button
        pdf_link = self.driver.find_element(By.LINK_TEXT, "Export PDF")
        pdf_link.click()
        
        # Wait a moment for download to initiate
        time.sleep(2)
        
        # Verify we're still on the dashboard
        self.assertEqual(self.driver.current_url, f"{self.base_url}/")

class TestResponsiveDesign(IntegrationTestCase):
    """Test responsive design functionality."""
    
    def setUp(self):
        """Set up for each test method."""
        self.login("admin", "admin123")
    
    def tearDown(self):
        """Clean up after each test method."""
        try:
            self.logout()
        except:
            pass
    
    def test_mobile_viewport(self):
        """Test application in mobile viewport."""
        # Set mobile viewport
        self.driver.set_window_size(375, 667)  # iPhone 6/7/8 size
        
        # Navigate to dashboard
        self.driver.get(f"{self.base_url}/")
        
        # Verify mobile-friendly elements are present
        header = self.driver.find_element(By.TAG_NAME, "header")
        self.assertTrue(header.is_displayed())
        
        # Verify table is scrollable on mobile
        table_container = self.driver.find_element(By.CLASS_NAME, "table-container")
        self.assertTrue(table_container.is_displayed())
    
    def test_tablet_viewport(self):
        """Test application in tablet viewport."""
        # Set tablet viewport
        self.driver.set_window_size(768, 1024)  # iPad size
        
        # Navigate to dashboard
        self.driver.get(f"{self.base_url}/")
        
        # Verify layout adapts to tablet size
        filters = self.driver.find_element(By.CLASS_NAME, "filters")
        self.assertTrue(filters.is_displayed())

class TestPerformanceFlow(IntegrationTestCase):
    """Test performance-related functionality."""
    
    def setUp(self):
        """Set up for each test method."""
        self.login("admin", "admin123")
    
    def tearDown(self):
        """Clean up after each test method."""
        try:
            self.logout()
        except:
            pass
    
    def test_health_check_endpoint(self):
        """Test health check endpoint accessibility."""
        self.driver.get(f"{self.base_url}/health")
        
        # Verify health check returns JSON
        page_source = self.driver.page_source
        self.assertIn("healthy", page_source)
        self.assertIn("timestamp", page_source)
    
    def test_metrics_endpoint_access(self):
        """Test metrics endpoint for admin users."""
        self.driver.get(f"{self.base_url}/metrics")
        
        # Verify metrics data is returned
        page_source = self.driver.page_source
        self.assertIn("database", page_source)
        self.assertIn("performance", page_source)

if __name__ == '__main__':
    # Run integration tests
    unittest.main(verbosity=2)

