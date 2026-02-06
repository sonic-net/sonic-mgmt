#!/usr/bin/env python3

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
import os
import pyotp
import qrcode
import io
import base64
import logging
from functools import wraps
import yaml
import secrets
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import zipfile
import subprocess
import shutil

app = Flask(__name__, template_folder='templates')

# Configure upload settings
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'xml', 'zip'}
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def setup_logging():
    """Configure console logging based on FLASK_ENV environment variable."""
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
    ))

    # Set log level based on FLASK_ENV environment variable
    flask_env = os.environ.get('FLASK_ENV', 'production')
    if flask_env == 'development':
        console_handler.setLevel(logging.DEBUG)
        app.logger.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
        app.logger.setLevel(logging.INFO)

    app.logger.addHandler(console_handler)
    app.logger.info('SONiC Test Results Uploader startup')


# Initialize logging
setup_logging()

# TOTP configuration
APP_NAME = 'SONiC Test Results Uploader'
ISSUER_NAME = 'SONiC Management'

# Initialize storage
try:
    from azure_storage import get_user_storage
    user_storage = get_user_storage()
    app.logger.info('Azure user storage initialized successfully')
except Exception as e:
    app.logger.error(f'Failed to initialize Azure storage: {e}')
    raise SystemExit(f"Application startup failed: Azure storage initialization error - {e}")

# Configure secret key for sessions from Key Vault
try:
    app.secret_key = user_storage.get_flask_secret_key()
    app.logger.info('Flask secret key retrieved from Key Vault successfully')
except Exception as e:
    app.logger.error(f'Failed to get Flask secret key from Key Vault: {e}')
    raise SystemExit(f"Application startup failed: Flask secret key initialization error - {e}")


def get_user(username: str):
    """Get user from Azure storage."""
    return user_storage.get_user(username)


def update_user(username: str, **kwargs):
    """Update user in Azure storage."""
    return user_storage.update_user(username, **kwargs)


def is_administrator(username: str) -> bool:
    """Check if username is in administrators.yml."""
    try:
        administrators_file = os.path.join(os.path.dirname(__file__), 'administrators.yml')
        with open(administrators_file, 'r') as f:
            administrators = yaml.safe_load(f)
        return username in administrators
    except Exception as e:
        app.logger.error(f'Failed to load administrators.yml: {e}')
        return False


def is_password_strong(password: str) -> tuple[bool, str]:
    """Check if password meets strength requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    if not has_upper:
        return False, "Password must contain at least one uppercase letter"
    if not has_lower:
        return False, "Password must contain at least one lowercase letter"
    if not has_digit:
        return False, "Password must contain at least one digit"

    return True, "Password is strong"


def create_user(username: str, initial_password: str) -> bool:
    """Create a new user in Azure storage."""
    return user_storage.create_user(username, initial_password, totp_enabled=False)


def delete_user(username: str) -> bool:
    """Delete a user from Azure storage."""
    return user_storage.delete_user(username) if hasattr(user_storage, 'delete_user') else False


def reset_user(username: str, new_password: str) -> bool:
    """Reset a user's TOTP settings and password."""
    return user_storage.update_user(
        username,
        totp_enabled=False,
        totp_secret=None,
        initial_password=new_password
    )


def get_all_users() -> list:
    """Get all users from Azure storage."""
    return user_storage.get_all_users() if hasattr(user_storage, 'get_all_users') else []


def generate_random_password() -> str:
    """Generate a secure random password."""
    # Generate a secure random password using secrets module
    return secrets.token_urlsafe()


def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_user_cluster_config(username: str, database_override: str = None) -> tuple[str, str]:
    """Map username to cluster URL and database name based on email domain.

    Args:
        username: Username in format "name@company.com"
        database_override: Optional database name override for admin users

    Returns:
        tuple: (cluster_url, database_name)
    """
    # Default values
    default_cluster = "https://ingest-vendortestcluster.westus2.kusto.windows.net"
    default_database = "SampleTestData"

    # If database override is provided (admin user), use it with appropriate cluster
    if database_override:
        # Try to find the cluster for the overridden database from mappings
        try:
            mappings_file = os.path.join(os.path.dirname(__file__), 'company-mappings.yml')
            with open(mappings_file, 'r') as f:
                company_mappings = yaml.safe_load(f)

            # Find the cluster for the overridden database
            for domain, (cluster, database) in company_mappings.items():
                if database == database_override:
                    return cluster, database_override

        except Exception as e:
            app.logger.error(f'Failed to load company mappings for database override: {e}')

        # If not found in mappings, use default cluster with override database
        return default_cluster, database_override

    # Extract domain from username
    if '@' not in username:
        # If no domain, use default
        return default_cluster, default_database

    domain = username.split('@')[1].lower()

    # Load company mappings from YAML file
    try:
        mappings_file = os.path.join(os.path.dirname(__file__), 'company-mappings.yml')
        with open(mappings_file, 'r') as f:
            company_mappings = yaml.safe_load(f)

        # Return company-specific mapping if found
        if domain in company_mappings:
            cluster, database = company_mappings[domain]
            return cluster, database

    except Exception as e:
        app.logger.error(f'Failed to load company mappings from YAML file: {e}')

    # Return default if domain not found or YAML loading failed
    return default_cluster, default_database


def extract_zip_files(upload_folder: str, uploaded_files: list) -> list:
    """Extract all ZIP files in the uploaded files list.

    Args:
        upload_folder: Directory containing uploaded files
        uploaded_files: List of uploaded file info dictionaries

    Returns:
        list: List of extraction results with status and details
    """
    extraction_results = []

    for file_info in uploaded_files:
        filename = file_info['filename']
        if not filename.lower().endswith('.zip'):
            continue

        file_path = os.path.join(upload_folder, filename)
        extract_dir = os.path.join(upload_folder, f"{filename}_extracted")

        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Create extraction directory
                os.makedirs(extract_dir, exist_ok=True)

                # Extract all files
                zip_ref.extractall(extract_dir)

                # Get list of extracted files
                extracted_files = []
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        extracted_files.append(os.path.relpath(os.path.join(root, file), extract_dir))

                extraction_results.append({
                    'zip_file': filename,
                    'success': True,
                    'extract_dir': extract_dir,
                    'extracted_files': extracted_files,
                    'extracted_count': len(extracted_files)
                })

                app.logger.info(f'Successfully extracted {len(extracted_files)} files from {filename}')

        except Exception as e:
            extraction_results.append({
                'zip_file': filename,
                'success': False,
                'error': str(e)
            })
            app.logger.error(f'Failed to extract {filename}: {str(e)}')

    return extraction_results


def cleanup_extracted_files(extraction_results: list) -> dict:
    """Delete extracted directories after processing is complete.

    Args:
        extraction_results: List of extraction results from extract_zip_files

    Returns:
        dict: Cleanup results with deleted directories and any errors
    """
    cleanup_results = {
        'deleted_directories': [],
        'errors': []
    }

    for result in extraction_results:
        if not result.get('success', False):
            continue

        extract_dir = result.get('extract_dir')
        if not extract_dir:
            continue

        try:
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
                cleanup_results['deleted_directories'].append(extract_dir)
                app.logger.info(f'Deleted extracted directory: {extract_dir}')
            else:
                app.logger.warning(f'Extracted directory not found for cleanup: {extract_dir}')
        except Exception as e:
            error_msg = f'Failed to delete {extract_dir}: {str(e)}'
            app.logger.error(error_msg)
            cleanup_results['errors'].append(error_msg)

    return cleanup_results


def cleanup_old_files(upload_folder: str, max_size_gb: float = 5.0) -> dict:
    """Delete oldest uploaded files (.xml and .zip) if upload folder exceeds size limit.

    Only processes files directly in upload_folder, not in subdirectories.
    Extracted directories are handled separately by cleanup_extracted_files().

    Args:
        upload_folder: Directory containing uploaded files
        max_size_gb: Maximum size in GB before cleanup (default: 5.0)

    Returns:
        dict: Cleanup results with total size, deleted files, and space freed
    """
    cleanup_results = {
        'total_size_gb': 0.0,
        'deleted_files': [],
        'space_freed_gb': 0.0,
        'cleanup_triggered': False
    }

    try:
        # Calculate total size of upload folder (including subdirectories for size calculation)
        total_size = 0
        for root, dirs, files in os.walk(upload_folder):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.exists(file_path):
                    total_size += os.path.getsize(file_path)

        # Track only files directly in upload_folder for potential deletion
        # (not in subdirectories like extracted directories)
        file_list = []
        for file in os.listdir(upload_folder):
            file_path = os.path.join(upload_folder, file)
            # Only process regular files (not directories)
            if os.path.isfile(file_path):
                # Track .xml and .zip files for potential deletion
                if file.lower().endswith(('.xml', '.zip')):
                    file_size = os.path.getsize(file_path)
                    file_mtime = os.path.getmtime(file_path)
                    file_list.append({
                        'path': file_path,
                        'size': file_size,
                        'mtime': file_mtime
                    })

        total_size_gb = total_size / (1024 ** 3)  # Convert to GB
        cleanup_results['total_size_gb'] = round(total_size_gb, 2)

        app.logger.info(f'Upload folder total size: {cleanup_results["total_size_gb"]} GB')

        # Check if cleanup is needed
        if total_size_gb > max_size_gb:
            cleanup_results['cleanup_triggered'] = True
            app.logger.warning(
                f'Upload folder size ({cleanup_results["total_size_gb"]} GB) exceeds limit '
                f'({max_size_gb} GB). Starting cleanup...'
            )

            # Sort files by modification time (oldest first)
            file_list.sort(key=lambda x: x['mtime'])

            space_freed = 0
            current_size = total_size

            # Delete oldest files until we're back under the limit
            for file_info in file_list:
                if current_size / (1024 ** 3) <= max_size_gb:
                    break

                try:
                    os.remove(file_info['path'])
                    space_freed += file_info['size']
                    current_size -= file_info['size']
                    cleanup_results['deleted_files'].append(os.path.basename(file_info['path']))
                    app.logger.info(
                        f'Deleted old file: {os.path.basename(file_info["path"])} '
                        f'({file_info["size"] / (1024 ** 2):.2f} MB)'
                    )
                except Exception as e:
                    app.logger.error(f'Failed to delete {file_info["path"]}: {str(e)}')

            cleanup_results['space_freed_gb'] = round(space_freed / (1024 ** 3), 2)
            app.logger.info(
                f'Cleanup completed: {len(cleanup_results["deleted_files"])} files deleted, '
                f'{cleanup_results["space_freed_gb"]} GB freed'
            )
        else:
            app.logger.info(
                f'No cleanup needed. Current size ({cleanup_results["total_size_gb"]} GB) '
                f'is below limit ({max_size_gb} GB)'
            )

    except Exception as e:
        app.logger.error(f'Error during disk cleanup: {str(e)}')
        cleanup_results['error'] = str(e)

    return cleanup_results


def run_report_uploader(upload_folder: str, database_name: str, cluster_url: str) -> dict:
    """Run the report_uploader.py script to upload test results to Kusto.

    Args:
        upload_folder: Directory containing uploaded files
        database_name: Kusto database name
        cluster_url: Kusto cluster URL

    Returns:
        dict: Execution results with command, stdout, stderr, and return code
    """
    try:
        # Set environment variable for Kusto cluster
        env = os.environ.copy()
        env['TEST_REPORT_INGEST_KUSTO_CLUSTER'] = cluster_url

        # Construct command
        script_path = os.path.join(os.path.dirname(__file__), '../report_uploader.py')
        cmd = [
            'python', script_path,
            '--category', 'test_result',
            '--auth_method', 'defaultCred',
            upload_folder,
            database_name
        ]

        # Run the command
        app.logger.info(f'Running report uploader: {" ".join(cmd)}')
        app.logger.info(f'Environment: TEST_REPORT_INGEST_KUSTO_CLUSTER={cluster_url}')

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            env=env
        )

        # Log the command execution results
        app.logger.info(f'Report uploader completed with return code: {result.returncode}')

        # Log stdout if present
        if result.stdout:
            app.logger.info(f'Report uploader stdout:\n{result.stdout}')
        else:
            app.logger.info('Report uploader stdout: (empty)')

        # Log stderr if present
        if result.stderr:
            app.logger.warning(f'Report uploader stderr:\n{result.stderr}')
        else:
            app.logger.info('Report uploader stderr: (empty)')

        return {
            'success': result.returncode == 0,
            'command': ' '.join(cmd),
            'environment': f'TEST_REPORT_INGEST_KUSTO_CLUSTER={cluster_url}',
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }

    except subprocess.TimeoutExpired:
        cmd_str = ' '.join(cmd) if 'cmd' in locals() else 'Unknown command'
        app.logger.error(f'Report uploader command timed out after 5 minutes for database: {database_name}')
        app.logger.error(f'Timed out command: {cmd_str}')
        return {
            'success': False,
            'command': cmd_str,
            'environment': f'TEST_REPORT_INGEST_KUSTO_CLUSTER={cluster_url}',
            'return_code': -1,
            'stdout': '',
            'stderr': 'Command timed out after 5 minutes'
        }
    except Exception as e:
        cmd_str = ' '.join(cmd) if 'cmd' in locals() else 'Failed to construct command'
        app.logger.error(f'Report uploader error for database {database_name}: {str(e)}')
        app.logger.error(f'Failed command: {cmd_str}')
        return {
            'success': False,
            'command': cmd_str,
            'environment': f'TEST_REPORT_INGEST_KUSTO_CLUSTER={cluster_url}',
            'return_code': -1,
            'stdout': '',
            'stderr': str(e)
        }


def require_admin(f):
    """Decorator to require admin authentication for protected endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))

        # Check if user exists and is fully authenticated
        user = get_user(username)
        if not user:
            session.clear()
            return redirect(url_for('login'))

        # Check if user is an administrator
        if not is_administrator(username):
            app.logger.warning(f'Non-administrator {username} attempted to access admin endpoint')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function


def require_auth(f):
    """Decorator to require authentication for protected endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        if not username:
            return redirect(url_for('login'))

        # Check if user exists and is fully authenticated
        user = get_user(username)
        if not user:
            session.clear()
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function


def generate_qr_code_data_url(secret, username):
    """Generate QR code data URL for TOTP setup."""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=ISSUER_NAME
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64 data URL
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)

    img_data = base64.b64encode(img_buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_data}"


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Basic login page - username only."""
    if request.method == 'GET':
        # Check if already logged in
        if session.get('username'):
            return redirect(url_for('index'))
        return render_template('login.html')

    # Handle POST request - username validation only
    try:
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')

        app.logger.info(f'Login attempt for username: {username}')

        if not username:
            app.logger.warning('Login attempt with empty username')
            if request.is_json:
                return jsonify({'error': 'Username is required'}), 400
            else:
                return render_template('login.html', error='Username is required')

        user = get_user(username)

        # Check if username is an administrator
        if is_administrator(username):
            # For administrators, check if user exists
            if not user:
                # Administrator user doesn't exist, redirect to register
                app.logger.info(f'Administrator {username} not found, redirecting to register')
                if request.is_json:
                    return jsonify({'redirect': f'/register?username={username}'})
                else:
                    return redirect(url_for('register', username=username))
            # Administrator user exists, proceed with normal logic
        else:
            # For non-administrators, proceed with original logic
            if not user:
                app.logger.warning(f'Login attempt with invalid username: {username}')
                error_msg = 'Invalid username'
                if request.is_json:
                    return jsonify({'error': error_msg}), 401
                else:
                    return render_template('login.html', error=error_msg)

        # Check if TOTP is enabled and redirect accordingly
        if user['totp_enabled']:
            app.logger.info(f'Redirecting user {username} to TOTP code entry')
            if request.is_json:
                return jsonify({'redirect': f'/login-code?username={username}'})
            else:
                return redirect(url_for('login_code', username=username))
        else:
            app.logger.info(f'Redirecting user {username} to initial password setup')
            if request.is_json:
                return jsonify({'redirect': '/login-setup'})
            else:
                return redirect(url_for('login_setup', username=username))

    except Exception as e:
        app.logger.error(f'Login error: {str(e)}')
        error_msg = 'Authentication failed'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            return render_template('login.html', error=error_msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page for administrators."""
    # Get username from URL parameter
    username = request.args.get('username')
    if not username:
        app.logger.warning('Register page accessed without username parameter')
        return redirect(url_for('login'))

    # Verify user is an administrator
    if not is_administrator(username):
        app.logger.warning(f'Non-administrator {username} attempted to access register page')
        return redirect(url_for('login'))

    # Check if user already exists
    user = get_user(username)
    if user:
        app.logger.info(f'Administrator {username} already exists, redirecting to login')
        return redirect(url_for('login'))

    if request.method == 'GET':
        app.logger.info(f'Register page accessed for administrator: {username}')
        return render_template('register.html', username=username)

    # Handle POST - process registration
    try:
        data = request.get_json() if request.is_json else request.form
        password = data.get('password')
        confirm_password = data.get('confirmPassword')

        app.logger.info(f'Registration attempt for administrator: {username}')

        if not password:
            error_msg = 'Password is required'
            app.logger.warning(f'Empty password submitted for registration: {username}')
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                return render_template('register.html', username=username, error=error_msg)

        if not confirm_password:
            error_msg = 'Password confirmation is required'
            app.logger.warning(f'Empty password confirmation for registration: {username}')
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                return render_template('register.html', username=username, error=error_msg)

        if password != confirm_password:
            error_msg = 'Passwords do not match'
            app.logger.warning(f'Password mismatch during registration: {username}')
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                return render_template('register.html', username=username, error=error_msg)

        # Verify password strength
        is_strong, strength_message = is_password_strong(password)
        if not is_strong:
            app.logger.warning(f'Weak password submitted for registration: {username}')
            if request.is_json:
                return jsonify({'error': strength_message}), 400
            else:
                return render_template('register.html', username=username, error=strength_message)

        # Create the user
        success = create_user(username, password)
        if success:
            app.logger.info(f'Administrator {username} registered successfully')
            if request.is_json:
                return jsonify({'success': True, 'redirect': f'/login-setup?username={username}'})
            else:
                return redirect(url_for('login_setup', username=username))
        else:
            error_msg = 'Failed to create user account. Please try again.'
            app.logger.error(f'Failed to create administrator account: {username}')
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                return render_template('register.html', username=username, error=error_msg)

    except Exception as e:
        app.logger.error(f'Registration error for administrator {username}: {str(e)}')
        error_msg = 'Registration failed due to system error'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            return render_template('register.html', username=username, error=error_msg)


@app.route('/admin', methods=['GET', 'POST'])
@require_admin
def admin():
    """Admin panel for user management."""
    if request.method == 'GET':
        # Get all users and their administrator status
        users = get_all_users()
        for user in users:
            user['is_admin'] = is_administrator(user['username'])

        app.logger.info(f'Admin panel accessed by: {session.get("username")}')
        return render_template('admin.html', users=users)

    # Handle POST requests for user operations
    try:
        data = request.get_json() if request.is_json else request.form
        action = data.get('action')
        username = data.get('username')

        admin_user = session.get('username')
        app.logger.info(f'Admin operation {action} for user {username} by {admin_user}')

        if action == 'delete':
            if not username:
                return jsonify({'error': 'Username is required'}), 400

            # Prevent self-deletion
            if username == admin_user:
                return jsonify({'error': 'Cannot delete your own account'}), 400

            success = delete_user(username)
            if success:
                app.logger.info(f'User {username} deleted by admin {admin_user}')
                return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
            else:
                return jsonify({'error': 'Failed to delete user'}), 500

        elif action == 'create':
            new_username = data.get('new_username')
            if not new_username:
                return jsonify({'error': 'Username is required'}), 400

            # Check if user already exists
            if get_user(new_username):
                return jsonify({'error': 'User already exists'}), 400

            # Generate random password
            new_password = generate_random_password()

            success = create_user(new_username, new_password)
            if success:
                app.logger.info(f'User {new_username} created by admin {admin_user}')
                return jsonify({
                    'success': True,
                    'message': f'User {new_username} created successfully',
                    'password': new_password,
                    'username': new_username
                })
            else:
                return jsonify({'error': 'Failed to create user'}), 500

        elif action == 'reset':
            if not username:
                return jsonify({'error': 'Username is required'}), 400

            # Generate new password
            new_password = generate_random_password()

            success = reset_user(username, new_password)
            if success:
                app.logger.info(f'User {username} reset by admin {admin_user}')
                return jsonify({
                    'success': True,
                    'message': f'User {username} reset successfully',
                    'password': new_password,
                    'username': username
                })
            else:
                return jsonify({'error': 'Failed to reset user'}), 500

        else:
            return jsonify({'error': 'Invalid action'}), 400

    except Exception as e:
        app.logger.error(f'Admin operation error: {str(e)}')
        return jsonify({'error': 'Operation failed due to system error'}), 500


@app.route('/files', methods=['GET'])
@require_admin
def files_page():
    """Admin page to view and download uploaded files."""
    username = session.get('username')
    app.logger.info(f'Files page accessed by admin: {username}')
    return render_template('files.html', username=username, app_name=APP_NAME)


def validate_file_path(filename: str, upload_folder: str, admin_user: str) -> tuple:
    """Validate filename and return file path, or error response.

    Args:
        filename: The filename to validate
        upload_folder: The upload folder path
        admin_user: The admin username for logging

    Returns:
        tuple: (file_path, error_response) - file_path is None if validation fails
    """
    if not filename:
        app.logger.warning(f'File operation without filename by admin: {admin_user}')
        return None, (jsonify({'error': 'Filename parameter is required'}), 400)

    # Security: Check for path traversal patterns
    # Check for directory traversal sequences like '../', '..\\', or path separators
    if '../' in filename or '..\\' in filename or filename.startswith(('/', '\\')) or os.sep in filename:
        app.logger.warning(f'Potential path traversal attempt by admin {admin_user}: {filename}')
        return None, (jsonify({'error': 'Invalid filename'}), 400)

    # Check if file exists
    file_path = os.path.join(upload_folder, filename)
    if not os.path.exists(file_path):
        app.logger.warning(f'File not found: {filename}')
        return None, (jsonify({'error': 'File not found'}), 404)

    # Ensure the resolved path is still within upload folder (prevent path traversal)
    if not os.path.abspath(file_path).startswith(os.path.abspath(upload_folder)):
        app.logger.warning(f'Path traversal attempt detected by admin {admin_user}: {filename}')
        return None, (jsonify({'error': 'Invalid file path'}), 400)

    return file_path, None


@app.route('/uploaded_files', methods=['GET', 'DELETE'])
@require_admin
def uploaded_files():
    """Admin endpoint to list all uploaded files, download a specific file, or delete a specific file.

    - GET /uploaded_files -> Returns JSON list of all files
    - GET /uploaded_files?filename=xyz.xml -> Downloads the specified file
    - DELETE /uploaded_files?filename=xyz.xml -> Deletes the specified file
    """
    try:
        admin_user = session.get('username')
        filename = request.args.get('filename')
        upload_folder = app.config['UPLOAD_FOLDER']

        # Handle DELETE request
        if request.method == 'DELETE':
            app.logger.info(f'File deletion requested by admin {admin_user}: {filename}')

            file_path, error_response = validate_file_path(filename, upload_folder, admin_user)
            if error_response:
                return error_response

            # Delete the file
            try:
                file_size = os.path.getsize(file_path)
                os.remove(file_path)
                app.logger.info(
                    f'File deleted successfully by admin {admin_user}: {filename} '
                    f'({file_size / (1024 ** 2):.2f} MB)'
                )
                return jsonify({
                    'success': True,
                    'message': f'File {filename} deleted successfully',
                    'deleted_file': filename,
                    'size_freed_mb': round(file_size / (1024 ** 2), 2)
                }), 200
            except Exception as e:
                app.logger.error(f'Failed to delete file {filename} by admin {admin_user}: {str(e)}')
                return jsonify({'error': f'Failed to delete file: {str(e)}'}), 500

        # Handle GET request with filename - download the file
        if filename:
            app.logger.info(f'File download requested by admin {admin_user}: {filename}')

            file_path, error_response = validate_file_path(filename, upload_folder, admin_user)
            if error_response:
                return error_response

            app.logger.info(f'File download started by admin {admin_user}: {filename}')
            return send_from_directory(upload_folder, os.path.basename(file_path), as_attachment=True)

        # Handle GET request without filename - list all files
        app.logger.info(f'Uploaded files list requested by admin: {admin_user}')

        files_info = []

        # Walk through the upload folder and collect file information
        for root, dirs, files in os.walk(upload_folder):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                        file_mtime = os.path.getmtime(file_path)
                        file_ctime = os.path.getctime(file_path)

                        # Convert timestamps to ISO format
                        modified_time = datetime.fromtimestamp(file_mtime, timezone.utc).isoformat()
                        created_time = datetime.fromtimestamp(file_ctime, timezone.utc).isoformat()

                        # Get relative path from upload folder
                        relative_path = os.path.relpath(file_path, upload_folder)

                        files_info.append({
                            'filename': file,
                            'relative_path': relative_path,
                            'size_bytes': file_size,
                            'size_mb': round(file_size / (1024 ** 2), 2),
                            'modified_time': modified_time,
                            'created_time': created_time,
                            'file_type': os.path.splitext(file)[1].lower()
                        })
                except Exception as e:
                    app.logger.error(f'Error reading file info for {file_path}: {str(e)}')

        # Sort by modified time (newest first)
        files_info.sort(key=lambda x: x['modified_time'], reverse=True)

        # Calculate total size
        total_size_bytes = sum(f['size_bytes'] for f in files_info)
        total_size_gb = round(total_size_bytes / (1024 ** 3), 2)

        app.logger.info(f'Uploaded files list: {len(files_info)} files, {total_size_gb} GB total')

        return jsonify({
            'success': True,
            'total_files': len(files_info),
            'total_size_bytes': total_size_bytes,
            'total_size_gb': total_size_gb,
            'files': files_info
        }), 200

    except Exception as e:
        app.logger.error(f'Error in uploaded_files endpoint: {str(e)}')
        return jsonify({
            'success': False,
            'error': f'Operation failed: {str(e)}'
        }), 500


@app.route('/login-setup', methods=['GET', 'POST'])
def login_setup():
    """Login with initial password."""
    username = session.get('username')

    # If username is in session, authentication passed, redirect to index
    if username:
        return redirect(url_for('index'))

    # Check if username is in URL parameters
    url_username = request.args.get('username')
    if url_username:
        user = get_user(url_username)
        if not user:
            return redirect(url_for('login'))

        # If TOTP is already enabled, redirect to code entry
        if user['totp_enabled']:
            return redirect(url_for('login_code'))

        if request.method == 'GET':
            return render_template('login-setup.html', username=url_username)
    else:
        # No username in session or args, redirect to login
        return redirect(url_for('login'))

    # Handle POST - validate initial password
    try:
        data = request.get_json() if request.is_json else request.form
        password = data.get('password')

        app.logger.info(f'Initial password validation attempt for user: {url_username}')

        if not password:
            app.logger.warning(f'Empty password submitted for user: {url_username}')
            error_msg = 'Password is required'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                return render_template('login-setup.html', username=url_username, error=error_msg)

        # Validate initial password
        if password != user['initial_password']:
            app.logger.warning(f'Invalid initial password for user: {url_username}')
            error_msg = 'Invalid password'
            if request.is_json:
                return jsonify({'error': error_msg}), 401
            else:
                return render_template('login-setup.html', username=url_username, error=error_msg)

        # Password is correct, redirect to setup with username
        app.logger.info(f'Initial password validated successfully for user: {url_username}')
        if request.is_json:
            return jsonify({'success': True, 'redirect': f'/setup?username={url_username}'})
        else:
            return redirect(url_for('setup', username=url_username))

    except Exception as e:
        app.logger.error(f'Login setup error for user {url_username}: {str(e)}')
        error_msg = 'Authentication failed'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            return render_template('login-setup.html', username=url_username, error=error_msg)


@app.route('/login-code', methods=['GET', 'POST'])
def login_code():
    """Login with TOTP code."""
    # Check username in URL parameter
    username = request.args.get('username')
    if not username:
        app.logger.warning('Login code page accessed without username parameter')
        return redirect(url_for('login'))

    # Validate user exists
    user = get_user(username)
    if not user:
        app.logger.warning(f'Login code page accessed with invalid username: {username}')
        return redirect(url_for('login'))

    # Check if TOTP is enabled, if not redirect to login-setup
    if not user['totp_enabled']:
        app.logger.info(f'Login code page accessed for user without TOTP enabled: {username}')
        return redirect(url_for('login_setup', username=username))

    if request.method == 'GET':
        app.logger.info(f'Login code page accessed for user: {username}')
        return render_template('login-code.html', username=username)

    # Handle POST - validate TOTP code
    try:
        data = request.get_json() if request.is_json else request.form
        code = data.get('code')

        app.logger.info(f'TOTP code verification attempt for user: {username}')

        if not code:
            app.logger.warning(f'Empty TOTP code submitted for user: {username}')
            error_msg = 'TOTP code is required'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                return render_template('login-code.html', username=username, error=error_msg)

        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(code, valid_window=1):
            app.logger.warning(f'Invalid TOTP code for user: {username}')
            error_msg = 'Invalid authentication code'
            if request.is_json:
                return jsonify({'error': error_msg}), 401
            else:
                return render_template('login-code.html', username=username, error=error_msg)

        # Code is valid, store username in session and redirect to index
        session['username'] = username

        # Update last login time
        last_login_time = datetime.now(timezone.utc).isoformat()
        update_user(username, last_login=last_login_time)

        app.logger.info(f'TOTP authentication successful for user: {username}, last login updated')

        if request.is_json:
            return jsonify({'success': True, 'redirect': '/'})
        else:
            return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f'Login code error for user {username}: {str(e)}')
        error_msg = 'Authentication failed'
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            return render_template('login-code.html', username=username, error=error_msg)


@app.route('/setup', methods=['GET'])
def setup():
    """TOTP setup page."""
    # Get username from URL parameter
    username = request.args.get('username')
    if not username:
        app.logger.warning('Setup page accessed without username parameter')
        return redirect(url_for('login'))

    # Check if username exists
    user = get_user(username)
    if not user:
        app.logger.warning(f'Setup page accessed with invalid username: {username}')
        return redirect(url_for('login'))

    # If TOTP is already enabled, redirect to login-code
    if user['totp_enabled']:
        app.logger.info(f'Setup page accessed for user with TOTP already enabled: {username}')
        return redirect(url_for('login_code', username=username))

    app.logger.info(f'TOTP setup page accessed for user: {username}')

    # Generate TOTP secret if not exists
    if not user['totp_secret']:
        new_secret = pyotp.random_base32()
        update_user(username, totp_secret=new_secret)
        user['totp_secret'] = new_secret  # Update local copy for immediate use
        app.logger.info(f'Generated new TOTP secret for user: {username}')
    else:
        app.logger.debug(f'Using existing TOTP secret for user: {username}')

    qr_code_url = generate_qr_code_data_url(user['totp_secret'], username)
    app.logger.info(f'QR code generated for user: {username}')

    return render_template(
        'setup.html',
        qr_code_url=qr_code_url,
        secret=user['totp_secret'],
        username=username,
        app_name=APP_NAME,
        issuer=ISSUER_NAME
    )


@app.route('/complete-setup', methods=['POST'])
def complete_setup():
    """Handle TOTP setup completion."""
    # Get username from URL parameter
    username = request.args.get('username')
    if not username:
        app.logger.warning('Complete setup accessed without username parameter')
        return jsonify({'error': 'Username is required'}), 400

    # Check if username exists
    user = get_user(username)
    if not user:
        app.logger.warning(f'Complete setup accessed with invalid username: {username}')
        return jsonify({'error': 'Invalid username'}), 400

    # If TOTP is already enabled, redirect to login-code
    if user['totp_enabled']:
        app.logger.info(f'Complete setup accessed for user with TOTP already enabled: {username}')
        return jsonify({'redirect': f'/login-code?username={username}'})

    try:
        app.logger.info(f'TOTP setup completion attempt for user: {username}')

        # Try to get JSON data first, fallback to form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        if not data:
            app.logger.warning(f'No data received for TOTP setup completion for user: {username}')
            return jsonify({'error': 'No data received'}), 400

        code = data.get('code')
        if not code:
            app.logger.warning(f'No TOTP code provided for user: {username}')
            return jsonify({'error': 'TOTP code is required'}), 400

        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(code, valid_window=1):
            app.logger.warning(f'Invalid TOTP code for user: {username}')
            return jsonify({'error': 'Invalid authentication code'}), 400

        # 1. Set TOTP enabled to true and delete initial password for the user
        last_login_time = datetime.now(timezone.utc).isoformat()
        update_user(username, totp_enabled=True, initial_password=None, last_login=last_login_time)
        app.logger.info(
            f'TOTP enabled successfully, initial password deleted, '
            f'and last login updated for user: {username}'
        )

        # 2. Store username in session to indicate authentication passed
        session['username'] = username
        app.logger.info(f'User {username} authenticated and session created')

        return jsonify({'success': True, 'redirect': '/'})

    except Exception as e:
        app.logger.error(f'TOTP setup completion error for user {username}: {str(e)}')
        app.logger.debug(f'TOTP setup completion traceback for user {username}:', exc_info=True)
        return jsonify({'error': f'Setup failed: {str(e)}'}), 500


@app.route('/logout')
def logout():
    """Logout endpoint."""
    username = session.get('username')
    session.clear()
    app.logger.info(f'User logged out: {username}')
    return redirect(url_for('login'))


@app.route('/')
@require_auth
def index():
    """Main page with file upload form."""
    username = session.get('username')
    is_admin = is_administrator(username)

    # Get database options for admin users
    database_options = []
    if is_admin:
        try:
            # Load company mappings from YAML file
            mappings_file = os.path.join(os.path.dirname(__file__), 'company-mappings.yml')
            with open(mappings_file, 'r') as f:
                company_mappings = yaml.safe_load(f)

            # Extract unique database names
            databases = set()
            for domain, (cluster, database) in company_mappings.items():
                databases.add(database)

            # Sort databases alphabetically
            database_options = sorted(list(databases))
            app.logger.info(f'Admin user {username} loaded database options: {database_options}')

        except Exception as e:
            app.logger.error(f'Failed to load database options for admin {username}: {e}')
            database_options = []

    app.logger.info(f'Main page accessed by user: {username} (admin: {is_admin})')
    return render_template('index.html', username=username, is_admin=is_admin, database_options=database_options)


@app.route('/upload', methods=['POST'])
@require_auth
def upload_file():
    """Handle file uploads for .xml and .zip files (supports multiple files)."""
    username = session.get('username')

    try:
        # Check if the post request has the file part
        if 'file' not in request.files:
            app.logger.warning(f'Upload attempt without file by user: {username}')
            return jsonify({'error': 'No file part in the request'}), 400

        uploaded_files = request.files.getlist('file')

        # Get database selection from form (admin feature)
        database_override = request.form.get('database_selection', '').strip()
        if database_override == '':  # Empty string means use default mapping
            database_override = None
        app.logger.info(f'User {username} database selection: {database_override or "default mapping"}')

        # Check if any files were selected
        if not uploaded_files or all(f.filename == '' for f in uploaded_files):
            app.logger.warning(f'Upload attempt with no files selected by user: {username}')
            return jsonify({'error': 'No files selected'}), 400

        successful_uploads = []
        failed_uploads = []

        for uploaded_file in uploaded_files:
            # Skip empty file entries
            if uploaded_file.filename == '':
                continue

            try:
                # Check if file type is allowed
                if not allowed_file(uploaded_file.filename):
                    app.logger.warning(
                        f'Upload attempt with invalid file type {uploaded_file.filename} '
                        f'by user: {username}'
                    )
                    failed_uploads.append({
                        'original_filename': uploaded_file.filename,
                        'error': 'File type not allowed. Only .xml and .zip files are supported'
                    })
                    continue

                # Secure the filename and add timestamp to avoid conflicts
                original_filename = secure_filename(uploaded_file.filename)
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')[:-3]  # Include milliseconds
                filename = f"{timestamp}_{username}_{original_filename}"

                # Save the file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded_file.save(file_path)

                # Get file size
                file_size = os.path.getsize(file_path)

                app.logger.info(f'File uploaded successfully: {filename} ({file_size} bytes) by user: {username}')

                successful_uploads.append({
                    'filename': filename,
                    'original_filename': original_filename,
                    'file_size': file_size,
                    'upload_time': datetime.now(timezone.utc).isoformat()
                })

            except Exception as file_error:
                app.logger.error(
                    f'Error uploading file {uploaded_file.filename} for user {username}: '
                    f'{str(file_error)}'
                )
                failed_uploads.append({
                    'original_filename': uploaded_file.filename,
                    'error': f'Upload failed: {str(file_error)}'
                })

        # Prepare response
        total_files = len(successful_uploads) + len(failed_uploads)

        # Get user's cluster configuration
        cluster_url, database_name = get_user_cluster_config(username, database_override)
        app.logger.info(f'User {username} mapped to cluster: {cluster_url}, database: {database_name}')

        # Post-processing results
        processing_results = {
            'zip_extraction': [],
            'report_upload': None
        }

        if successful_uploads:
            # Step 1: Extract ZIP files
            app.logger.info(f'Starting ZIP file extraction for {len(successful_uploads)} files...')
            extraction_results = extract_zip_files(app.config['UPLOAD_FOLDER'], successful_uploads)
            processing_results['zip_extraction'] = extraction_results
            app.logger.info(f'ZIP extraction completed: {len(extraction_results)} results')

            # Step 2: Run report uploader
            app.logger.info(f'Starting report upload to Kusto for user {username}...')
            upload_result = run_report_uploader(
                app.config['UPLOAD_FOLDER'],
                database_name,
                cluster_url
            )
            processing_results['report_upload'] = upload_result
            app.logger.info(f'Report upload completed with status: {upload_result.get("success", False)}')

            # Step 3: Cleanup extracted files after upload completes
            app.logger.info('Starting cleanup of extracted files...')
            cleanup_result = cleanup_extracted_files(extraction_results)
            processing_results['cleanup'] = cleanup_result
            app.logger.info(
                f'Cleanup completed: {len(cleanup_result["deleted_directories"])} directories deleted, '
                f'{len(cleanup_result["errors"])} errors'
            )

            # Step 4: Cleanup old files (.xml and .zip) if disk usage exceeds 5GB
            app.logger.info('Checking disk usage and cleaning up old files if needed...')
            disk_cleanup_result = cleanup_old_files(app.config['UPLOAD_FOLDER'], max_size_gb=5.0)
            processing_results['disk_cleanup'] = disk_cleanup_result
            if disk_cleanup_result['cleanup_triggered']:
                app.logger.info(
                    f'Disk cleanup completed: {len(disk_cleanup_result["deleted_files"])} files deleted, '
                    f'{disk_cleanup_result["space_freed_gb"]} GB freed'
                )

        if successful_uploads and not failed_uploads:
            # All files uploaded successfully
            return jsonify({
                'success': True,
                'message': f'All {len(successful_uploads)} file(s) uploaded successfully',
                'uploaded_files': successful_uploads,
                'total_files': total_files,
                'successful_count': len(successful_uploads),
                'failed_count': 0,
                'cluster_url': cluster_url,
                'database_name': database_name,
                'processing_results': processing_results
            }), 200
        elif successful_uploads and failed_uploads:
            # Some files uploaded successfully, some failed
            return jsonify({
                'success': True,
                'message': f'{len(successful_uploads)} file(s) uploaded successfully, {len(failed_uploads)} failed',
                'uploaded_files': successful_uploads,
                'failed_files': failed_uploads,
                'total_files': total_files,
                'successful_count': len(successful_uploads),
                'failed_count': len(failed_uploads),
                'cluster_url': cluster_url,
                'database_name': database_name,
                'processing_results': processing_results
            }), 207  # 207 Multi-Status
        else:
            # All files failed
            return jsonify({
                'success': False,
                'message': f'All {len(failed_uploads)} file(s) failed to upload',
                'failed_files': failed_uploads,
                'total_files': total_files,
                'successful_count': 0,
                'failed_count': len(failed_uploads),
                'cluster_url': cluster_url,
                'database_name': database_name,
                'processing_results': processing_results
            }), 400

    except Exception as e:
        app.logger.error(f'Upload error for user {username}: {str(e)}')
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


@app.route('/health')
def health():
    """Health check endpoint."""
    return {'status': 'healthy', 'app': 'sonic-test-uploader'}


@app.route('/reset')
def reset():
    """TEMPORARY DEBUG ENDPOINT: Reset all data - delete all users and secrets."""
    try:
        # Check for required key parameter
        key = request.args.get('key')
        if not key:
            app.logger.warning("RESET ENDPOINT ACCESS DENIED - No key provided")
            return {
                'status': 'error',
                'message': 'Access denied'
            }, 401

        # Get the reset key from Key Vault
        try:
            stored_reset_key = user_storage.get_secret('reset-key')
        except Exception as e:
            app.logger.error(f"RESET ENDPOINT ERROR - Failed to retrieve reset-key from Key Vault: {str(e)}")
            return {
                'status': 'error',
                'message': 'Access denied'
            }, 500

        if not stored_reset_key:
            app.logger.error("RESET ENDPOINT ERROR - reset-key not found in Key Vault")
            return {
                'status': 'error',
                'message': 'Access denied'
            }, 500

        if key != stored_reset_key:
            app.logger.warning("RESET ENDPOINT ACCESS DENIED - Invalid key provided")
            return {
                'status': 'error',
                'message': 'Access denied'
            }, 401

        app.logger.warning("RESET ENDPOINT ACCESSED - This will delete all users and secrets!")

        # Perform the reset
        success = user_storage.reset_all_data()

        if success:
            app.logger.warning("RESET COMPLETED SUCCESSFULLY")
            return {
                'status': 'success',
                'message': 'All data has been reset - users and secrets deleted',
                'warning': 'This was a destructive operation for testing purposes'
            }, 200
        else:
            app.logger.error("RESET FAILED")
            return {
                'status': 'error',
                'message': 'Failed to reset data',
                'error': 'Check server logs for details'
            }, 500

    except Exception as e:
        app.logger.error(f"Reset endpoint error: {str(e)}")
        return {
            'status': 'error',
            'message': 'Reset operation failed',
            'error': str(e)
        }, 500


@app.route('/reset-key', methods=['POST'])
@require_admin
def reset_key():
    """Admin endpoint to create/update the reset key in Key Vault."""
    try:
        admin_user = session.get('username')
        app.logger.info(f'Reset key generation requested by admin: {admin_user}')

        # Generate a new secure random key
        new_reset_key = secrets.token_urlsafe(32)  # 32 bytes = 256 bits of entropy

        # Store the key in Key Vault (will overwrite if exists)
        success = user_storage.set_secret('reset-key', new_reset_key)

        if success:
            app.logger.info(f'Reset key successfully created/updated by admin: {admin_user}')
            return {
                'status': 'success',
                'message': 'Reset key created/updated successfully',
                'reset_key': new_reset_key
            }, 200
        else:
            app.logger.error(f'Failed to store reset key for admin: {admin_user}')
            return {
                'status': 'error',
                'message': 'Failed to store reset key in Key Vault'
            }, 500

    except Exception as e:
        app.logger.error(f"Reset key endpoint error: {str(e)}")
        return {
            'status': 'error',
            'message': 'Reset key operation failed',
            'error': str(e)
        }, 500


if __name__ == '__main__':
    # Get port from environment variable or default to 8000
    port = int(os.environ.get('PORT', 8000))

    app.run(host='0.0.0.0', port=port, debug=True)
