#!/usr/bin/env python3
import csv
import os
import sys
import secrets
import string
import smtplib
import logging
import requests
import time
from email.message import EmailMessage
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------ CONFIGURATION (from environment) ------------------
JENKINS_URL = os.environ.get('JENKINS_URL', 'http://localhost:8080').rstrip('/')
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
FROM_EMAIL = os.environ.get('FROM_EMAIL', SMTP_USER)
CSV_PATH = os.environ.get('CSV_PATH', 'users.csv')

# ------------------ LOGGING ------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('jenkins_provision')

# ------------------ UTILS ------------------
def generate_password(length=14):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

def requests_retry_session(retries=3, backoff_factor=1):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# ------------------ JENKINS CRUMB (CSRF) HANDLING ------------------
def get_crumb():
    """Fetch a valid crumb token for CSRF-protected POST requests."""
    url = f"{JENKINS_URL}/crumbIssuer/api/json"
    try:
        resp = requests_retry_session().get(url, auth=(ADMIN_USER, ADMIN_TOKEN), timeout=10)
        if resp.status_code == 200:
            crumb_data = resp.json()
            logger.debug(f"Crumb fetched: {crumb_data}")
            return {crumb_data["crumbRequestField"]: crumb_data["crumb"]}
        else:
            logger.warning("Crumb issuer not available or returned non-200. Proceeding without crumb.")
            return {}
    except Exception as e:
        logger.warning(f"Failed to fetch crumb: {e}. Proceeding without crumb.")
        return {}

# ------------------ JENKINS API INTERACTIONS ------------------
def user_exists(username):
    """Check if user already exists via API."""
    url = f"{JENKINS_URL}/securityRealm/user/{username}/api/json"
    resp = requests_retry_session().get(url, auth=(ADMIN_USER, ADMIN_TOKEN))
    if resp.status_code == 200:
        return True
    elif resp.status_code == 404:
        return False
    else:
        logger.error(f"User existence check failed: {resp.status_code} - {resp.text[:200]}")
        resp.raise_for_status()

def create_user(username, password, email, fullname=None):
    """Create a new Jenkins user with CSRF crumb handling."""
    url = f"{JENKINS_URL}/securityRealm/createAccountByAdmin"
    
    # Prepare form data
    data = {
        "username": username,
        "password1": password,
        "password2": password,
        "fullname": fullname or username,
        "email": email
    }
    
    # Add crumb if available
    crumb = get_crumb()
    if crumb:
        data.update(crumb)
        logger.info("Including CSRF crumb in request.")
    else:
        logger.warning("No crumb – proceeding without CSRF token. May fail if CSRF is enforced.")
    
    logger.info(f"Creating user '{username}' via POST to {url}")
    resp = requests_retry_session().post(url, auth=(ADMIN_USER, ADMIN_TOKEN), data=data, allow_redirects=False)
    
    # Success is indicated by HTTP 302 (redirect)
    if resp.status_code == 302:
        logger.info(f"User '{username}' created successfully (302 redirect).")
        # Wait a moment for Jenkins to persist the user
        time.sleep(2)
        # Verify user actually exists
        if not user_exists(username):
            raise RuntimeError(f"User '{username}' was reported created but does not exist after creation.")
        return True
    else:
        # On failure, the response is HTTP 200 with the HTML form + error message
        logger.error(f"User creation failed. Status: {resp.status_code}, Response preview: {resp.text[:500]}")
        # Try to extract error reason from HTML (optional)
        if "User name is already taken" in resp.text:
            raise RuntimeError(f"User '{username}' already exists (creation attempted anyway).")
        elif "Invalid email address" in resp.text:
            raise RuntimeError(f"Invalid email address for user '{username}'.")
        else:
            raise RuntimeError(f"Failed to create user {username}: HTTP {resp.status_code}")

def assign_role(username, role):
    """Assign a global role to the user via Groovy, with output validation."""
    # First, verify that the role exists in Jenkins
    groovy_check_role = f"""
import jenkins.model.*
import com.michelin.cio.hudson.plugins.rolestrategy.*

def strategy = Jenkins.instance.getAuthorizationStrategy()
if (!(strategy instanceof RoleBasedAuthorizationStrategy)) {{
    println "ERROR: RoleBasedAuthorizationStrategy not active"
    return
}}
def globalRoles = strategy.getGrantedRoles(RoleBasedAuthorizationStrategy.GLOBAL)
def roleExists = globalRoles.any {{ it.key.name == "{role}" }}
if (!roleExists) {{
    println "ERROR: Role '{role}' does not exist in Global roles"
    return
}}
println "OK: Role exists"
"""
    url = f"{JENKINS_URL}/scriptText"
    check_resp = requests_retry_session().post(
        url,
        auth=(ADMIN_USER, ADMIN_TOKEN),
        data={"script": groovy_check_role}
    )
    if "ERROR" in check_resp.text:
        raise RuntimeError(f"Role validation failed: {check_resp.text.strip()}")

    # Now assign the role
    groovy_assign = f"""
import jenkins.model.*
import com.michelin.cio.hudson.plugins.rolestrategy.*

def jenkins = Jenkins.getInstance()
def strategy = jenkins.getAuthorizationStrategy()
if (strategy instanceof RoleBasedAuthorizationStrategy) {{
    strategy.assignRole(RoleBasedAuthorizationStrategy.GLOBAL, "{role}", "{username}")
    jenkins.save()
    println "ASSIGNED"
}} else {{
    println "ERROR: RBAC not active"
}}
"""
    assign_resp = requests_retry_session().post(
        url,
        auth=(ADMIN_USER, ADMIN_TOKEN),
        data={"script": groovy_assign}
    )
    if "ASSIGNED" not in assign_resp.text:
        logger.error(f"Role assignment failed: {assign_resp.text}")
        raise RuntimeError(f"Failed to assign role {role} to {username}")
    logger.info(f"Role '{role}' assigned to '{username}'.")

def get_current_role(username):
    """Retrieve the current global role of a user (if any)."""
    groovy_script = f"""
import jenkins.model.*
import com.michelin.cio.hudson.plugins.rolestrategy.*

def jenkins = Jenkins.getInstance()
def strategy = jenkins.getAuthorizationStrategy()
if (strategy instanceof RoleBasedAuthorizationStrategy) {{
    def roles = strategy.getGrantedRoles(RoleBasedAuthorizationStrategy.GLOBAL)
    def userRole = roles.find {{ it.value.contains("{username}") }}?.key?.name
    println userRole ?: "NONE"
}} else {{
    println "NONE"
}}
"""
    url = f"{JENKINS_URL}/scriptText"
    resp = requests_retry_session().post(
        url,
        auth=(ADMIN_USER, ADMIN_TOKEN),
        data={"script": groovy_script}
    )
    resp.raise_for_status()
    role = resp.text.strip()
    return None if role == "NONE" else role

# ------------------ EMAIL ------------------
def send_email(username, email, password, role):
    msg = EmailMessage()
    msg["Subject"] = "Your Jenkins Account Access"
    msg["From"] = FROM_EMAIL
    msg["To"] = email
    body = f"""
Hello {username},

Your Jenkins account has been provisioned.

Jenkins URL: {JENKINS_URL}
Username:    {username}
Password:    {password}
Role:        {role}

Please log in and change your password immediately.

Regards,
DevOps Automation
"""
    msg.set_content(body)
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        if SMTP_PORT == 587:
            server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
    logger.info(f"Email sent to {email}")

# ------------------ MAIN PROVISIONING LOOP ------------------
def main():
    if not ADMIN_TOKEN:
        logger.error("ADMIN_TOKEN environment variable not set.")
        sys.exit(1)

    # Read CSV
    try:
        with open(CSV_PATH, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            if not {'username', 'email', 'role'}.issubset(reader.fieldnames):
                raise ValueError("CSV must contain 'username', 'email', 'role' columns")
            users = list(reader)
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}")
        sys.exit(1)

    success_count = 0
    fail_count = 0

    for user in users:
        username = user['username'].strip()
        email = user['email'].strip()
        role = user['role'].strip().lower()
        logger.info(f"Processing {username}...")

        try:
            # 1. Check if user already exists
            exists = user_exists(username)

            if not exists:
                # Generate password
                password = generate_password()

                # Create user
                create_user(username, password, email)

                # Assign role
                assign_role(username, role)

                # Send email
                send_email(username, email, password, role)
                logger.info(f"✓ {username} created, role assigned, email sent.")
            else:
                # Idempotency: verify current role
                current_role = get_current_role(username)
                if current_role != role:
                    logger.info(f"Updating role for {username} from '{current_role}' to '{role}'")
                    assign_role(username, role)
                else:
                    logger.info(f"{username} already exists with role '{role}'. No action.")
            success_count += 1

        except Exception as e:
            logger.error(f"✗ Failed to provision {username}: {e}")
            fail_count += 1

    logger.info(f"Done. Success: {success_count}, Failures: {fail_count}")
    if fail_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
