#!/usr/bin/env python3
"""
Production‑grade Jenkins User Provisioning Script
Features:
- Idempotent user creation & role assignment
- CSRF crumb handling
- Robust error detection (parses HTTP 302 success)
- Secure password generation (never logged)
- Email notification only for new users
- Explicit user role assignment (no ambiguity warnings)
"""

import csv
import os
import sys
import secrets
import string
import smtplib
import logging
import requests
import time
import re
from email.message import EmailMessage
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ----------------------------------------------------------------------
# Environment configuration – all secrets injected via Jenkins credentials
# ----------------------------------------------------------------------
JENKINS_URL = os.environ.get('JENKINS_URL', 'http://localhost:8080').rstrip('/')
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
FROM_EMAIL = os.environ.get('FROM_EMAIL', SMTP_USER)
CSV_PATH = os.environ.get('CSV_PATH', 'users.csv')

# ----------------------------------------------------------------------
# Logging – INFO for pipeline, DEBUG for troubleshooting
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('jenkins_provision')

# ----------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------
def generate_password(length=14):
    """Generate a strong random password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

def requests_retry_session(retries=3, backoff_factor=1):
    """Create a requests session with retry strategy."""
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

def validate_env():
    """Ensure all required environment variables are set."""
    missing = []
    if not ADMIN_TOKEN:
        missing.append('ADMIN_TOKEN')
    if not SMTP_USER:
        missing.append('SMTP_USER (from smtp-creds username)')
    if not SMTP_PASSWORD:
        missing.append('SMTP_PASSWORD (from smtp-creds password)')
    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)

def validate_username(username):
    """Raise ValueError if username contains invalid characters."""
    if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        raise ValueError(
            f"Invalid username '{username}'. "
            "Only alphanumeric characters, underscore (_), and dash (-) are allowed."
        )

# ----------------------------------------------------------------------
# Jenkins CSRF crumb handling
# ----------------------------------------------------------------------
def get_crumb():
    """Fetch a valid CSRF crumb for form posts."""
    url = f"{JENKINS_URL}/crumbIssuer/api/json"
    try:
        resp = requests_retry_session().get(url, auth=(ADMIN_USER, ADMIN_TOKEN), timeout=10)
        if resp.status_code == 200:
            crumb_data = resp.json()
            logger.debug(f"Crumb fetched: {crumb_data}")
            return {crumb_data["crumbRequestField"]: crumb_data["crumb"]}
        else:
            logger.warning(f"Crumb issuer returned {resp.status_code}. Proceeding without crumb.")
            return {}
    except Exception as e:
        logger.warning(f"Failed to fetch crumb: {e}. Proceeding without crumb.")
        return {}

# ----------------------------------------------------------------------
# Jenkins API: User existence check
# ----------------------------------------------------------------------
def user_exists(username):
    """Return True if the user already exists in Jenkins."""
    url = f"{JENKINS_URL}/securityRealm/user/{username}/api/json"
    logger.debug(f"Checking existence of user '{username}' via GET {url}")
    try:
        resp = requests_retry_session().get(url, auth=(ADMIN_USER, ADMIN_TOKEN), timeout=10)
        if resp.status_code == 200:
            logger.debug(f"User '{username}' exists.")
            return True
        elif resp.status_code == 404:
            logger.debug(f"User '{username}' does NOT exist.")
            return False
        else:
            logger.error(f"User existence check failed (HTTP {resp.status_code}) – {resp.text[:200]}")
            resp.raise_for_status()
    except Exception as e:
        logger.error(f"Exception during user existence check: {e}")
        raise

# ----------------------------------------------------------------------
# Jenkins API: Create user (with CSRF and error parsing)
# ----------------------------------------------------------------------
def create_user(username, password, email, fullname=None):
    """
    Create a new Jenkins user.
    Returns True if user was created, False if user already existed.
    Raises exception on other failures.
    """
    url = f"{JENKINS_URL}/securityRealm/createAccountByAdmin"
    data = {
        "username": username,
        "password1": password,
        "password2": password,
        "fullname": fullname or username,
        "email": email
    }

    # Add CSRF crumb if available
    crumb = get_crumb()
    if crumb:
        data.update(crumb)
        logger.debug("Including CSRF crumb in request.")
    else:
        logger.warning("No crumb – CSRF may cause failure.")

    logger.info(f"Creating user '{username}' via POST to {url}")
    resp = requests_retry_session().post(
        url,
        auth=(ADMIN_USER, ADMIN_TOKEN),
        data=data,
        allow_redirects=False,
        timeout=15
    )

    # ---------- SUCCESS: HTTP 302 Redirect ----------
    if resp.status_code == 302:
        logger.info(f"User '{username}' created successfully (302 redirect).")
        time.sleep(2)  # allow Jenkins to persist the user
        # Double-check that the user now exists
        if not user_exists(username):
            raise RuntimeError(f"User '{username}' was reported created but does not exist after creation.")
        return True   # new user created

    # ---------- HTTP 200: Form returned (usually error) ----------
    elif resp.status_code == 200:
        logger.warning(f"User creation returned HTTP 200. Checking if user already exists via API...")
        if user_exists(username):
            logger.warning(f"User '{username}' already exists (detected via API). Proceeding idempotently.")
            return False   # user already existed, no creation done
        else:
            logger.error(f"User creation failed with HTTP 200 and user does NOT exist. Full response:\n{resp.text}")
            raise RuntimeError(f"Failed to create user {username}: HTTP 200 and user does not exist")

    # ---------- OTHER HTTP STATUS CODES ----------
    else:
        logger.error(f"User creation failed with unexpected status {resp.status_code}")
        logger.error(f"Response preview: {resp.text[:500]}")
        raise RuntimeError(f"Failed to create user {username}: HTTP {resp.status_code}")

# ----------------------------------------------------------------------
# Jenkins API: Role assignment via Groovy (using doAssignUserRole)
# ----------------------------------------------------------------------
def assign_role(username, role):
    """
    Assign a global role to the user.
    - Removes any existing assignments for this user (cleans ambiguity)
    - Assigns role explicitly as a USER using doAssignUserRole()
    """
    # Step 1: Verify that the role exists in Jenkins
    groovy_check = f"""
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
    logger.debug(f"Checking if role '{role}' exists via Groovy.")
    check_resp = requests_retry_session().post(
        url,
        auth=(ADMIN_USER, ADMIN_TOKEN),
        data={"script": groovy_check},
        timeout=15
    )
    check_resp.raise_for_status()
    if "ERROR" in check_resp.text:
        raise RuntimeError(f"Role validation failed: {check_resp.text.strip()}")

    # Step 2: Assign the role – with full cleanup and explicit user assignment
    groovy_assign = f"""
import jenkins.model.*
import com.michelin.cio.hudson.plugins.rolestrategy.*

def jenkins = Jenkins.getInstance()
def strategy = jenkins.getAuthorizationStrategy()
if (strategy instanceof RoleBasedAuthorizationStrategy) {{
    def type = RoleBasedAuthorizationStrategy.GLOBAL

    // ---- Remove any existing assignments of this SID from ALL global roles ----
    def globalRoles = strategy.getGrantedRoles(type)
    globalRoles.each {{ roleEntry ->
        def roleName = roleEntry.key.name
        def sids = roleEntry.value
        if (sids.contains("{username}")) {{
            strategy.doUnassignRole(type, roleName, "{username}")
        }}
    }}

    // ---- Assign the role explicitly as a USER ----
    strategy.doAssignUserRole(type, "{role}", "{username}")
    jenkins.save()
    println "ASSIGNED"
}} else {{
    println "ERROR: RBAC not active"
}}
"""
    logger.debug(f"Assigning role '{role}' to '{username}' via Groovy (explicit user).")
    assign_resp = requests_retry_session().post(
        url,
        auth=(ADMIN_USER, ADMIN_TOKEN),
        data={"script": groovy_assign},
        timeout=15
    )
    assign_resp.raise_for_status()
    if "ASSIGNED" not in assign_resp.text:
        logger.error(f"Role assignment failed. Script output: {assign_resp.text}")
        raise RuntimeError(f"Failed to assign role {role} to {username}")
    logger.info(f"Role '{role}' assigned to '{username}' (explicit user).")

def get_current_role(username):
    """Return the current global role of the user, or None if none assigned."""
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
        data={"script": groovy_script},
        timeout=15
    )
    resp.raise_for_status()
    role = resp.text.strip()
    return None if role == "NONE" else role

# ----------------------------------------------------------------------
# Email notification (only for new users)
# ----------------------------------------------------------------------
def send_email(username, email, password, role):
    """Send an email with account credentials."""
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
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            if SMTP_PORT == 587:
                server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send email to {email}: {e}")
        raise

# ----------------------------------------------------------------------
# Main provisioning logic
# ----------------------------------------------------------------------
def main():
    validate_env()

    # Read CSV
    try:
        with open(CSV_PATH, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            required = {'username', 'email', 'role'}
            if not required.issubset(reader.fieldnames):
                raise ValueError(f"CSV must contain columns: {required}")
            users = list(reader)
    except Exception as e:
        logger.critical(f"Failed to read CSV: {e}")
        sys.exit(1)

    success_count = 0
    fail_count = 0

    for user in users:
        username = user['username'].strip()
        email = user['email'].strip()
        role = user['role'].strip().lower()
        logger.info(f"=== Processing {username} ===")

        try:
            # Validate username format (Jenkins default policy)
            validate_username(username)

            # Step 1: Does the user already exist?
            exists = user_exists(username)

            # Step 2: Create user if it does not exist
            if not exists:
                password = generate_password()
                created = create_user(username, password, email)
                if created:
                    # New user created → assign role and send email
                    assign_role(username, role)
                    send_email(username, email, password, role)
                    logger.info(f"✓ {username} – created, role assigned, email sent.")
                else:
                    # create_user returned False meaning user already existed (idempotent)
                    logger.info(f"User {username} already exists. Skipping creation.")
                    # Still ensure correct role
                    current_role = get_current_role(username)
                    if current_role != role:
                        logger.info(f"Updating role for {username} from '{current_role}' to '{role}'")
                        assign_role(username, role)
                    else:
                        logger.info(f"{username} already has role '{role}'. No action.")
            else:
                # User exists → no creation, no email
                logger.info(f"User {username} already exists. Skipping creation.")
                # Ensure correct role
                current_role = get_current_role(username)
                if current_role != role:
                    logger.info(f"Updating role for {username} from '{current_role}' to '{role}'")
                    assign_role(username, role)
                else:
                    logger.info(f"{username} already has role '{role}'. No action.")

            success_count += 1

        except Exception as e:
            logger.exception(f"✗ Failed to provision {username}: {e}")
            fail_count += 1

    logger.info(f"=== Provisioning completed. Success: {success_count}, Failures: {fail_count} ===")
    if fail_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
