from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import os
from functools import wraps
from datetime import timedelta

app = Flask(__name__)

app.permanent_session_lifetime = timedelta(minutes=30)

# Secret key used for login sessions
app.secret_key = os.environ["SECRET_KEY"]

app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Admin credentials


def get_threat_severity(event_id, command=None):
    """
    Classify Cowrie events based on event type and command activity.
    """

    if event_id == "cowrie.login.success":
        return "Critical"

    if event_id == "cowrie.login.failed":
        return "Medium"

    if event_id == "cowrie.command.failed":
        return "Medium"

    if event_id == "cowrie.command.input":
        command_lower = (command or "").lower().strip()

        # Critical activity
        critical_patterns = [
            "cat /etc/passwd",
            "cat /etc/shadow",
            "/dev/tcp/",
            "bash -i",
            "sh -i",
            "nc ",
            "netcat",
            "reverse shell"
        ]

        for pattern in critical_patterns:
            if pattern in command_lower:
                return "Critical"

        # High-risk activity
        high_patterns = [
            "wget ",
            "curl ",
            "chmod ",
            "chown ",
            "passwd",
            "useradd",
            "userdel",
            "sudo ",
            "rm -rf",
            "python -c",
            "python3 -c"
        ]

        for pattern in high_patterns:
            if pattern in command_lower:
                return "High"

        # Reconnaissance / information gathering
        medium_commands = [
            "whoami",
            "uname",
            "ipconfig",
            "ifconfig",
            "ps",
            "id",
            "ls",
            "pwd",
            "env",
            "history"
        ]

        for command_name in medium_commands:
            if command_lower == command_name or command_lower.startswith(command_name + " "):
                return "Medium"

        # Other commands
        return "Low"

    if event_id in [
        "cowrie.session.connect",
        "cowrie.session.closed"
    ]:
        return "Low"

    return "Low"

def get_evidence_activity_type(event_id, command=None):
    command_lower = (command or "").lower().strip()

    if event_id in [
        "cowrie.login.success",
        "cowrie.login.failed"
    ]:
        return "Authentication Activity"

    if event_id == "cowrie.command.input":

        if any(pattern in command_lower for pattern in [
            "cat /etc/passwd",
            "cat /etc/shadow"
        ]):
            return "System Information / Credential Discovery"

        if any(pattern in command_lower for pattern in [
            "/dev/tcp/",
            "bash -i",
            "sh -i",
            "nc ",
            "netcat",
            "reverse shell"
        ]):
            return "Potential Reverse Shell"

        if any(pattern in command_lower for pattern in [
            "wget ",
            "curl ",
            "download"
        ]):
            return "File Download Activity"

        recon_commands = [
            "whoami",
            "uname",
            "ifconfig",
            "ipconfig",
            "ps",
            "id",
            "ls",
            "pwd",
            "env",
            "history"
        ]

        for command_name in recon_commands:
            if (
                command_lower == command_name
                or command_lower.startswith(command_name + " ")
            ):
                return "Reconnaissance"

        return "Command Execution"

    if event_id == "cowrie.command.failed":
        return "Command Execution"

    return "Other Activity"

def get_alert_details(event_id, command=None):
    command_lower = (command or "").lower().strip()

    # Successful authentication to the honeypot
    if event_id == "cowrie.login.success":
        return (
            "Authentication Activity",
            "Successful Authentication",
            "A successful authentication was recorded on the honeypot."
        )

    # Failed authentication
    if event_id == "cowrie.login.failed":
        return (
            "Authentication Activity",
            "Failed Authentication Attempt",
            "A failed authentication attempt was recorded on the honeypot."
        )

    # Failed command
    if event_id == "cowrie.command.failed":
        return (
            "Command Activity",
            "Command Execution Failed",
            "A command entered during the honeypot session failed."
        )

    # Command-based detection
    if event_id == "cowrie.command.input":

        critical_patterns = [
            "cat /etc/passwd",
            "cat /etc/shadow",
            "/dev/tcp/",
            "bash -i",
            "sh -i",
            "nc ",
            "netcat",
            "reverse shell"
        ]

        for pattern in critical_patterns:
            if pattern in command_lower:
                return (
                    "Potential Shell Activity",
                    "Potential Shell Activity Detected",
                    "A command matching a potential shell or reverse-shell pattern was detected."
                )

        high_patterns = [
            "wget ",
            "curl ",
            "chmod ",
            "chown ",
            "passwd",
            "useradd",
            "userdel",
            "sudo ",
            "rm -rf",
            "python -c",
            "python3 -c"
        ]

        for pattern in high_patterns:
            if pattern in command_lower:
                return (
                    "Suspicious Command Activity",
                    "Suspicious Command Activity",
                    "A command associated with file transfer, privilege, account, or potentially destructive activity was detected."
                )

        reconnaissance_commands = [
            "whoami",
            "uname",
            "ipconfig",
            "ifconfig",
            "ps",
            "id",
            "ls",
            "pwd",
            "env",
            "history"
        ]

        for command_name in reconnaissance_commands:
            if (
                command_lower == command_name
                or command_lower.startswith(command_name + " ")
            ):
                return (
                    "Reconnaissance Activity",
                    "System Information Gathering",
                    "A command commonly used to gather information about the honeypot environment was detected."
                )

    return None
    
def sync_alerts():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            l.id,
            l.timestamp,
            l.event_id,
            l.command,
            l.src_ip,
            l.session_id
        FROM attack_logs l
        LEFT JOIN alerts a
            ON a.log_id = l.id
        WHERE a.log_id IS NULL
        ORDER BY l.timestamp ASC
    """)

    events = cursor.fetchall()

    for event in events:

        alert_details = get_alert_details(
            event["event_id"],
            event.get("command")
        )

        # Ignore events that are not considered alert-worthy
        if not alert_details:
            continue

        alert_type, title, description = alert_details

        severity = get_threat_severity(
            event["event_id"],
            event.get("command")
        )

        cursor.execute("""
            INSERT IGNORE INTO alerts (
                log_id,
                alert_type,
                title,
                description,
                severity,
                source_ip,
                session_id
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            event["id"],
            alert_type,
            title,
            description,
            severity,
            event.get("src_ip"),
            event.get("session_id")
        ))

    db.commit()

    cursor.close()
    db.close()    

def get_db_connection():
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        port=int(os.environ.get("DB_PORT", 4000)),
        ssl_ca=os.path.join(os.path.dirname(__file__), "ca.pem"),
        ssl_verify_cert=True,
        ssl_verify_identity=True
    )


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            return render_template(
                "403.html",
                role=session.get("role")
            ), 403

        return f(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        from werkzeug.security import check_password_hash

        db = None
        cursor = None

        try:
            db = get_db_connection()
            cursor = db.cursor(dictionary=True)

            cursor.execute("""
                SELECT username, password_hash, role
                FROM users
                WHERE username = %s
                LIMIT 1
            """, (username,))

            user = cursor.fetchone()

            if user and check_password_hash(
                user["password_hash"],
                password
            ):
                session.permanent = True
                session["logged_in"] = True
                session["username"] = user["username"]
                session["role"] = user["role"]

                return redirect(url_for("dashboard"))

            error = "Invalid username or password."

        except Exception as e:
            print("LOGIN DATABASE ERROR:", e)
            error = "Unable to process login."

        finally:
            if cursor:
                cursor.close()
            if db:
                db.close()

    return render_template("login.html", error=error)
    
@app.route("/settings")
@admin_required
def settings():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, username, role, created_at
        FROM users
        ORDER BY id ASC
    """)

    users = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "settings.html",
        username=session.get("username"),
        role=session.get("role"),
        users=users
    )
    
@app.route("/admin/add-user", methods=["POST"])
@admin_required
def add_user():
    from werkzeug.security import generate_password_hash

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return redirect(url_for("settings"))

    db = get_db_connection()
    cursor = db.cursor()

    try:
        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (%s, %s, 'staff')
            """,
            (username, password_hash)
        )

        db.commit()

    except Exception as e:
        db.rollback()
        print("ADD USER ERROR:", e)

    finally:
        cursor.close()
        db.close()

    return redirect(url_for("settings"))


@app.route("/admin/edit-user/<int:user_id>", methods=["POST"])
@admin_required
def edit_user(user_id):
    from werkzeug.security import generate_password_hash

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username:
        return redirect(url_for("settings"))

    db = get_db_connection()
    cursor = db.cursor()

    try:
        if password:
            password_hash = generate_password_hash(password)

            cursor.execute(
                """
                UPDATE users
                SET username = %s, password_hash = %s
                WHERE id = %s AND role = 'staff'
                """,
                (username, password_hash, user_id)
            )
        else:
            cursor.execute(
                """
                UPDATE users
                SET username = %s
                WHERE id = %s AND role = 'staff'
                """,
                (username, user_id)
            )

        db.commit()

    except Exception as e:
        db.rollback()
        print("EDIT USER ERROR:", e)

    finally:
        cursor.close()
        db.close()

    return redirect(url_for("settings"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute(
            """
            DELETE FROM users
            WHERE id = %s AND role = 'staff'
            """,
            (user_id,)
        )

        db.commit()

    except Exception as e:
        db.rollback()
        print("DELETE USER ERROR:", e)

    finally:
        cursor.close()
        db.close()

    return redirect(url_for("settings"))
    
    
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)


    # Total events
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM attack_logs
    """)
    total_events = cursor.fetchone()["total"]

    # Successful logins
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM attack_logs
        WHERE event_id = 'cowrie.login.success'
    """)
    successful_logins = cursor.fetchone()["total"]

    # Failed commands
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM attack_logs
        WHERE event_id = 'cowrie.command.failed'
    """)
    failed_commands = cursor.fetchone()["total"]

    # Total sessions
    cursor.execute("""
        SELECT COUNT(DISTINCT session_id) AS total
        FROM attack_logs
    """)
    total_sessions = cursor.fetchone()["total"]

    # Attack sources
    cursor.execute("""
        SELECT src_ip, protocol, COUNT(*) AS total
        FROM attack_logs
        GROUP BY src_ip, protocol
        ORDER BY total DESC
        LIMIT 5
    """)
    attack_sources = cursor.fetchall()
    
    # Recent attack activity
    cursor.execute("""
        SELECT
            timestamp,
            src_ip,
            protocol,
            event_id,
            command
        FROM attack_logs
        ORDER BY timestamp DESC
        LIMIT 8
    """)

    recent_events = cursor.fetchall()

    for event in recent_events:
        event["severity"] = get_threat_severity(
            event["event_id"],
            event.get("command")
        )
    
        # Threat severity analysis
    cursor.execute("""
        SELECT event_id, command
        FROM attack_logs
    """)
    severity_events = cursor.fetchall()

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for event in severity_events:
        severity = get_threat_severity(
            event["event_id"],
            event.get("command")
        )
        severity_counts[severity] += 1
        
            # Attack activity trend
    cursor.execute("""
        SELECT
            DATE_FORMAT(timestamp, '%Y-%m-%d %H:00') AS hour,
            COUNT(*) AS total
        FROM attack_logs
        WHERE timestamp >= (
            SELECT MAX(timestamp) - INTERVAL 48 HOUR
            FROM attack_logs
        )
        GROUP BY hour
        ORDER BY hour ASC
    """)

    trend_data = cursor.fetchall()

    trend_labels = [row["hour"] for row in trend_data]
    trend_values = [row["total"] for row in trend_data]
    
    cursor.close()
    db.close()


    return render_template(
        "dashboard.html",
        total_events=total_events,
        successful_logins=successful_logins,
        failed_commands=failed_commands,
        total_sessions=total_sessions,
        attack_sources=attack_sources,
        severity_counts=severity_counts,
        recent_events=recent_events,
        trend_labels=trend_labels,
        trend_values=trend_values,
        username=session.get("username"),
        role=session.get("role")
    )
    
@app.route("/analytics")
@login_required
def analytics():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Total events
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM attack_logs
    """)
    total_events = cursor.fetchone()["total"]

    # Total sessions
    cursor.execute("""
        SELECT COUNT(DISTINCT session_id) AS total
        FROM attack_logs
    """)
    total_sessions = cursor.fetchone()["total"]

    # Event distribution
    cursor.execute("""
        SELECT event_id, COUNT(*) AS total
        FROM attack_logs
        WHERE event_id IS NOT NULL
        GROUP BY event_id
        ORDER BY total DESC
    """)
    event_distribution = cursor.fetchall()

    # Top source IPs
    cursor.execute("""
        SELECT src_ip, COUNT(*) AS total
        FROM attack_logs
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY total DESC
        LIMIT 10
    """)
    top_sources = cursor.fetchall()

    # Most used commands
    cursor.execute("""
        SELECT command, COUNT(*) AS total
        FROM attack_logs
        WHERE command IS NOT NULL
          AND command != ''
        GROUP BY command
        ORDER BY total DESC
        LIMIT 10
    """)
    top_commands = cursor.fetchall()

    # Threat severity
    cursor.execute("""
        SELECT event_id, command
        FROM attack_logs
    """)
    severity_events = cursor.fetchall()

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for event in severity_events:
        severity = get_threat_severity(
            event["event_id"],
            event.get("command")
        )
        severity_counts[severity] += 1


    # Attack category analysis
    attack_type_counts = {
        "Authentication Activity": 0,
        "Reconnaissance Activity": 0,
        "Command Execution": 0,
        "File / Download Activity": 0,
        "Privilege / Account Activity": 0,
        "Potential Shell Activity": 0
    }

    cursor.execute("""
        SELECT event_id, command
        FROM attack_logs
    """)
    attack_events = cursor.fetchall()

    for event in attack_events:

        event_id = event["event_id"]
        command_lower = (event.get("command") or "").lower().strip()

        # Authentication
        if event_id in [
            "cowrie.login.success",
            "cowrie.login.failed"
        ]:

            attack_type_counts["Authentication Activity"] += 1


        # Command-based activity
        elif event_id == "cowrie.command.input":

            # File / download activity
            if any(pattern in command_lower for pattern in [
                "wget ",
                "curl ",
                "download"
            ]):

                attack_type_counts["File / Download Activity"] += 1


            # Privilege / account activity
            elif any(pattern in command_lower for pattern in [
                "sudo ",
                "passwd",
                "useradd",
                "userdel",
                "chmod ",
                "chown "
            ]):

                attack_type_counts["Privilege / Account Activity"] += 1


            # Potential shell activity
            elif any(pattern in command_lower for pattern in [
                "/dev/tcp/",
                "bash -i",
                "sh -i",
                "nc ",
                "netcat",
                "reverse shell"
            ]):

                attack_type_counts["Potential Shell Activity"] += 1


            # Reconnaissance
            elif command_lower in [
                "whoami",
                "uname",
                "ifconfig",
                "ipconfig",
                "ps",
                "id",
                "ls",
                "pwd",
                "env",
                "history"
            ]:

                attack_type_counts["Reconnaissance Activity"] += 1


            # Other commands
            else:

                attack_type_counts["Command Execution"] += 1


        # Failed commands
        elif event_id == "cowrie.command.failed":

            attack_type_counts["Command Execution"] += 1


    # Attack trend
    cursor.execute("""
        SELECT
            DATE_FORMAT(timestamp, '%Y-%m-%d %H:00') AS hour,
            COUNT(*) AS total
        FROM attack_logs
        GROUP BY hour
        ORDER BY hour ASC
    """)
    trend_data = cursor.fetchall()

    trend_labels = [row["hour"] for row in trend_data]
    trend_values = [row["total"] for row in trend_data]
    
        # Analytical summary metrics
    if total_events > 0:
        critical_event_rate = round(
            (severity_counts["Critical"] / total_events) * 100, 1
        )
    else:
        critical_event_rate = 0

    if top_sources:
        top_source_ip = top_sources[0]["src_ip"]
    else:
        top_source_ip = "N/A"

    if event_distribution:
        most_common_event = event_distribution[0]["event_id"]
    else:
        most_common_event = "N/A"

    if top_commands:
        most_used_command = top_commands[0]["command"]
    else:
        most_used_command = "N/A"

    cursor.close()
    db.close()

    return render_template(
        "analytics.html",
        total_events=total_events,
        total_sessions=total_sessions,
        event_distribution=event_distribution,
        top_sources=top_sources,
        top_commands=top_commands,
        severity_counts=severity_counts,
        attack_type_counts=attack_type_counts,
        trend_labels=trend_labels,
        trend_values=trend_values,
        critical_event_rate=critical_event_rate,
        top_source_ip=top_source_ip,
        most_common_event=most_common_event,
        most_used_command=most_used_command,
        username=session.get("username"),
        role=session.get("role")
    )

@app.route("/reports")
@login_required
def reports():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    report_type = request.args.get("report_type", "summary")
    period = request.args.get("period", "all")
    
    included_sections = request.args.getlist("section")

    if not included_sections:
        included_sections = [
            "executive_summary",
            "attack_type",
            "threat_severity",
            "event_summary",
            "attack_sources",
            "commands",
            "evidence"
        ]

    # Reporting period filter
    period_conditions = {
        "24h": "AND timestamp >= NOW() - INTERVAL 1 DAY",
        "7d": "AND timestamp >= NOW() - INTERVAL 7 DAY",
        "30d": "AND timestamp >= NOW() - INTERVAL 30 DAY",
        "all": ""
    }

    date_condition = period_conditions.get(period, "")

    # Total events
    cursor.execute(f"""
        SELECT COUNT(*) AS total
        FROM attack_logs
        WHERE 1=1
        {date_condition}
    """)
    total_events = cursor.fetchone()["total"]

    # Total sessions
    cursor.execute(f"""
        SELECT COUNT(DISTINCT session_id) AS total
        FROM attack_logs
        WHERE session_id IS NOT NULL
        {date_condition}
    """)
    total_sessions = cursor.fetchone()["total"]

    # Severity summary
    cursor.execute(f"""
        SELECT event_id, command
        FROM attack_logs
        WHERE 1=1
        {date_condition}
    """)
    severity_events = cursor.fetchall()

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for event in severity_events:
        severity = get_threat_severity(
            event["event_id"],
            event.get("command")
        )
        severity_counts[severity] += 1

    # Attack type analysis
    attack_type_counts = {
        "Authentication Activity": 0,
        "Reconnaissance Activity": 0,
        "Command Execution": 0,
        "File / Download Activity": 0,
        "Privilege / Account Activity": 0,
        "Potential Shell Activity": 0
    }

    cursor.execute(f"""
        SELECT event_id, command
        FROM attack_logs
        WHERE 1=1
        {date_condition}
    """)
    attack_events = cursor.fetchall()

    for event in attack_events:

        event_id = event["event_id"]
        command_lower = (event.get("command") or "").lower().strip()

        if event_id in [
            "cowrie.login.success",
            "cowrie.login.failed"
        ]:
            attack_type_counts["Authentication Activity"] += 1

        elif event_id == "cowrie.command.input":

            if any(pattern in command_lower for pattern in [
                "wget ",
                "curl ",
                "download"
            ]):
                attack_type_counts["File / Download Activity"] += 1

            elif any(pattern in command_lower for pattern in [
                "sudo ",
                "passwd",
                "useradd",
                "userdel",
                "chmod ",
                "chown "
            ]):
                attack_type_counts["Privilege / Account Activity"] += 1

            elif any(pattern in command_lower for pattern in [
                "/dev/tcp/",
                "bash -i",
                "sh -i",
                "nc ",
                "netcat",
                "reverse shell"
            ]):
                attack_type_counts["Potential Shell Activity"] += 1

            elif command_lower in [
                "whoami",
                "uname",
                "ifconfig",
                "ipconfig",
                "ps",
                "id",
                "ls",
                "pwd",
                "env",
                "history"
            ]:
                attack_type_counts["Reconnaissance Activity"] += 1

            else:
                attack_type_counts["Command Execution"] += 1

        elif event_id == "cowrie.command.failed":
            attack_type_counts["Command Execution"] += 1

    # Top attack sources
    cursor.execute(f"""
        SELECT src_ip, COUNT(*) AS total
        FROM attack_logs
        WHERE src_ip IS NOT NULL
        {date_condition}
        GROUP BY src_ip
        ORDER BY total DESC
        LIMIT 10
    """)
    top_sources = cursor.fetchall()

    # Event summary
    cursor.execute(f"""
        SELECT event_id, COUNT(*) AS total
        FROM attack_logs
        WHERE event_id IS NOT NULL
        {date_condition}
        GROUP BY event_id
        ORDER BY total DESC
    """)
    event_summary = cursor.fetchall()

    # Most executed commands
    cursor.execute(f"""
        SELECT command, COUNT(*) AS total
        FROM attack_logs
        WHERE command IS NOT NULL
          AND command != ''
          {date_condition}
        GROUP BY command
        ORDER BY total DESC
        LIMIT 10
    """)
    top_commands = cursor.fetchall()
    
        # Available SSH sessions for Session Reports
    cursor.execute(f"""
        SELECT
            session_id,
            COUNT(*) AS total,
            MIN(timestamp) AS start_time,
            MAX(timestamp) AS last_activity
        FROM attack_logs
        WHERE session_id IS NOT NULL
        {date_condition}
        GROUP BY session_id
        ORDER BY last_activity DESC
    """)
    session_list = cursor.fetchall()

    # High-risk events for Incident Reports
    cursor.execute(f"""
        SELECT
            id,
            timestamp,
            src_ip,
            event_id,
            command,
            protocol,
            session_id
        FROM attack_logs
        WHERE 1=1
        {date_condition}
        ORDER BY timestamp DESC
    """)
    all_report_events = cursor.fetchall()

    incident_events = []

    for event in all_report_events:
        severity = get_threat_severity(
            event["event_id"],
            event.get("command")
        )

        if severity in ["Critical", "High"]:
            event["severity"] = severity
            incident_events.append(event)
            
    # Selected session for Session Reports
    selected_session = request.args.get("session_id", "").strip()

    if not selected_session and session_list:
        selected_session = session_list[0]["session_id"]

    # Evidence events
    evidence_condition = date_condition
    evidence_params = []

    if selected_session:
        evidence_condition += " AND session_id = %s"
        evidence_params.append(selected_session)

    cursor.execute(f"""
        SELECT
            id,
            timestamp,
            src_ip,
            session_id,
            event_id,
            command,
            protocol
        FROM attack_logs
        WHERE 1=1
        {evidence_condition}
        ORDER BY timestamp DESC
        LIMIT 50
    """, tuple(evidence_params))

    report_evidence = cursor.fetchall()

    for event in report_evidence:
        event["severity"] = get_threat_severity(
            event["event_id"],
            event.get("command")
        )

        event["attack_type"] = get_evidence_activity_type(
            event["event_id"],
            event.get("command")
        )

    session_events = []

    if selected_session:
        cursor.execute("""
            SELECT
                id,
                timestamp,
                src_ip,
                event_id,
                command,
                protocol,
                session_id
            FROM attack_logs
            WHERE session_id = %s
            ORDER BY timestamp ASC
        """, (selected_session,))

        session_events = cursor.fetchall()

    # Report title
    report_titles = {
        "summary": "Security Monitoring Report",
        "incident": "Security Incident Report",
        "session": "SSH Session Report"
    }

    report_title = report_titles.get(
        report_type,
        "Security Monitoring Report"
    )

    cursor.close()
    db.close()

    return render_template(
        "reports.html",
        total_events=total_events,
        total_sessions=total_sessions,
        severity_counts=severity_counts,
        attack_type_counts=attack_type_counts,
        top_sources=top_sources,
        event_summary=event_summary,
        top_commands=top_commands,
        report_type=report_type,
        period=period,
        report_title=report_title,
        session_list=session_list,
        selected_session=selected_session,
        session_events=session_events,
        incident_events=incident_events,
        report_evidence=report_evidence,
        included_sections=included_sections,
        get_threat_severity=get_threat_severity,
        username=session.get("username"),
        role=session.get("role")
    )




@app.route("/alerts")
@login_required
def alerts():

    # Create alerts from any new Cowrie events
    sync_alerts()

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    search = request.args.get("search", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    status_filter = request.args.get("status", "").strip()

    # Alert list
    query = """
        SELECT
            id,
            log_id,
            alert_type,
            title,
            description,
            severity,
            source_ip,
            session_id,
            status,
            created_at,
            updated_at,
            resolved_at
        FROM alerts
        WHERE 1=1
    """

    params = []

    if search:
        query += """
            AND (
                title LIKE %s
                OR alert_type LIKE %s
                OR source_ip LIKE %s
                OR session_id LIKE %s
            )
        """

        search_value = f"%{search}%"

        params.extend([
            search_value,
            search_value,
            search_value,
            search_value
        ])

    if severity_filter:
        query += " AND severity = %s"
        params.append(severity_filter)

    if status_filter:
        query += " AND status = %s"
        params.append(status_filter)

    query += " ORDER BY created_at DESC"

    cursor.execute(query, tuple(params))
    alert_list = cursor.fetchall()

    # Alert statistics
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
    """)
    total_alerts = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
        WHERE severity = 'Critical'
    """)
    critical_alerts = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
        WHERE severity = 'High'
    """)
    high_alerts = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
        WHERE status = 'Resolved'
    """)
    resolved_alerts = cursor.fetchone()["total"]

    cursor.close()
    db.close()

    return render_template(
        "alerts.html",
        alerts=alert_list,
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        resolved_alerts=resolved_alerts,
        search=search,
        severity_filter=severity_filter,
        status_filter=status_filter,
        username=session.get("username"),
        role=session.get("role")
    )
    
@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def update_alert_status(alert_id):

    new_status = request.form.get("status", "").strip()

    allowed_statuses = [
        "New",
        "Investigating",
        "Resolved"
    ]

    if new_status not in allowed_statuses:
        return redirect(url_for("alerts"))

    db = get_db_connection()
    cursor = db.cursor()

    if new_status == "Resolved":
        cursor.execute("""
            UPDATE alerts
            SET status = %s,
                resolved_at = NOW()
            WHERE id = %s
        """, (new_status, alert_id))

    else:
        cursor.execute("""
            UPDATE alerts
            SET status = %s,
                resolved_at = NULL
            WHERE id = %s
        """, (new_status, alert_id))

    db.commit()

    cursor.close()
    db.close()

    return redirect(url_for("alerts"))

@app.route("/attack-activity")
@login_required
def attack_activity():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    search = request.args.get("search", "").strip()
    event_filter = request.args.get("event", "").strip()
    log_id = request.args.get("log_id", "").strip()

    query = """
        SELECT
            id,
            timestamp,
            src_ip,
            event_id,
            command,
            protocol,
            session_id
        FROM attack_logs
        WHERE 1=1
    """

    params = []

    if search:
        query += """
            AND (
                src_ip LIKE %s
                OR event_id LIKE %s
                OR session_id LIKE %s
            )
        """

        search_value = f"%{search}%"
        params.extend([
            search_value,
            search_value,
            search_value
        ])

    if event_filter:
        query += " AND event_id = %s"
        params.append(event_filter)
        
    if log_id:
        query += " AND id = %s"
        params.append(log_id)

    query += """
        ORDER BY timestamp DESC
        LIMIT 100
    """

    cursor.execute(query, params)
    events = cursor.fetchall()
    
    for event in events:
        event["severity"] = get_threat_severity(
            event["event_id"],
            event.get("command")
        )

    cursor.execute("""
        SELECT DISTINCT event_id
        FROM attack_logs
        WHERE event_id IS NOT NULL
        ORDER BY event_id
    """)

    event_types = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "attack_activity.html",
        events=events,
        event_types=event_types,
        search=search,
        event_filter=event_filter,
        username=session.get("username"),
        role=session.get("role")
    )
    
@app.route("/event/<int:event_id>")
@login_required
def event_details(event_id):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            timestamp,
            src_ip,
            event_id,
            command,
            protocol,
            session_id
        FROM attack_logs
        WHERE id = %s
        LIMIT 1
    """, (event_id,))

    event = cursor.fetchone()

    if not event:
        cursor.close()
        db.close()
        return "Event not found", 404

    severity = get_threat_severity(
        event["event_id"],
        event.get("command")
    )

    cursor.execute("""
        SELECT
            timestamp,
            event_id,
            command,
            protocol
        FROM attack_logs
        WHERE session_id = %s
        ORDER BY timestamp ASC
    """, (event["session_id"],))

    related_events = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "event_details.html",
        event=event,
        severity=severity,
        related_events=related_events,
        username=session.get("username"),
        role=session.get("role")
    )

@app.route("/sessions")
@login_required
def sessions():

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            session_id,
            MIN(timestamp) AS start_time,
            MAX(timestamp) AS last_activity,
            MAX(src_ip) AS src_ip,
            MAX(protocol) AS protocol,
            COUNT(*) AS event_count
        FROM attack_logs
        WHERE session_id IS NOT NULL
        GROUP BY session_id
        ORDER BY last_activity DESC
    """)

    sessions_data = cursor.fetchall()

    severity_order = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }

    for item in sessions_data:

        cursor.execute("""
            SELECT
                id,
                timestamp,
                event_id,
                command,
                src_ip,
                protocol
            FROM attack_logs
            WHERE session_id = %s
            ORDER BY timestamp ASC
        """, (item["session_id"],))

        session_events = cursor.fetchall()

        highest_severity = "Low"

        for event in session_events:

            event["severity"] = get_threat_severity(
                event["event_id"],
                event.get("command")
            )

            if severity_order[event["severity"]] > severity_order[highest_severity]:
                highest_severity = event["severity"]

        item["severity"] = highest_severity
        item["events"] = session_events

        # Session duration
        if item["start_time"] and item["last_activity"]:
            duration_seconds = int(
                (item["last_activity"] - item["start_time"]).total_seconds()
            )

            minutes = duration_seconds // 60
            seconds = duration_seconds % 60

            item["duration"] = f"{minutes}m {seconds}s"
        else:
            item["duration"] = "N/A"

        # Count critical events
        item["critical_event_count"] = sum(
            1
            for event in session_events
            if event["severity"] == "Critical"
        )

        # Session status
        if any(
            event["event_id"] == "cowrie.session.closed"
            for event in session_events
        ):
            item["session_status"] = "Closed"
        else:
            item["session_status"] = "Recorded"

    cursor.close()
    db.close()

    return render_template(
        "sessions.html",
        sessions=sessions_data,
        username=session.get("username"),
        role=session.get("role")
    )
    
@app.route("/session/<session_id>")
@login_required
def session_details(session_id):

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            session_id,
            MIN(timestamp) AS start_time,
            MAX(timestamp) AS last_activity,
            MAX(src_ip) AS src_ip,
            MAX(protocol) AS protocol,
            COUNT(*) AS event_count
        FROM attack_logs
        WHERE session_id = %s
        GROUP BY session_id
        LIMIT 1
    """, (session_id,))

    session_info = cursor.fetchone()

    if not session_info:
        cursor.close()
        db.close()
        return "Session not found", 404

    cursor.execute("""
        SELECT
            id,
            timestamp,
            src_ip,
            event_id,
            command,
            protocol,
            session_id
        FROM attack_logs
        WHERE session_id = %s
        ORDER BY timestamp ASC
    """, (session_id,))

    session_events = cursor.fetchall()

    severity_order = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }

    highest_severity = "Low"

    for event in session_events:

        event["severity"] = get_threat_severity(
            event["event_id"],
            event.get("command")
        )

        if severity_order[event["severity"]] > severity_order[highest_severity]:
            highest_severity = event["severity"]

    cursor.close()
    db.close()

    return render_template(
        "session_details.html",
        session_info=session_info,
        session_events=session_events,
        highest_severity=highest_severity,
        username=session.get("username"),
        role=session.get("role")
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
