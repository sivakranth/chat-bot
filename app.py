import os
import re
import sqlite3
import logging
import base64
import requests
from datetime import datetime
from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, abort, session, send_from_directory
)
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from database import (
    DB_NAME, create_user, authenticate_user, get_user as db_get_user,
    save_ticket, get_ticket as db_get_ticket, get_ticket_with_comments,
    add_comment as db_add_comment, ensure_db, get_filtered_tickets,
    get_all_staff_members, assign_ticket, update_ticket_category
)
ensure_db()

# --- Init ---
load_dotenv()
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- API Keys ---
PPLX_API_KEY = os.getenv("PPLX_API_KEY")
PPLX_API_URL = "https://api.perplexity.ai/chat/completions"
PPLX_MODEL = "sonar-pro"

# --- Upload Config ---
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Flask-Login User class ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = int(user_data["id"])
        self.username = user_data["username"]
        self.role = user_data["role"]

@login_manager.user_loader
def load_user(user_id):
    user_data = db_get_user(int(user_id))
    return User(user_data) if user_data else None

# --- DB connection helper ---
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# --- Priority Determination ---
def determine_priority(msg: str) -> str:
    low_msg = msg.lower().strip()
    high_keywords = ["urgent", "critical", "emergency", "asap", "immediately", "high priority"]
    low_keywords = ["low priority", "not urgent", "minor", "no hurry"]
    if any(k in low_msg for k in high_keywords):
        return "High"
    elif any(k in low_msg for k in low_keywords):
        return "Low"
    return "Medium"

# --- Ticket Triggers ---
def needs_ticket_creation(msg: str) -> bool:
    msg = msg.lower().strip()
    triggers = [
        r"\bcreate\b.*\bticket\b",
        r"\bmake\b.*\bticket\b",
        r"\bopen\b.*\bticket\b",
        r"\bfile\b.*\bticket\b",
        r"\bsubmit\b.*\bticket\b",
        r"\braise\b.*\bticket\b",
        r"\blog\b.*\bticket\b",
        r"\bgenerate\b.*\bticket\b",
        r"\bnew\s+ticket\b",
        r"\bi\s+need\s+a\s+ticket\b",
    ]
    return any(re.search(t, msg) for t in triggers)

# --- Detect if message looks like a problem ---
def looks_like_issue(msg: str) -> bool:
    keywords = [
        "issue", "problem", "error", "bug", "fail", "crash", "not working", "login",
        "disconnect", "not connecting", "cannot connect", "can't connect",
        "slow", "down", "offline", "unreachable",
        "vpn", "network", "wifi", "internet"
    ]
    msg_lower = msg.lower()
    return any(k in msg_lower for k in keywords)

# --- Chatbot guided flow keywords ---
CANCEL_KEYWORDS = {"cancel", "abort", "stop", "nevermind", "forget it", "exit"}
NO_SCREENSHOT_KEYWORDS = {"no", "none", "n", "nope", "skip", "not now", "dont have", "don't have"}

# --- Screenshot analysis ---
def analyze_image_with_pplx(filepath: str) -> str:
    try:
        with open(filepath, "rb") as f:
            img_bytes = f.read()
        b64 = base64.b64encode(img_bytes).decode("utf-8")
        ext = os.path.splitext(filepath)[1].lower()
        mime = "image/jpeg" if ext in [".jpg", ".jpeg"] else "image/png"
        data_uri = f"data:{mime};base64,{b64}"
        payload = {
            "model": PPLX_MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Extract only the main error message from this screenshot."},
                        {"type": "image_url", "image_url": {"url": data_uri}},
                    ],
                }
            ],
        }
        headers = {"Authorization": f"Bearer {PPLX_API_KEY}", "Content-Type": "application/json"}
        resp = requests.post(PPLX_API_URL, json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "No error found.")
    except Exception as e:
        return f"⚠️ Error analyzing screenshot: {e}"

# --- Chat endpoint ---
@app.route("/chat", methods=["POST"])
@login_required
def chat():
    if current_user.role in ["Staff", "Admin"]:
        return jsonify({"error": "Only Users can use the chat assistant"}), 403
    try:
        data = request.json or {}
        user_message = (data.get("message") or "").strip()
        from_button = data.get("from_button", False)

        if from_button:
            full_message = "Ticket created directly via button (no details provided yet)"
            priority = "Medium"
            ticket_id = save_ticket(
                user_id=current_user.id,
                user_message=full_message,
                bot_reply="Ticket created instantly from button click",
                priority=priority,
                ticket_type="General"
            )
            return jsonify({
                "reply": f"✅ Ticket #{ticket_id} created successfully (from button).",
                "ticket_id": ticket_id
            })

        if not user_message:
            return jsonify({"error": "Empty message"}), 400
        msg_lower = user_message.lower().strip()

        # --- Small talk FIRST ---
        if any(word in msg_lower for word in ["hi", "hello", "hey"]):
            return jsonify({"reply": f"👋 Hello {current_user.username}! How can I help you today?"})
        if "how are you" in msg_lower:
            return jsonify({"reply": "I'm doing great! Let me know how I can assist you."})
        if "who are you" in msg_lower or "what are you" in msg_lower:
            return jsonify({"reply": "I'm your IT Helpdesk assistant 🤖. I can help log issues and create tickets."})

        # --- Category keyword mapping ---
        CATEGORY_KEYWORDS = {
            "Network": [
                "network", "net", "wifi", "wi-fi", "wi fi", "internet", "vpn", "connection",
                "disconnect", "slow", "offline", "latency", "router", "modem", "dns", "ping", "drop"
            ],
            "Hardware": [
                "hardware", "laptop", "pc", "computer", "desktop", "mouse", "keyboard", "printer",
                "screen", "monitor", "camera", "webcam", "speaker", "mic", "microphone",
                "dock", "usb", "charger", "battery", "projector", "device", "hard drive"
            ],
            "Software": [
                "software", "outlook", "teams", "excel", "word", "app", "application", "program",
                "crash", "install", "update", "patch", "windows", "os", "zoom", "slack",
                "browser", "chrome", "firefox", "edge", "office", "ms office", "tool", "bug"
            ],
            "Access": [
                "access", "login", "log in", "sign in", "sign-in", "password", "passcode",
                "account", "credentials", "auth", "authentication", "authorization", "blocked",
                "locked", "lockout", "reset", "forgot password", "2fa", "otp", "mfa"
            ],
            "Email/Communication": [
                "email", "mail", "outlook", "gmail", "smtp", "imap", "exchange", "mailbox", "send", "receive"
            ],
            "Security": [
                "security", "antivirus", "virus", "malware", "phishing", "firewall", "spyware", "attack", "breach"
            ],
            "Accounts/HR": [
                "payroll", "leave", "hrms", "sap", "employee portal", "hr system", "salary", "attendance"
            ],
            "Infrastructure/DevOps": [
                "pipeline", "ci", "cd", "build", "deploy", "deployment", "release",
                "jenkins", "gitlab", "github actions", "azure devops", "artifact",
                "docker", "kubernetes", "k8s", "helm", "pods", "cluster",
                "terraform", "ansible", "provision", "infrastructure"
            ],
            "Server/API Issues": [
                "server", "api", "gateway", "proxy", "502", "503", "504",
                "bad gateway", "internal server error", "timeout", "connection reset",
                "load balancer", "nginx", "apache", "tomcat", "service down"
            ],
            "Monitoring/Alerts": [
                "alert", "pagerduty", "grafana", "prometheus", "datadog",
                "splunk", "log", "metrics", "cpu", "memory", "disk", "latency",
                "response time", "downtime", "error rate"
            ],
            "Cloud/Hosting": [
                "aws", "azure", "gcp", "cloud", "ec2", "s3", "rds", "lambda",
                "kinesis", "cloudwatch", "vm", "bucket", "iam", "dns", "route53",
                "quota", "limit exceeded"
            ],
            "CI/CD Errors": [
                "pipeline failed", "build failed", "test failed", "staging",
                "production", "rollback", "migration failed", "job error",
                "script failed", "release failed", "artifact missing"
            ],
            "Infra Security": [
                "ssh", "ssl", "tls", "certificate expired", "permission denied",
                "firewall", "vpn", "ddos", "intrusion", "vulnerability", "patching"
            ]
        }

        def detect_category(msg_lower: str):
            for category, keywords in CATEGORY_KEYWORDS.items():
                for k in keywords:
                    if re.search(rf"\b{re.escape(k)}\b", msg_lower):
                        logger.info(f"Detected category: {category} for keyword: {k}")
                        return category
            return None

        # --- Trigger guided flow ---
        if "ticket_in_progress" not in session and (needs_ticket_creation(user_message) or looks_like_issue(user_message)):
            auto_category = detect_category(msg_lower)
            session["ticket_in_progress"] = {
                "issue": user_message,
                "error_message": None,
                "screenshot": None,
                "category": auto_category,
                "stage": "confirm_category" if auto_category else "ask_category"
            }
            logger.info(f"Initialized ticket_in_progress: {session['ticket_in_progress']}")
            session.modified = True
            issue_text = user_message.strip().rstrip("?.!")
            if auto_category:
                return jsonify({
                    "reply": f"Got it. Thanks for reporting the issue: \"{issue_text}\". "
                             f"I've categorized this as {auto_category}. Is this correct? (yes/no)"
                })
            else:
                return jsonify({
                    "reply": f"Got it. Thanks for reporting the issue: \"{issue_text}\". "
                             f"Please choose a category: Network, Hardware, Software, Access, Email/Communication, Security, Accounts/HR"
                })

        # --- Guided flow steps ---
        if "ticket_in_progress" in session:
            flow = session["ticket_in_progress"]
            stage = flow.get("stage")
            logger.info(f"Current stage: {stage}, Flow: {flow}")

            if msg_lower in CANCEL_KEYWORDS:
                session.pop("ticket_in_progress", None)
                session.modified = True
                return jsonify({"reply": "Ticket creation cancelled."})

            # --- Confirm category ---
            if stage == "confirm_category":
                confirm_keywords = ["yes", "y", "yeah", "yep", "sure", "ok", "okay"]
                deny_keywords = ["no", "n", "nope"]
                if any(k in msg_lower for k in confirm_keywords):
                    flow["stage"] = "ask_error_or_screenshot"
                    session["ticket_in_progress"] = flow
                    session.modified = True
                    return jsonify({
                        "reply": f"Category confirmed as {flow['category']}. Do you have an error message or a screenshot to share?"
                    })
                elif any(k in msg_lower for k in deny_keywords):
                    flow["category"] = None
                    flow["stage"] = "ask_category"
                    session["ticket_in_progress"] = flow
                    session.modified = True
                    return jsonify({
                        "reply": f"Okay, please choose a category: Network, Hardware, Software, Access, Email/Communication, Security, Accounts/HR"
                    })
                else:
                    return jsonify({
                        "reply": f"Please confirm if {flow['category']} is correct (yes/no)."
                    })

            # --- Ask category ---
            if stage == "ask_category":
                chosen_category = detect_category(msg_lower) or msg_lower.title()
                if chosen_category not in CATEGORY_KEYWORDS and chosen_category not in ["General"]:
                    return jsonify({
                        "reply": f"I couldn't recognize that category. Please choose one: Network, Hardware, Software, Access, Email/Communication, Security, Accounts/HR"
                    })
                flow["category"] = chosen_category
                flow["stage"] = "confirm_category"
                session["ticket_in_progress"] = flow
                session.modified = True
                return jsonify({
                    "reply": f"I've categorized this as {chosen_category}. Is this correct? (yes/no)"
                })

            # --- Ask error or screenshot ---
            if stage == "ask_error_or_screenshot":
                if "screenshot" in msg_lower:
                    flow["stage"] = "waiting_screenshot_upload"
                    session["ticket_in_progress"] = flow
                    session.modified = True
                    return jsonify({
                        "reply": "Okay, please upload the screenshot using the upload button.",
                        "show_upload": True
                    })
                elif "error" in msg_lower or "message" in msg_lower:
                    flow["stage"] = "waiting_error_message"
                    session["ticket_in_progress"] = flow
                    session.modified = True
                    return jsonify({"reply": "Please type the exact error message you see."})
                elif msg_lower in NO_SCREENSHOT_KEYWORDS:
                    flow["stage"] = "waiting_error_message"
                    session["ticket_in_progress"] = flow
                    session.modified = True
                    return jsonify({"reply": "Alright, please type the exact error message you see."})
                else:
                    return jsonify({
                        "reply": "Do you have an error message or a screenshot to share?"
                    })

            # --- Waiting for error message ---
            if stage == "waiting_error_message":
                invalid_responses = ["", "error", "error message", "message", "yes", "ok", "okay"]
                if user_message.lower().strip() in invalid_responses:
                    return jsonify({
                        "reply": "That doesn't look like a valid error message. Please type the exact error text you see."
                    })
                flow["error_message"] = user_message
                flow["stage"] = "confirm_ticket"
                session["ticket_in_progress"] = flow
                session.modified = True
                return jsonify({
                    "reply": f"Got it. Error noted: \"{user_message}\". Do you want me to create a ticket? (yes/no)"
                })

            # --- Waiting for screenshot upload ---
            if stage == "waiting_screenshot_upload":
                return jsonify({
                    "reply": "Please upload your screenshot now using the upload button below",
                    "show_upload": True
                })

            # --- Confirm ticket creation ---
            if stage == "confirm_ticket":
                confirm_keywords = ["yes", "y", "yeah", "yep", "sure", "ok", "okay", "create", "confirm"]
                deny_keywords = ["no", "n", "nope", "cancel", "abort", "stop", "nevermind"]

                if any(k in msg_lower for k in confirm_keywords):
                    parts = [f"Issue: {flow.get('issue', '')}"]
                    if flow.get("category"):
                        parts.append(f"Category: {flow['category']}")
                    if flow.get("error_message"):
                        parts.append(f"Error: {flow['error_message']}")
                    if flow.get("screenshot"):
                        parts.append(f"Screenshot: {flow['screenshot']}")

                    full_message = " | ".join(parts)
                    priority = determine_priority(full_message)

                    ticket_id = save_ticket(
                        user_id=current_user.id,
                        user_message=full_message,
                        bot_reply="Ticket created from guided flow",
                        priority=priority,
                        ticket_type=flow.get("category", "General"),
                        screenshot=flow.get("screenshot")
                    )
                    session.pop("ticket_in_progress", None)
                    session.modified = True
                    return jsonify({
                        "reply": f"Ticket #{ticket_id} created successfully under category \"{flow.get('category', 'General')}\".",
                        "ticket_id": ticket_id
                    })
                elif any(k in msg_lower for k in deny_keywords):
                    session.pop("ticket_in_progress", None)
                    session.modified = True
                    return jsonify({"reply": "Ticket creation cancelled."})
                else:
                    return jsonify({
                        "reply": "Please reply 'yes' to create the ticket or 'no' to cancel."
                    })

        # --- General fallback ---
        headers = {"Authorization": f"Bearer {PPLX_API_KEY}", "Content-Type": "application/json"}
        payload = {"model": PPLX_MODEL, "messages": [{"role": "user", "content": user_message}]}
        resp = requests.post(PPLX_API_URL, json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        reply = data.get("choices", [{}])[0].get("message", {}).get("content", "Sorry, I couldn't find an answer.")
        return jsonify({"reply": reply})

    except Exception as e:
        logger.exception("Chat error")
        return jsonify({"error": "Internal server error"}), 500

# --- Serve uploaded files ---
@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# --- Routes ---
@app.route("/")
def root():
    if current_user.is_authenticated:
        if current_user.role in ["Staff", "Admin"]:
            return redirect(url_for("tickets_view"))
        return redirect(url_for("home"))
    return redirect(url_for("login"))

@app.route("/home")
@login_required
def home():
    if current_user.role in ["Staff", "Admin"]:
        return redirect(url_for("tickets_view"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user_data = authenticate_user(username, password)
        if user_data:
            user = User(user_data)
            login_user(user)
            logger.info(f"User {username} logged in with role: {user_data['role']}")
            return redirect(url_for("home"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form.get("role", "User")
        if role not in ["User", "Staff", "Admin"]:
            role = "User"
        if not username or not password:
            return render_template("register.html", error="Username and password are required")
        try:
            create_user(username, password, role)
            logger.info(f"New {role} registered: {username}")
            return redirect(url_for("login"))
        except ValueError as e:
            return render_template("register.html", error=str(e))
    return render_template("register.html")

# --- Ticket Views ---
@app.route("/tickets")
@login_required
def tickets_view():
    try:
        filter_status = request.args.get("status", "All")
        filter_priority = request.args.get("priority", "All")
        filter_assigned = request.args.get("assigned", "All")
        
        # Determine user access based on role
        user_id = None
        assigned_to = None
        
        if current_user.role == "User":
            # Users see only their tickets
            user_id = current_user.id
        elif current_user.role == "Staff":
            # Staff see only tickets assigned to them
            assigned_to = current_user.id
        elif current_user.role == "Admin":
            # Admin can filter by assignment
            if filter_assigned == "unassigned":
                assigned_to = "unassigned"
            elif filter_assigned != "All" and filter_assigned.isdigit():
                assigned_to = int(filter_assigned)

        # Normalize case only for "All"
        if filter_status.lower() == "all":
            filter_status = "All"
        if filter_priority.lower() == "all":
            filter_priority = "All"

        logger.info(f"Fetching tickets for user: {current_user.username}, role: {current_user.role}, "
                    f"filter_status: {filter_status}, filter_priority: {filter_priority}, "
                    f"filter_assigned: {filter_assigned}, user_id: {user_id}, assigned_to: {assigned_to}")

        tickets = get_filtered_tickets(
            user_id=user_id, 
            status=filter_status if filter_status != "All" else None, 
            priority=filter_priority if filter_priority != "All" else None,
            assigned_to=assigned_to
        )
        
        # Get staff members for admin assignment dropdown
        staff_members = get_all_staff_members() if current_user.role == "Admin" else []
        
        logger.info(f"Retrieved {len(tickets)} tickets")

        return render_template("tickets.html",
                             tickets=tickets,
                             filter_status=filter_status,
                             filter_priority=filter_priority,
                             filter_assigned=filter_assigned,
                             staff_members=staff_members)
    except Exception as e:
        logger.error(f"Error in tickets endpoint: {e}")
        return render_template("tickets.html",
                             tickets=[],
                             filter_status="All",
                             filter_priority="All",
                             filter_assigned="All",
                             staff_members=[],
                             error=f"Error loading tickets: {str(e)}")

# --- Ticket APIs ---
@app.route("/api/ticket/<int:tid>")
@login_required
def api_get_ticket(tid):
    try:
        ticket = db_get_ticket(tid)
        if not ticket:
            return jsonify({"error": f"Ticket #{tid} not found"}), 404
        ticket_d = dict(ticket)
        
        # Check access permissions
        from database import check_user_can_access_ticket
        if not check_user_can_access_ticket(current_user.id, current_user.role, tid):
            return jsonify({"error": "Unauthorized access to ticket"}), 403
            
        return jsonify(ticket_d)
    except Exception as e:
        logger.error(f"Error fetching ticket {tid}: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/ticket/<int:tid>/comments")
@login_required
def ticket_comments(tid):
    try:
        ticket, comments = get_ticket_with_comments(tid)
        if not ticket:
            return jsonify({"error": f"Ticket #{tid} not found"}), 404
            
        # Check access permissions
        from database import check_user_can_access_ticket
        if not check_user_can_access_ticket(current_user.id, current_user.role, tid):
            return jsonify({"error": "Unauthorized access to ticket"}), 403
            
        ticket_d = dict(ticket)
        comments_list = [dict(c) for c in comments]
        return jsonify({"ticket": ticket_d, "comments": comments_list})
    except Exception as e:
        logger.error(f"Error fetching ticket {tid} comments: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- Add comment API ---
@app.route("/ticket/<int:tid>/add_comment", methods=["POST"])
@login_required
def add_ticket_comment(tid):
    try:
        ticket = db_get_ticket(tid)
        if not ticket:
            return jsonify({"error": f"Ticket #{tid} not found"}), 404
            
        # Check access permissions
        from database import check_user_can_comment_on_ticket
        if not check_user_can_comment_on_ticket(current_user.id, current_user.role, tid):
            return jsonify({"error": "You cannot comment on this ticket"}), 403

        message = ""
        file_url = None
        is_screenshot = 0

        if request.content_type.startswith("multipart/form-data"):
            message = (request.form.get("message") or "").strip()
            file = request.files.get("screenshot")
            if file and allowed_file(file.filename):
                filename = secure_filename(f"ticket_{tid}_{file.filename}")
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                file_url = filename
                is_screenshot = 1
                if not message:
                    message = "[screenshot]"
        else:
            data = request.get_json() or {}
            message = (data.get("message") or "").strip()

        if not message and not file_url:
            return jsonify({"error": "Empty comment"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO comments (ticket_id, message, author_id, is_screenshot, file_url)
            VALUES (?, ?, ?, ?, ?)
        """, (tid, message, current_user.id, is_screenshot, file_url))
        conn.commit()
        conn.close()

        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error adding comment to ticket {tid}: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- Assignment API ---
@app.route("/assign_ticket/<int:ticket_id>", methods=["POST"])
@login_required
def assign_ticket_route(ticket_id):
    if current_user.role not in ["Staff", "Admin"]:
        return jsonify({"error": "Unauthorized - only Staff and Admin can assign tickets"}), 403
    
    try:
        data = request.get_json()
        assigned_to_id = data.get("assigned_to")
        
        # Convert "unassigned" to None
        if assigned_to_id == "unassigned":
            assigned_to_id = None
        elif assigned_to_id:
            assigned_to_id = int(assigned_to_id)
        
        # Staff can only assign to themselves or unassign
        if current_user.role == "Staff":
            if assigned_to_id is not None and assigned_to_id != current_user.id:
                return jsonify({"error": "Staff can only assign tickets to themselves"}), 403
        
        assign_ticket(ticket_id, assigned_to_id)
        
        if assigned_to_id:
            staff_user = db_get_user(assigned_to_id)
            staff_name = staff_user['username'] if staff_user else "Unknown"
            return jsonify({"success": True, "message": f"Ticket assigned to {staff_name}"})
        else:
            return jsonify({"success": True, "message": "Ticket unassigned"})
            
    except Exception as e:
        logger.error(f"Error assigning ticket {ticket_id}: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- Update category API ---
@app.route("/update_category/<int:ticket_id>", methods=["POST"])
@login_required
def update_category(ticket_id):
    if current_user.role not in ["Staff", "Admin"]:
        return jsonify({"error": "Unauthorized - only Staff and Admin can update category"}), 403
    try:
        data = request.get_json()
        new_category = data.get("category")
        
        update_ticket_category(ticket_id, new_category)
        return jsonify({"success": True, "category": new_category})
    except Exception as e:
        logger.error(f"Error updating category for ticket {ticket_id}: {e}")
        return jsonify({"error": "Internal server error"}), 500
    
# --- Cancel Ticket ---
@app.route("/cancel_ticket/<int:ticket_id>", methods=["POST"])
@login_required
def cancel_ticket(ticket_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch ticket
        cursor.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            conn.close()
            return jsonify({"success": False, "error": f"Ticket #{ticket_id} not found"}), 404

        # Check ownership if User
        if current_user.role == "User" and ticket["user_id"] != current_user.id:
            conn.close()
            return jsonify({"success": False, "error": "Unauthorized to cancel this ticket"}), 403

        # Update ticket status
        cursor.execute("UPDATE tickets SET status = ? WHERE id = ?", ("Cancelled", ticket_id))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": f"Ticket #{ticket_id} has been cancelled."})
    except Exception as e:
        logger.error(f"Error cancelling ticket {ticket_id}: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500

# --- Delete Ticket ---
@app.route("/delete_ticket/<int:ticket_id>", methods=["POST"])
@login_required
def delete_ticket(ticket_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch ticket
        cursor.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            conn.close()
            return jsonify({"success": False, "error": f"Ticket #{ticket_id} not found"}), 404

        # Check permissions
        if current_user.role == "User" and ticket["user_id"] != current_user.id:
            conn.close()
            return jsonify({"success": False, "error": "Unauthorized to delete this ticket"}), 403

        # Delete related comments first
        cursor.execute("DELETE FROM comments WHERE ticket_id = ?", (ticket_id,))
        # Delete ticket
        cursor.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": f"Ticket #{ticket_id} has been deleted."})
    except Exception as e:
        logger.error(f"Error deleting ticket {ticket_id}: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500

# --- Screenshot upload ---
@app.route("/upload_screenshot", methods=["POST"])
@login_required
def upload_screenshot():
    try:
        file = request.files.get("screenshot")
        if not file or not allowed_file(file.filename):
            return jsonify({"error": "Invalid or missing file"}), 400

        # Save file
        filename = secure_filename(f"{current_user.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Analyze screenshot for error text
        analysis = analyze_image_with_pplx(filepath)
        detected_error = analysis if analysis and "Error analyzing" not in analysis else None

        # Auto-detect category
        auto_category = None
        if detected_error:
            msg_lower = detected_error.lower()
            for category, keywords in {
                "Network": ["network", "wifi", "internet", "vpn"],
                "Access": ["login", "password", "sign in", "credentials", "auth", "invalid"],
                "Software": ["app", "application", "outlook", "excel", "word", "teams"],
                "Hardware": ["laptop", "keyboard", "printer", "device"],
            }.items():
                if any(k in msg_lower for k in keywords):
                    auto_category = category
                    break

        # Start/Update flow
        flow = {
            "issue": "Error detected from screenshot",
            "error_message": detected_error,
            "screenshot": filename,
            "category": auto_category or "General",
            "stage": "confirm_ticket"
        }
        session["ticket_in_progress"] = flow
        session.modified = True

        reply_msg = (
            f"Screenshot uploaded. Error detected: \"{detected_error}\". "
            f"I've categorized this as {flow['category']}. Do you want me to create the ticket now? (yes/no)"
        )

        return jsonify({
            "success": True,
            "file_url": f"/uploads/{filename}",
            "analysis": detected_error,
            "reply": reply_msg
        })

    except Exception as e:
        logger.error(f"Screenshot upload error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- Update status & priority ---
@app.route("/update_status/<int:ticket_id>", methods=["POST"])
@login_required
def update_status(ticket_id):
    if current_user.role not in ["Staff", "Admin"]:
        return jsonify({"error": "Unauthorized - only Staff and Admin can update status"}), 403
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch current ticket status
        cursor.execute("SELECT status FROM tickets WHERE id = ?", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            conn.close()
            return jsonify({"error": f"Ticket #{ticket_id} not found"}), 404

        current_status = ticket["status"]
        if current_status in ["Closed", "Cancelled"]:
            conn.close()
            return jsonify({
                "error": f"Ticket #{ticket_id} is already {current_status} and cannot be updated."
            }), 400

        # Validate new status
        data = request.get_json()
        new_status = data.get("status")
        if new_status not in ["New", "Open", "In Progress", "Resolved", "Closed"]:
            conn.close()
            return jsonify({"error": "Invalid status"}), 400

        # Update
        cursor.execute("UPDATE tickets SET status = ? WHERE id = ?", (new_status, ticket_id))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "status": new_status})
    except Exception as e:
        logger.error(f"Error updating status for ticket {ticket_id}: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/update_priority/<int:ticket_id>", methods=["POST"])
@login_required
def update_priority(ticket_id):
    if current_user.role != "Admin":
        return jsonify({"error": "Unauthorized - only Admin can update priority"}), 403
    try:
        data = request.get_json()
        new_priority = data.get("priority")
        if new_priority not in ["Low", "Medium", "High"]:
            return jsonify({"error": "Invalid priority"}), 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tickets SET priority = ? WHERE id = ?", (new_priority, ticket_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "priority": new_priority})
    except Exception as e:
        logger.error(f"Error updating priority for ticket {ticket_id}: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- Run ---
if __name__ == "__main__":
    ensure_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
