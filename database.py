import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = "tickets.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('User', 'Staff', 'Admin')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Tickets table - Add assigned_to column
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        user_message TEXT NOT NULL,
        bot_reply TEXT,
        status TEXT DEFAULT 'New',
        ticket_type TEXT DEFAULT 'General',
        priority TEXT DEFAULT 'Medium',
        assigned_to INTEGER,  -- NEW: Staff member assigned to this ticket
        screenshot TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(assigned_to) REFERENCES users(id)
    )
    """)

    # Comments table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        message TEXT,
        file_url TEXT,
        is_screenshot INTEGER DEFAULT 0,
        author_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ticket_id) REFERENCES tickets(id),
        FOREIGN KEY(author_id) REFERENCES users(id)
    )
    """)

    # Add the assigned_to column to existing tickets table if it doesn't exist
    cursor.execute("PRAGMA table_info(tickets)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'assigned_to' not in columns:
        cursor.execute("ALTER TABLE tickets ADD COLUMN assigned_to INTEGER REFERENCES users(id)")

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets(priority)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_assigned_to ON tickets(assigned_to)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_comments_ticket_id ON comments(ticket_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_comments_author_id ON comments(author_id)")

    conn.commit()
    conn.close()

def ensure_db():
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count == 0:
        default_users = [
            ('admin', 'admin', 'Admin'),
            ('staff1', 'staff1', 'Staff'),
            ('staff2', 'staff2', 'Staff'),
            ('staff3', 'staff3', 'Staff'),
            ('user', 'user', 'User')
        ]
        for username, password, role in default_users:
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                           (username, hashed_password, role))
        conn.commit()
        print("Default users created: admin/admin, staff1/staff1, staff2/staff2, staff3/staff3, user/user")
    conn.close()

def create_user(username, password, role="User"):
    if role not in ["User", "Staff", "Admin"]:
        raise ValueError("Invalid role")
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                       (username, hashed_password, role))
        user_id = cursor.lastrowid
        conn.commit()
        print(f"User '{username}' created with role '{role}' and ID {user_id}")
        return user_id
    except sqlite3.IntegrityError:
        raise ValueError("Username already exists")
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        print(f"Authentication successful for {username} with role {user['role']}")
        return dict(user)
    print(f"Authentication failed for {username}")
    return None

def get_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_username(username):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_all_staff_members():
    """Get all users with Staff role for assignment dropdown"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE role = 'Staff' ORDER BY username")
    staff = cursor.fetchall()
    conn.close()
    return [dict(s) for s in staff]

def save_ticket(user_id, user_message, bot_reply, priority="Medium", ticket_type="General", screenshot=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO tickets (user_id, user_message, bot_reply, priority, ticket_type, status, screenshot, updated_at)
        VALUES (?, ?, ?, ?, ?, 'New', ?, CURRENT_TIMESTAMP)
    """, (user_id, user_message, bot_reply, priority, ticket_type, screenshot))
    ticket_id = cursor.lastrowid
    conn.commit()
    conn.close()
    print(f"Ticket #{ticket_id} created by user ID {user_id} with priority {priority}")
    return ticket_id

def get_ticket(ticket_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, 
               u.username as user_name, 
               s.username as assigned_staff_name
        FROM tickets t 
        LEFT JOIN users u ON t.user_id = u.id
        LEFT JOIN users s ON t.assigned_to = s.id
        WHERE t.id = ?
    """, (ticket_id,))
    ticket = cursor.fetchone()
    conn.close()
    return ticket

def get_filtered_tickets(user_id=None, status=None, priority=None, assigned_to=None):
    """Enhanced filtering with assignment support"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = """
        SELECT t.*, 
               u.username, 
               u.role,
               s.username as assigned_staff_name
        FROM tickets t 
        JOIN users u ON t.user_id = u.id
        LEFT JOIN users s ON t.assigned_to = s.id
    """
    params = []
    conditions = []
    
    if user_id is not None:
        conditions.append("t.user_id = ?")
        params.append(user_id)
    
    if assigned_to is not None:
        if assigned_to == "unassigned":
            conditions.append("t.assigned_to IS NULL")
        else:
            conditions.append("t.assigned_to = ?")
            params.append(assigned_to)
    
    if status and status != "All":
        conditions.append("t.status = ?")
        params.append(status)
    
    if priority and priority != "All":
        conditions.append("t.priority = ?")
        params.append(priority)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY t.created_at DESC"

    cursor.execute(query, params)
    tickets = cursor.fetchall()
    conn.close()
    return tickets

def get_all_tickets():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, 
               u.username, 
               u.role,
               s.username as assigned_staff_name
        FROM tickets t 
        JOIN users u ON t.user_id = u.id 
        LEFT JOIN users s ON t.assigned_to = s.id
        ORDER BY t.created_at DESC
    """)
    tickets = cursor.fetchall()
    conn.close()
    return tickets

def get_tickets_for_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, 
               u.username, 
               u.role,
               s.username as assigned_staff_name
        FROM tickets t 
        JOIN users u ON t.user_id = u.id 
        LEFT JOIN users s ON t.assigned_to = s.id
        WHERE t.user_id = ? 
        ORDER BY t.created_at DESC
    """, (user_id,))
    tickets = cursor.fetchall()
    conn.close()
    return tickets

def assign_ticket(ticket_id, assigned_to_id):
    """Assign a ticket to a staff member (or unassign if assigned_to_id is None)"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Verify ticket exists
    cursor.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,))
    if not cursor.fetchone():
        conn.close()
        raise ValueError(f"Ticket #{ticket_id} not found")
    
    # Verify staff member exists if assigning
    if assigned_to_id is not None:
        cursor.execute("SELECT id FROM users WHERE id = ? AND role = 'Staff'", (assigned_to_id,))
        if not cursor.fetchone():
            conn.close()
            raise ValueError(f"Staff member with ID {assigned_to_id} not found")
    
    cursor.execute("""
        UPDATE tickets 
        SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    """, (assigned_to_id, ticket_id))
    
    conn.commit()
    conn.close()
    
    if assigned_to_id:
        print(f"Ticket #{ticket_id} assigned to staff ID {assigned_to_id}")
    else:
        print(f"Ticket #{ticket_id} unassigned")
    
    return True

# ----------------------
# Comments & Screenshots
# ----------------------
def add_comment(ticket_id, message=None, author_id=None, file_url=None, is_screenshot=0):
    """Add a comment or a screenshot to a ticket. Either message or file_url is required."""
    if not message and not file_url:
        raise ValueError("Either message or file_url must be provided.")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,))
    if not cursor.fetchone():
        conn.close()
        raise ValueError(f"Ticket #{ticket_id} not found")
    cursor.execute("SELECT id FROM users WHERE id = ?", (author_id,))
    if not cursor.fetchone():
        conn.close()
        raise ValueError(f"Author with ID {author_id} not found")
    
    cursor.execute("""
        INSERT INTO comments (ticket_id, message, author_id, file_url, is_screenshot)
        VALUES (?, ?, ?, ?, ?)
    """, (ticket_id, message, author_id, file_url, is_screenshot))
    comment_id = cursor.lastrowid
    cursor.execute("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
    conn.commit()
    conn.close()
    print(f"Comment #{comment_id} added to ticket #{ticket_id} by author {author_id}")
    return comment_id

def add_screenshot_comment(ticket_id, file_url, author_id):
    """Helper to add a screenshot comment."""
    return add_comment(ticket_id, message="[screenshot]", author_id=author_id, file_url=file_url, is_screenshot=1)

def get_comments(ticket_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.*, u.username AS author_name, u.role AS author_role
        FROM comments c
        JOIN users u ON c.author_id = u.id
        WHERE c.ticket_id=?
        ORDER BY c.created_at ASC
    """, (ticket_id,))
    comments = cursor.fetchall()
    conn.close()
    return comments

def get_ticket_with_comments(ticket_id):
    ticket = get_ticket(ticket_id)
    comments = get_comments(ticket_id)
    return ticket, comments

# ----------------------
# Ticket updates
# ----------------------
def update_ticket_status(ticket_id, status):
    valid_statuses = ['New', 'Open', 'In Progress', 'Resolved', 'Closed']
    if status not in valid_statuses:
        raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    """, (status, ticket_id))
    affected_rows = cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Ticket #{ticket_id} status updated to {status}")
    return affected_rows > 0

def update_ticket_priority(ticket_id, priority):
    valid_priorities = ['Low', 'Medium', 'High']
    if priority not in valid_priorities:
        raise ValueError(f"Invalid priority. Must be one of: {valid_priorities}")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE tickets SET priority = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    """, (priority, ticket_id))
    affected_rows = cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Ticket #{ticket_id} priority updated to {priority}")
    return affected_rows > 0

def update_ticket_category(ticket_id, category):
    """Update ticket category/type"""
    valid_categories = ['Network', 'Hardware', 'Software', 'Access', 'Security', 'Email/Communication', 'Accounts/HR', 'General']
    if category not in valid_categories:
        raise ValueError(f"Invalid category. Must be one of: {valid_categories}")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE tickets SET ticket_type = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    """, (category, ticket_id))
    affected_rows = cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Ticket #{ticket_id} category updated to {category}")
    return affected_rows > 0

# ----------------------
# Stats & Activity
# ----------------------
def get_ticket_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    stats = {}
    cursor.execute("SELECT COUNT(*) FROM tickets")
    stats['total'] = cursor.fetchone()[0]
    cursor.execute("SELECT status, COUNT(*) FROM tickets GROUP BY status")
    stats['by_status'] = {row[0]: row[1] for row in cursor.fetchall()}
    cursor.execute("SELECT priority, COUNT(*) FROM tickets GROUP BY priority")
    stats['by_priority'] = {row[0]: row[1] for row in cursor.fetchall()}
    cursor.execute("""
        SELECT u.role, COUNT(*) 
        FROM tickets t 
        JOIN users u ON t.user_id = u.id 
        GROUP BY u.role
    """)
    stats['by_role'] = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Assignment stats
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE assigned_to IS NULL")
    stats['unassigned'] = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE assigned_to IS NOT NULL")
    stats['assigned'] = cursor.fetchone()[0]
    
    conn.close()
    return stats

def get_user_tickets_count(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE user_id = ?", (user_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_recent_activity(limit=10):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 'ticket' as type, t.id, t.created_at, u.username, u.role, t.status, t.priority,
               s.username as assigned_staff_name
        FROM tickets t
        JOIN users u ON t.user_id = u.id
        LEFT JOIN users s ON t.assigned_to = s.id
        ORDER BY t.created_at DESC
        LIMIT ?
    """, (limit,))
    activity = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return activity

# ----------------------
# Access control
# ----------------------
def check_user_can_access_ticket(user_id, user_role, ticket_id):
    if user_role == 'Admin':
        return True
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, assigned_to FROM tickets WHERE id = ?", (ticket_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    ticket_user_id, assigned_to = result
    
    # User can see their own tickets
    if user_role == 'User' and ticket_user_id == user_id:
        return True
    
    # Staff can see tickets assigned to them
    if user_role == 'Staff' and assigned_to == user_id:
        return True
    
    return False

def check_user_can_comment_on_ticket(user_id, user_role, ticket_id):
    # Same access rules as viewing tickets
    return check_user_can_access_ticket(user_id, user_role, ticket_id)