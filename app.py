import csv
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import click
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TASKFLOW_DB_PATH", BASE_DIR / "tasks.db"))
STATUSES = ("To do", "In progress", "Done")
PRIORITIES = ("Low", "Medium", "High")
PROJECT_STATUSES = ("Planning", "In progress", "Completed", "On hold")
ADMIN_ROLES = ("Super Admin", "Admin", "User")
ADMIN_PAGE_SIZE = 20

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
                name TEXT NOT NULL, description TEXT DEFAULT '', start_date TEXT DEFAULT '',
                due_date TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Planning',
                priority TEXT NOT NULL DEFAULT 'Medium', progress INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                description TEXT DEFAULT '', priority TEXT NOT NULL DEFAULT 'Medium',
                status TEXT NOT NULL DEFAULT 'To do', due_date TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS team_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
                name TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Member',
                created_at TEXT NOT NULL, UNIQUE(owner_id, email),
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS project_members (
                project_id INTEGER NOT NULL, member_id INTEGER NOT NULL,
                PRIMARY KEY(project_id, member_id),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY(member_id) REFERENCES team_members(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
                project_id INTEGER, author_id INTEGER, content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE SET NULL,
                FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
                action TEXT NOT NULL, entity TEXT NOT NULL, entity_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER PRIMARY KEY, timezone TEXT NOT NULL DEFAULT 'UTC',
                week_start TEXT NOT NULL DEFAULT 'Monday',
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER,
                admin_name TEXT NOT NULL, action TEXT NOT NULL,
                target_type TEXT NOT NULL, target_id INTEGER,
                details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                FOREIGN KEY(admin_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
            );
        """)
        user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        if "role" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'User'")
        if "status" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'Active'")
        if "reset_token_hash" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN reset_token_hash TEXT")
        if "reset_expires_at" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN reset_expires_at TEXT")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(tasks)")}
        if "owner_id" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN owner_id INTEGER REFERENCES users(id)")
        if "project_id" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL")
        if "assignee_id" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN assignee_id INTEGER REFERENCES team_members(id) ON DELETE SET NULL")
        if "updated_at" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN updated_at TEXT DEFAULT ''")
        if "is_archived" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0")
        project_columns = {row[1] for row in conn.execute("PRAGMA table_info(projects)")}
        if "is_archived" not in project_columns:
            conn.execute("ALTER TABLE projects ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_owner_status ON tasks(owner_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_projects_owner_due ON projects(owner_id, due_date)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)")
        conn.execute("INSERT OR IGNORE INTO app_settings(key,value,updated_at) VALUES('registration_enabled','true',?)", (now(),))


def now():
    return datetime.now().isoformat(timespec="seconds")


@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id:
        with get_db() as conn:
            g.user = conn.execute("SELECT id, name, email, role, status FROM users WHERE id = ?", (user_id,)).fetchone()
        if g.user is None or g.user["status"] != "Active":
            session.clear()
            g.user = None


@app.before_request
def protect_admin_posts():
    if request.path.startswith("/admin/") and request.path != "/admin/login" and request.method == "POST":
        expected = session.get("admin_csrf_token", "")
        submitted = request.form.get("admin_csrf_token", "")
        if not expected or not submitted or not hmac.compare_digest(expected, submitted):
            abort(400)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("admin_login", next=request.path))
        if g.user["role"] not in {"Admin", "Super Admin"}:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def super_admin_required(view):
    @wraps(view)
    @admin_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "Super Admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def common_template_data():
    csrf_token = session.setdefault("admin_csrf_token", secrets.token_urlsafe(32))
    return {"current_user": g.get("user"), "current_year": date.today().year, "current_date": date.today().isoformat(), "admin_csrf_token": csrf_token}


def record_activity(owner_id, action, entity, entity_id=None):
    with get_db() as conn:
        conn.execute("INSERT INTO activity(owner_id, action, entity, entity_id, created_at) VALUES (?, ?, ?, ?, ?)",
                     (owner_id, action, entity, entity_id, now()))


def record_admin_action(action, target_type, target_id=None, details=""):
    with get_db() as conn:
        conn.execute("INSERT INTO audit_logs(admin_id,admin_name,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?,?)",
                     (g.user["id"], g.user["name"], action, target_type, target_id, details[:500], now()))


def admin_page(page_name, title, **context):
    return render_template("admin.html", admin_page=page_name, title=title, **context)


def pagination(total, requested_page):
    pages = max(1, (total + ADMIN_PAGE_SIZE - 1) // ADMIN_PAGE_SIZE)
    current = min(max(requested_page, 1), pages)
    return {"page": current, "pages": pages, "total": total, "offset": (current - 1) * ADMIN_PAGE_SIZE}


def seed_workspace(owner_id):
    today = date.today()
    with get_db() as conn:
        project_id = conn.execute(
            "INSERT INTO projects(owner_id,name,description,start_date,due_date,status,priority,created_at) VALUES(?,?,?,?,?,'In progress','High',?)",
            (owner_id, "Product launch", "Coordinate the work behind the next release.", today.isoformat(), (today + timedelta(days=18)).isoformat(), now()),
        ).lastrowid
        member_id = conn.execute(
            "INSERT INTO team_members(owner_id,name,email,role,created_at) VALUES(?,?,?,?,?)",
            (owner_id, "Jordan Lee", "jordan@example.test", "Product designer", now()),
        ).lastrowid
        conn.execute("INSERT INTO project_members(project_id,member_id) VALUES(?,?)", (project_id, member_id))
        sample_tasks = [
            ("Finalize launch brief", "Align the team on audience, scope, and success measures.", "High", "In progress", (today + timedelta(days=3)).isoformat(), member_id),
            ("Review onboarding flow", "Collect feedback on the first-run experience.", "Medium", "To do", (today + timedelta(days=7)).isoformat(), member_id),
            ("Prepare release checklist", "Confirm owners and readiness for launch day.", "Low", "To do", (today + timedelta(days=12)).isoformat(), None),
        ]
        for title, description, priority, status, due_date, assignee_id in sample_tasks:
            conn.execute("INSERT INTO tasks(title,description,priority,status,due_date,created_at,owner_id,project_id,assignee_id,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (title, description, priority, status, due_date, now(), owner_id, project_id, assignee_id, now()))
        refresh_project_progress(conn, project_id)
        conn.execute("INSERT INTO activity(owner_id,action,entity,entity_id,created_at) VALUES(?,?,?,?,?)",
                     (owner_id, "created your sample workspace", "Product launch", project_id, now()))


def owned_project(project_id, owner_id):
    with get_db() as conn:
        return conn.execute("SELECT * FROM projects WHERE id = ? AND owner_id = ? AND is_archived=0", (project_id, owner_id)).fetchone()


def owned_task(task_id, owner_id):
    with get_db() as conn:
        return conn.execute("SELECT * FROM tasks WHERE id = ? AND owner_id = ? AND is_archived=0", (task_id, owner_id)).fetchone()


def page(page_name, title, **context):
    return render_template("workspace.html", page=page_name, title=title, **context)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        with get_db() as conn:
            registration_setting = conn.execute("SELECT value FROM app_settings WHERE key='registration_enabled'").fetchone()
        if registration_setting and registration_setting["value"] != "true":
            flash("New account registration is currently disabled.", "error")
            return render_template("auth.html", mode="register", title="Create your account"), 403
        name = request.form.get("name", "").strip()[:80]
        email = request.form.get("email", "").strip().lower()[:254]
        password = request.form.get("password", "")
        if not name or "@" not in email:
            flash("Enter your name and a valid email address.", "error")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        else:
            try:
                with get_db() as conn:
                    cursor = conn.execute("INSERT INTO users(name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                                          (name, email, generate_password_hash(password), now()))
                    user_id = cursor.lastrowid
                    conn.execute("INSERT INTO user_settings(user_id) VALUES (?)", (user_id,))
                    conn.execute("UPDATE tasks SET owner_id = ? WHERE owner_id IS NULL", (user_id,))
                seed_workspace(user_id)
                session.clear()
                session["user_id"] = user_id
                flash("Your workspace is ready.", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
    return render_template("auth.html", mode="register", title="Create your account")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Email or password is incorrect.", "error")
        elif user["status"] != "Active":
            flash("This account is suspended. Contact a workspace administrator.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            destination = request.args.get("next", "")
            return redirect(destination if destination.startswith("/") and not destination.startswith("//") else url_for("index"))
    return render_template("auth.html", mode="login", title="Welcome back")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.cli.command("create-super-admin")
@click.option("--email", prompt=True, help="Email address for the Super Admin account.")
@click.option("--name", prompt=True, help="Display name for the Super Admin account.")
def create_super_admin(email, name):
    """Create or promote an account to Super Admin from a trusted terminal."""
    email = email.strip().lower()
    name = name.strip()[:80]
    password = click.prompt("Password (minimum 12 characters)", hide_input=True, confirmation_prompt=True)
    if not name or "@" not in email or len(password) < 12:
        raise click.ClickException("Provide a name, valid email, and password with at least 12 characters.")
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            conn.execute("UPDATE users SET name=?,password_hash=?,role='Super Admin',status='Active' WHERE id=?",
                         (name, generate_password_hash(password), existing["id"]))
            user_id = existing["id"]
        else:
            cursor = conn.execute("INSERT INTO users(name,email,password_hash,created_at,role,status) VALUES(?,?,?,?, 'Super Admin','Active')",
                                  (name, email, generate_password_hash(password), now()))
            user_id = cursor.lastrowid
            conn.execute("INSERT INTO user_settings(user_id) VALUES(?)", (user_id,))
        conn.execute("INSERT INTO audit_logs(admin_id,admin_name,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?,?)",
                     (user_id, name, "Super Admin bootstrap", "user", user_id, "Created or promoted through the trusted CLI", now()))
    click.echo(f"Super Admin account ready for {email}. Sign in at /admin/login.")


@app.route("/")
@app.route("/dashboard")
@login_required
def index():
    with get_db() as conn:
        project_stats = conn.execute("""SELECT
            SUM(CASE WHEN status != 'Completed' THEN 1 ELSE 0 END) active,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) completed,
            SUM(CASE WHEN status != 'Completed' AND due_date != '' AND due_date < ? THEN 1 ELSE 0 END) at_risk
            FROM projects WHERE owner_id = ? AND is_archived=0""", (date.today().isoformat(), g.user["id"])).fetchone()
        task_stats = conn.execute("SELECT COUNT(*) total, SUM(status = 'In progress') doing, SUM(status = 'Done') done FROM tasks WHERE owner_id = ? AND is_archived=0", (g.user["id"],)).fetchone()
        projects = conn.execute("""SELECT p.*, (SELECT COUNT(*) FROM tasks t WHERE t.project_id=p.id AND t.owner_id=p.owner_id AND t.is_archived=0) task_count,
            (SELECT COUNT(*) FROM tasks t WHERE t.project_id=p.id AND t.owner_id=p.owner_id AND t.is_archived=0 AND t.status='Done') done_count
            FROM projects p WHERE p.owner_id=? AND p.is_archived=0 ORDER BY CASE p.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, p.due_date LIMIT 6""", (g.user["id"],)).fetchall()
        tasks = conn.execute("SELECT * FROM tasks WHERE owner_id = ? AND is_archived=0 ORDER BY CASE priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, due_date LIMIT 6", (g.user["id"],)).fetchall()
        activities = conn.execute("SELECT * FROM activity WHERE owner_id=? ORDER BY id DESC LIMIT 6", (g.user["id"],)).fetchall()
        deadlines = conn.execute("SELECT id, name, due_date, status FROM projects WHERE owner_id=? AND is_archived=0 AND due_date >= ? AND status != 'Completed' ORDER BY due_date LIMIT 5", (g.user["id"], date.today().isoformat())).fetchall()
    stats = {"active": project_stats["active"] or 0, "doing": task_stats["doing"] or 0, "completed": project_stats["completed"] or 0, "at_risk": project_stats["at_risk"] or 0, "tasks": task_stats["total"] or 0, "done_tasks": task_stats["done"] or 0}
    return page("dashboard", "Dashboard", stats=stats, projects=projects, tasks=tasks, activities=activities, deadlines=deadlines)


@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks_page():
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:160]
        description = request.form.get("description", "").strip()[:2000]
        priority = request.form.get("priority", "Medium")
        due_date = request.form.get("due_date", "").strip()
        project_id = request.form.get("project_id", type=int) or request.args.get("project_id", type=int)
        assignee_id = request.form.get("assignee_id", type=int)
        if not title:
            flash("Please enter a task title.", "error")
        elif priority not in PRIORITIES or not valid_date(due_date):
            flash("Choose a valid priority and due date.", "error")
        elif project_id and not owned_project(project_id, g.user["id"]):
            flash("That project is not available in your workspace.", "error")
        elif assignee_id and not owned_member(assignee_id, g.user["id"]):
            flash("That team member is not available in your workspace.", "error")
        else:
            with get_db() as conn:
                cursor = conn.execute("INSERT INTO tasks(title, description, priority, status, due_date, created_at, owner_id, project_id, assignee_id, updated_at) VALUES (?, ?, ?, 'To do', ?, ?, ?, ?, ?, ?)",
                                      (title, description, priority, due_date, now(), g.user["id"], project_id, assignee_id, now()))
                refresh_project_progress(conn, project_id)
            record_activity(g.user["id"], "created task", title, cursor.lastrowid)
            flash("Task created.", "success")
            return redirect(url_for("tasks_page"))
    status = request.args.get("status", "All")
    search = request.args.get("q", "").strip()[:100]
    view = request.args.get("view", "list")
    if view not in {"list", "kanban"}:
        view = "list"
    query = "SELECT t.*, p.name project_name, m.name assignee_name FROM tasks t LEFT JOIN projects p ON p.id=t.project_id LEFT JOIN team_members m ON m.id=t.assignee_id WHERE t.owner_id=? AND t.is_archived=0 AND (t.project_id IS NULL OR p.is_archived=0)"
    params = [g.user["id"]]
    if status in STATUSES:
        query += " AND t.status=?"
        params.append(status)
    if search:
        query += " AND (t.title LIKE ? OR t.description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    query += " ORDER BY CASE t.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, t.due_date, t.id DESC"
    with get_db() as conn:
        tasks = conn.execute(query, params).fetchall()
        projects = conn.execute("SELECT id, name FROM projects WHERE owner_id=? AND is_archived=0 ORDER BY name", (g.user["id"],)).fetchall()
        members = conn.execute("SELECT id, name FROM team_members WHERE owner_id=? ORDER BY name", (g.user["id"],)).fetchall()
    selected_project_id = request.args.get("project_id", type=int)
    if selected_project_id and not owned_project(selected_project_id, g.user["id"]):
        selected_project_id = None
    return page("tasks", "Tasks", tasks=tasks, projects=projects, members=members, status=status, q=search, view=view, selected_project_id=selected_project_id)


def valid_date(value):
    if not value:
        return True
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def owned_member(member_id, owner_id):
    with get_db() as conn:
        return conn.execute("SELECT id FROM team_members WHERE id=? AND owner_id=?", (member_id, owner_id)).fetchone()


def refresh_project_progress(conn, project_id):
    if project_id:
        row = conn.execute("SELECT COUNT(*) total, SUM(status='Done') completed FROM tasks WHERE project_id=? AND is_archived=0", (project_id,)).fetchone()
        progress = round((row["completed"] or 0) * 100 / row["total"]) if row["total"] else 0
        conn.execute("UPDATE projects SET progress=? WHERE id=?", (progress, project_id))


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit_task(task_id):
    task = owned_task(task_id, g.user["id"])
    if not task:
        return "Task not found", 404
    with get_db() as conn:
        projects = conn.execute("SELECT id, name FROM projects WHERE owner_id=? AND is_archived=0 ORDER BY name", (g.user["id"],)).fetchall()
        members = conn.execute("SELECT id, name FROM team_members WHERE owner_id=? ORDER BY name", (g.user["id"],)).fetchall()
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:160]
        status = request.form.get("status", "")
        priority = request.form.get("priority", "")
        due_date = request.form.get("due_date", "").strip()
        project_id = request.form.get("project_id", type=int) or None
        assignee_id = request.form.get("assignee_id", type=int) or None
        if not title or status not in STATUSES or priority not in PRIORITIES or not valid_date(due_date):
            flash("Check the task title, status, priority, and date.", "error")
        elif project_id and not owned_project(project_id, g.user["id"]):
            flash("That project is not available in your workspace.", "error")
        elif assignee_id and not owned_member(assignee_id, g.user["id"]):
            flash("That team member is not available in your workspace.", "error")
        else:
            old_project = task["project_id"]
            with get_db() as conn:
                conn.execute("UPDATE tasks SET title=?, description=?, status=?, priority=?, due_date=?, project_id=?, assignee_id=?, updated_at=? WHERE id=? AND owner_id=?",
                             (title, request.form.get("description", "").strip()[:2000], status, priority, due_date, project_id, assignee_id, now(), task_id, g.user["id"]))
                refresh_project_progress(conn, old_project)
                refresh_project_progress(conn, project_id)
            record_activity(g.user["id"], "updated task", title, task_id)
            flash("Task updated.", "success")
            return redirect(url_for("tasks_page"))
    return page("task_form", "Edit task", task=task, projects=projects, members=members)


@app.route("/tasks/<int:task_id>/update", methods=["POST"])
@login_required
def update_task(task_id):
    task = owned_task(task_id, g.user["id"])
    status = request.form.get("status", "To do")
    if not task:
        return "Task not found", 404
    if status not in STATUSES:
        flash("Invalid status.", "error")
    else:
        with get_db() as conn:
            conn.execute("UPDATE tasks SET status=?, updated_at=? WHERE id=? AND owner_id=?", (status, now(), task_id, g.user["id"]))
            refresh_project_progress(conn, task["project_id"])
        record_activity(g.user["id"], "updated task status", task["title"], task_id)
        flash("Task updated.", "success")
    return redirect(request.form.get("next") if request.form.get("next", "").startswith("/") else url_for("tasks_page"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    task = owned_task(task_id, g.user["id"])
    if not task:
        return "Task not found", 404
    with get_db() as conn:
        conn.execute("DELETE FROM tasks WHERE id=? AND owner_id=?", (task_id, g.user["id"]))
        refresh_project_progress(conn, task["project_id"])
    record_activity(g.user["id"], "deleted task", task["title"], task_id)
    flash("Task deleted.", "success")
    return redirect(request.form.get("next") if request.form.get("next", "").startswith("/") else url_for("tasks_page"))


@app.route("/projects", methods=["GET", "POST"])
@login_required
def projects_page():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:120]
        status = request.form.get("status", "Planning")
        priority = request.form.get("priority", "Medium")
        start_date = request.form.get("start_date", "").strip()
        due_date = request.form.get("due_date", "").strip()
        if not name or status not in PROJECT_STATUSES or priority not in PRIORITIES or not valid_date(start_date) or not valid_date(due_date):
            flash("Enter a project name and valid project details.", "error")
        else:
            with get_db() as conn:
                cursor = conn.execute("INSERT INTO projects(owner_id,name,description,start_date,due_date,status,priority,created_at) VALUES(?,?,?,?,?,?,?,?)",
                                      (g.user["id"], name, request.form.get("description", "").strip()[:3000], start_date, due_date, status, priority, now()))
                assign_project_members(conn, cursor.lastrowid, request.form.getlist("member_ids"), g.user["id"])
            record_activity(g.user["id"], "created project", name, cursor.lastrowid)
            flash("Project created.", "success")
            return redirect(url_for("projects_page"))
    search = request.args.get("q", "").strip()[:100]
    status = request.args.get("status", "All")
    sort = request.args.get("sort", "due_date")
    order = {"name": "name COLLATE NOCASE", "priority": "CASE priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END", "due_date": "due_date"}.get(sort, "due_date")
    query = "SELECT * FROM projects WHERE owner_id=? AND is_archived=0"
    params = [g.user["id"]]
    if status in PROJECT_STATUSES:
        query += " AND status=?"
        params.append(status)
    if search:
        query += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    query += f" ORDER BY {order}, id DESC"
    with get_db() as conn:
        projects = conn.execute(query, params).fetchall()
        projects = [dict(p) for p in projects]
        for project in projects:
            project["task_total"] = conn.execute("SELECT COUNT(*) FROM tasks WHERE project_id=? AND owner_id=? AND is_archived=0", (project["id"], g.user["id"])).fetchone()[0]
            project["task_done"] = conn.execute("SELECT COUNT(*) FROM tasks WHERE project_id=? AND owner_id=? AND is_archived=0 AND status='Done'", (project["id"], g.user["id"])).fetchone()[0]
            project["members"] = conn.execute("SELECT m.name FROM team_members m JOIN project_members pm ON pm.member_id=m.id WHERE pm.project_id=? AND m.owner_id=?", (project["id"], g.user["id"])).fetchall()
        members = conn.execute("SELECT id,name FROM team_members WHERE owner_id=? ORDER BY name", (g.user["id"],)).fetchall()
    return page("projects", "Projects", projects=projects, members=members, q=search, status=status, sort=sort)


def assign_project_members(conn, project_id, member_ids, owner_id):
    for raw_id in member_ids:
        if raw_id.isdigit():
            conn.execute("INSERT OR IGNORE INTO project_members(project_id,member_id) SELECT ?,id FROM team_members WHERE id=? AND owner_id=?",
                         (project_id, int(raw_id), owner_id))


@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    project = owned_project(project_id, g.user["id"])
    if not project:
        return "Project not found", 404
    with get_db() as conn:
        tasks = conn.execute("SELECT t.*,m.name assignee_name FROM tasks t LEFT JOIN team_members m ON m.id=t.assignee_id WHERE t.project_id=? AND t.owner_id=? AND t.is_archived=0 ORDER BY t.due_date,t.id DESC", (project_id, g.user["id"])).fetchall()
        members = conn.execute("SELECT m.* FROM team_members m JOIN project_members pm ON pm.member_id=m.id WHERE pm.project_id=? AND m.owner_id=?", (project_id, g.user["id"])).fetchall()
    return render_template("project_detail.html", project=project, tasks=tasks, members=members, statuses=STATUSES)


@app.route("/projects/<int:project_id>/edit", methods=["GET", "POST"])
@login_required
def edit_project(project_id):
    project = owned_project(project_id, g.user["id"])
    if not project:
        return "Project not found", 404
    with get_db() as conn:
        members = conn.execute("SELECT id,name FROM team_members WHERE owner_id=? ORDER BY name", (g.user["id"],)).fetchall()
        selected = {row[0] for row in conn.execute("SELECT member_id FROM project_members WHERE project_id=?", (project_id,))}
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:120]
        status = request.form.get("status", "")
        priority = request.form.get("priority", "")
        start_date = request.form.get("start_date", "").strip()
        due_date = request.form.get("due_date", "").strip()
        if not name or status not in PROJECT_STATUSES or priority not in PRIORITIES or not valid_date(start_date) or not valid_date(due_date):
            flash("Enter a project name and valid project details.", "error")
        else:
            with get_db() as conn:
                conn.execute("UPDATE projects SET name=?,description=?,start_date=?,due_date=?,status=?,priority=? WHERE id=? AND owner_id=?",
                             (name, request.form.get("description", "").strip()[:3000], start_date, due_date, status, priority, project_id, g.user["id"]))
                conn.execute("DELETE FROM project_members WHERE project_id=?", (project_id,))
                assign_project_members(conn, project_id, request.form.getlist("member_ids"), g.user["id"])
            record_activity(g.user["id"], "updated project", name, project_id)
            flash("Project updated.", "success")
            return redirect(url_for("project_detail", project_id=project_id))
    return page("project_form", "Edit project", project=project, members=members, selected_members=selected, project_statuses=PROJECT_STATUSES, priorities=PRIORITIES)


@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    project = owned_project(project_id, g.user["id"])
    if not project:
        return "Project not found", 404
    with get_db() as conn:
        conn.execute("UPDATE tasks SET project_id=NULL WHERE project_id=? AND owner_id=?", (project_id, g.user["id"]))
        conn.execute("DELETE FROM projects WHERE id=? AND owner_id=?", (project_id, g.user["id"]))
    record_activity(g.user["id"], "deleted project", project["name"], project_id)
    flash("Project deleted.", "success")
    return redirect(url_for("projects_page"))


@app.route("/team", methods=["GET", "POST"])
@login_required
def team_page():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        email = request.form.get("email", "").strip().lower()[:254]
        role = request.form.get("role", "Member").strip()[:60]
        if not name or "@" not in email or not role:
            flash("Enter a name, valid email, and role.", "error")
        else:
            try:
                with get_db() as conn:
                    conn.execute("INSERT INTO team_members(owner_id,name,email,role,created_at) VALUES(?,?,?,?,?)", (g.user["id"], name, email, role, now()))
                flash("Team member added.", "success")
                return redirect(url_for("team_page"))
            except sqlite3.IntegrityError:
                flash("That email is already in your team.", "error")
    with get_db() as conn:
        members = conn.execute("SELECT m.*,COUNT(DISTINCT pm.project_id) project_count FROM team_members m LEFT JOIN project_members pm ON pm.member_id=m.id WHERE m.owner_id=? GROUP BY m.id ORDER BY m.name", (g.user["id"],)).fetchall()
    return page("team", "Team members", members=members)


@app.route("/team/<int:member_id>/delete", methods=["POST"])
@login_required
def delete_member(member_id):
    with get_db() as conn:
        conn.execute("DELETE FROM team_members WHERE id=? AND owner_id=?", (member_id, g.user["id"]))
        changed = conn.execute("SELECT changes()").fetchone()[0]
    if not changed:
        return "Team member not found", 404
    flash("Team member removed.", "success")
    return redirect(url_for("team_page"))


@app.route("/analytics")
@login_required
def analytics_page():
    with get_db() as conn:
        project_rows = conn.execute("SELECT status,COUNT(*) count FROM projects WHERE owner_id=? AND is_archived=0 GROUP BY status", (g.user["id"],)).fetchall()
        task_rows = conn.execute("SELECT status,COUNT(*) count FROM tasks WHERE owner_id=? AND is_archived=0 GROUP BY status", (g.user["id"],)).fetchall()
        workload = conn.execute("SELECT m.name,COUNT(t.id) count FROM team_members m LEFT JOIN tasks t ON t.assignee_id=m.id AND t.owner_id=m.owner_id AND t.is_archived=0 WHERE m.owner_id=? GROUP BY m.id ORDER BY count DESC,m.name LIMIT 8", (g.user["id"],)).fetchall()
    return page("analytics", "Analytics", project_rows=project_rows, task_rows=task_rows, workload=workload)


@app.route("/calendar")
@login_required
def calendar_page():
    month = request.args.get("month", date.today().strftime("%Y-%m"))
    if len(month) != 7 or month[4] != "-" or not month.replace("-", "").isdigit():
        month = date.today().strftime("%Y-%m")
    with get_db() as conn:
        projects = conn.execute("SELECT id,name,due_date,status,'Project' kind FROM projects WHERE owner_id=? AND is_archived=0 AND due_date LIKE ? AND status!='Completed'", (g.user["id"], f"{month}%")).fetchall()
        tasks = conn.execute("SELECT id,title name,due_date,status,'Task' kind FROM tasks WHERE owner_id=? AND is_archived=0 AND due_date LIKE ? AND status!='Done'", (g.user["id"], f"{month}%")).fetchall()
    items = sorted([dict(item) for item in [*projects, *tasks]], key=lambda item: (item["due_date"], item["kind"]))
    return page("calendar", "Calendar", items=items, month=month)


@app.route("/reports")
@login_required
def reports_page():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    if not valid_date(start) or not valid_date(end):
        start, end = "", ""
    with get_db() as conn:
        tasks = conn.execute("SELECT t.title,t.status,t.priority,t.due_date,t.created_at,p.name project_name,m.name assignee_name FROM tasks t LEFT JOIN projects p ON p.id=t.project_id LEFT JOIN team_members m ON m.id=t.assignee_id WHERE t.owner_id=? AND t.is_archived=0 AND (t.project_id IS NULL OR p.is_archived=0) AND (?='' OR t.created_at>=?) AND (?='' OR t.created_at<=?) ORDER BY t.created_at DESC",
                             (g.user["id"], start, start, end, end + "T23:59:59" if end else "")).fetchall()
    return page("reports", "Reports", tasks=tasks, start=start, end=end)


@app.route("/reports/export.csv")
@login_required
def export_report():
    with get_db() as conn:
        tasks = conn.execute("SELECT t.title,t.status,t.priority,t.due_date,t.created_at,p.name project_name,m.name assignee_name FROM tasks t LEFT JOIN projects p ON p.id=t.project_id LEFT JOIN team_members m ON m.id=t.assignee_id WHERE t.owner_id=? AND t.is_archived=0 AND (t.project_id IS NULL OR p.is_archived=0) ORDER BY t.created_at DESC", (g.user["id"],)).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Task", "Status", "Priority", "Due date", "Project", "Assignee", "Created"])
    for task in tasks:
        writer.writerow([task["title"], task["status"], task["priority"], task["due_date"], task["project_name"] or "", task["assignee_name"] or "", task["created_at"]])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=taskflow-report.csv"})


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages_page():
    if request.method == "POST":
        content = request.form.get("content", "").strip()[:2000]
        project_id = request.form.get("project_id", type=int) or None
        if not content:
            flash("Write a message before posting.", "error")
        elif project_id and not owned_project(project_id, g.user["id"]):
            flash("That project is not available in your workspace.", "error")
        else:
            with get_db() as conn:
                conn.execute("INSERT INTO messages(owner_id,project_id,author_id,content,created_at) VALUES(?,?,?,?,?)", (g.user["id"], project_id, g.user["id"], content, now()))
            flash("Message posted.", "success")
            return redirect(url_for("messages_page"))
    with get_db() as conn:
        messages = conn.execute("SELECT msg.*,u.name author_name,p.name project_name FROM messages msg LEFT JOIN users u ON u.id=msg.author_id LEFT JOIN projects p ON p.id=msg.project_id WHERE msg.owner_id=? ORDER BY msg.id DESC", (g.user["id"],)).fetchall()
        projects = conn.execute("SELECT id,name FROM projects WHERE owner_id=? AND is_archived=0 ORDER BY name", (g.user["id"],)).fetchall()
    return page("messages", "Messages", messages=messages, projects=projects)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        timezone = request.form.get("timezone", "UTC").strip()[:80]
        week_start = request.form.get("week_start", "Monday")
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        if not name or week_start not in {"Monday", "Sunday"}:
            flash("Enter a name and a valid week start day.", "error")
        else:
            with get_db() as conn:
                user = conn.execute("SELECT password_hash FROM users WHERE id=?", (g.user["id"],)).fetchone()
                if new_password and (not check_password_hash(user["password_hash"], current_password) or len(new_password) < 10):
                    flash("To change your password, enter your current password and use at least 10 characters.", "error")
                else:
                    conn.execute("UPDATE users SET name=? WHERE id=?", (name, g.user["id"]))
                    conn.execute("UPDATE user_settings SET timezone=?,week_start=? WHERE user_id=?", (timezone, week_start, g.user["id"]))
                    if new_password:
                        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_password), g.user["id"]))
                    flash("Settings saved.", "success")
                    return redirect(url_for("settings_page"))
        with get_db() as conn:
            g.user = conn.execute("SELECT id,name,email,role,status FROM users WHERE id=?", (g.user["id"],)).fetchone()
    with get_db() as conn:
        settings = conn.execute("SELECT * FROM user_settings WHERE user_id=?", (g.user["id"],)).fetchone()
    return page("settings", "Settings", settings=settings)


@app.route("/search")
@login_required
def search_page():
    q = request.args.get("q", "").strip()[:100]
    with get_db() as conn:
        projects = conn.execute("SELECT id,name,description FROM projects WHERE owner_id=? AND is_archived=0 AND (name LIKE ? OR description LIKE ?) LIMIT 8", (g.user["id"], f"%{q}%", f"%{q}%")).fetchall() if q else []
        tasks = conn.execute("SELECT id,title,description FROM tasks WHERE owner_id=? AND is_archived=0 AND (title LIKE ? OR description LIKE ?) LIMIT 8", (g.user["id"], f"%{q}%", f"%{q}%")).fetchall() if q else []
    return page("search", "Search", q=q, projects=projects, tasks=tasks)


def plan_tasks(goal):
    """Rule-based starter planner; deliberately works without a paid AI API."""
    cleaned = " ".join(goal.split()).strip(" .!?\n\t")
    if not cleaned:
        return []
    lower = cleaned.lower()
    if any(word in lower for word in ("website", "web app")):
        steps = ["Define the requirements and key pages", "Create the UI layout", "Build the backend routes", "Connect and test the database", "Test the complete workflow"]
    elif any(word in lower for word in ("learn", "study", "course", "exam")):
        steps = ["List the topics to cover", "Break topics into daily study sessions", "Study and take notes", "Practice with questions", "Review weak areas"]
    else:
        steps = [f"Define the expected outcome for: {cleaned}", "Break the work into smaller milestones", "Complete the first milestone", "Review progress and resolve blockers", "Check the final result against the goal"]
    return [{"title": step, "priority": "Medium"} for step in steps]


@app.route("/api/plan", methods=["POST"])
def api_plan():
    data = request.get_json(silent=True) or {}
    goal = str(data.get("goal", ""))[:500]
    steps = plan_tasks(goal)
    if not steps:
        return jsonify({"error": "Enter a goal to create a plan."}), 400
    return jsonify({"goal": goal, "steps": steps, "note": "Starter planner uses simple rules and does not call an external AI service."})


@app.route("/planner", methods=["POST"])
@login_required
def planner():
    goal = request.form.get("goal", "")[:500]
    steps = plan_tasks(goal)
    if not steps:
        flash("Enter a goal first.", "error")
        return redirect(url_for("index"))
    with get_db() as conn:
        for step in steps:
            conn.execute("INSERT INTO tasks(title,description,priority,status,created_at,owner_id,updated_at) VALUES(?,?,?,'To do',?,?,?)",
                         (step["title"], f"Generated from goal: {goal[:200]}", step["priority"], now(), g.user["id"], now()))
    flash(f"Added {len(steps)} starter tasks to your list.", "success")
    return redirect(url_for("tasks_page"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if g.user and g.user["role"] in {"Admin", "Super Admin"}:
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as conn:
            user = conn.execute("SELECT id,name,password_hash,role,status FROM users WHERE email=?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password) or user["role"] not in {"Admin", "Super Admin"}:
            flash("Admin email or password is incorrect.", "error")
        elif user["status"] != "Active":
            flash("This admin account is suspended.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            with get_db() as conn:
                conn.execute("INSERT INTO audit_logs(admin_id,admin_name,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?,?)",
                             (user["id"], user["name"], "admin signed in", "session", None, "Admin session created", now()))
            destination = request.args.get("next", "")
            return redirect(destination if destination.startswith("/admin") and not destination.startswith("//") else url_for("admin_dashboard"))
    return render_template("admin_login.html", title="Admin sign in")


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    record_admin_action("admin signed out", "session", None, "Admin session ended")
    session.clear()
    flash("Admin session ended.", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin")
@app.route("/admin/")
@admin_required
def admin_dashboard():
    today = date.today().isoformat()
    with get_db() as conn:
        stats = {
            "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "active_users": conn.execute("SELECT COUNT(*) FROM users WHERE status='Active'").fetchone()[0],
            "suspended_users": conn.execute("SELECT COUNT(*) FROM users WHERE status='Suspended'").fetchone()[0],
            "projects": conn.execute("SELECT COUNT(*) FROM projects WHERE is_archived=0").fetchone()[0],
            "active_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE is_archived=0 AND status IN ('Planning','In progress')").fetchone()[0],
            "completed_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE is_archived=0 AND status='Completed'").fetchone()[0],
            "overdue_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE is_archived=0 AND status!='Completed' AND due_date!='' AND due_date<?", (today,)).fetchone()[0],
            "tasks": conn.execute("SELECT COUNT(*) FROM tasks WHERE is_archived=0").fetchone()[0],
            "completed_tasks": conn.execute("SELECT COUNT(*) FROM tasks WHERE is_archived=0 AND status='Done'").fetchone()[0],
        }
        registrations = conn.execute("SELECT id,name,email,role,status,created_at FROM users ORDER BY id DESC LIMIT 8").fetchall()
        project_statuses = conn.execute("SELECT status,COUNT(*) count FROM projects WHERE is_archived=0 GROUP BY status ORDER BY count DESC").fetchall()
        task_statuses = conn.execute("SELECT status,COUNT(*) count FROM tasks WHERE is_archived=0 GROUP BY status ORDER BY count DESC").fetchall()
        platform_activity = conn.execute("""SELECT actor,action,target,created_at FROM (
            SELECT admin_name actor,action,target_type || ' #' || COALESCE(target_id,'') target,created_at FROM audit_logs
            UNION ALL
            SELECT COALESCE(u.name,'Deleted user') actor,a.action,a.entity target,a.created_at FROM activity a LEFT JOIN users u ON u.id=a.owner_id
        ) ORDER BY created_at DESC LIMIT 10""").fetchall()
    return admin_page("overview", "Overview", stats=stats, registrations=registrations, project_statuses=project_statuses, task_statuses=task_statuses, platform_activity=platform_activity)


@app.route("/admin/users")
@admin_required
def admin_users():
    search = request.args.get("q", "").strip()[:100]
    status = request.args.get("status", "All")
    role = request.args.get("role", "All")
    clauses, values = ["1=1"], []
    if search:
        clauses.append("(name LIKE ? OR email LIKE ?)")
        values.extend([f"%{search}%", f"%{search}%"])
    if status in {"Active", "Suspended"}:
        clauses.append("status=?")
        values.append(status)
    if role in ADMIN_ROLES:
        clauses.append("role=?")
        values.append(role)
    where = " AND ".join(clauses)
    requested_page = request.args.get("page", 1, type=int) or 1
    with get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM users WHERE {where}", values).fetchone()[0]
        paging = pagination(total, requested_page)
        users = conn.execute(f"SELECT id,name,email,role,status,created_at FROM users WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                             (*values, ADMIN_PAGE_SIZE, paging["offset"])).fetchall()
    return admin_page("users", "Users", users=users, paging=paging, q=search, status=status, role=role)


@app.route("/admin/users/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    with get_db() as conn:
        user = conn.execute("SELECT id,name,email,role,status,created_at FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            abort(404)
        user_stats = {
            "projects": conn.execute("SELECT COUNT(*) FROM projects WHERE owner_id=?", (user_id,)).fetchone()[0],
            "tasks": conn.execute("SELECT COUNT(*) FROM tasks WHERE owner_id=?", (user_id,)).fetchone()[0],
        }
        projects = conn.execute("SELECT id,name,status,priority,due_date,is_archived FROM projects WHERE owner_id=? ORDER BY id DESC LIMIT 8", (user_id,)).fetchall()
        tasks = conn.execute("SELECT id,title,status,priority,due_date,is_archived FROM tasks WHERE owner_id=? ORDER BY id DESC LIMIT 8", (user_id,)).fetchall()
    return admin_page("user_detail", "User profile", user=user, user_stats=user_stats, user_projects=projects, user_tasks=tasks)


@app.route("/admin/users/<int:user_id>/status", methods=["POST"])
@admin_required
def admin_user_status(user_id):
    new_status = request.form.get("status", "")
    if new_status not in {"Active", "Suspended"}:
        abort(400)
    with get_db() as conn:
        target = conn.execute("SELECT id,name,role,status FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if target["id"] == g.user["id"] and new_status != "Active":
            flash("You cannot suspend your own account.", "error")
            return redirect(url_for("admin_user_detail", user_id=user_id))
        if g.user["role"] != "Super Admin" and target["role"] != "User":
            abort(403)
        if target["role"] == "Super Admin" and new_status != "Active":
            active_super_admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='Super Admin' AND status='Active'").fetchone()[0]
            if active_super_admins <= 1:
                flash("The last active Super Admin cannot be suspended.", "error")
                return redirect(url_for("admin_user_detail", user_id=user_id))
        conn.execute("UPDATE users SET status=? WHERE id=?", (new_status, user_id))
    record_admin_action(f"set account status to {new_status}", "user", user_id, target["email"] if "email" in target.keys() else target["name"])
    flash(f"{target['name']}'s account is now {new_status.lower()}.", "success")
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@super_admin_required
def admin_user_role(user_id):
    role = request.form.get("role", "")
    if role not in ADMIN_ROLES:
        abort(400)
    with get_db() as conn:
        target = conn.execute("SELECT id,name,role,status FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if target["id"] == g.user["id"] and role != "Super Admin":
            flash("You cannot remove your own Super Admin role.", "error")
            return redirect(url_for("admin_user_detail", user_id=user_id))
        if target["role"] == "Super Admin" and role != "Super Admin":
            super_admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='Super Admin'").fetchone()[0]
            if super_admin_count <= 1:
                flash("The last Super Admin role cannot be removed.", "error")
                return redirect(url_for("admin_user_detail", user_id=user_id))
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    record_admin_action(f"changed role to {role}", "user", user_id, target["name"])
    flash(f"{target['name']}'s role is now {role}.", "success")
    return redirect(url_for("admin_user_detail", user_id=user_id))


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@admin_required
def admin_user_reset(user_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = (datetime.now() + timedelta(minutes=30)).isoformat(timespec="seconds")
    with get_db() as conn:
        target = conn.execute("SELECT id,name,role FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            abort(404)
        if g.user["role"] != "Super Admin" and target["role"] != "User":
            abort(403)
        conn.execute("UPDATE users SET reset_token_hash=?,reset_expires_at=? WHERE id=?", (token_hash, expires, user_id))
    record_admin_action("issued password reset link", "user", user_id, target["name"])
    return render_template("admin_reset_ready.html", reset_url=url_for("admin_password_reset", token=token, _external=False), user_name=target["name"])


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def admin_password_reset(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with get_db() as conn:
        user = conn.execute("SELECT id FROM users WHERE reset_token_hash=? AND reset_expires_at>?", (token_hash, now())).fetchone()
    if not user:
        return render_template("admin_reset.html", invalid=True), 400
    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        else:
            with get_db() as conn:
                conn.execute("UPDATE users SET password_hash=?,reset_token_hash=NULL,reset_expires_at=NULL WHERE id=? AND reset_token_hash=?",
                             (generate_password_hash(password), user["id"], token_hash))
            session.clear()
            flash("Password updated. Sign in with your new password.", "success")
            return redirect(url_for("login"))
    return render_template("admin_reset.html", invalid=False, token=token)


def admin_record_filter(request_args, alias=""):
    prefix = f"{alias}." if alias else ""
    clauses, values = ["1=1"], []
    owner = request_args.get("owner", type=int)
    status = request_args.get("status", "All")
    priority = request_args.get("priority", "All")
    due = request_args.get("due", "All")
    search = request_args.get("q", "").strip()[:100]
    archived = request_args.get("archived", "Active")
    if owner:
        clauses.append(f"{prefix}owner_id=?")
        values.append(owner)
    if status not in {"All", ""}:
        clauses.append(f"{prefix}status=?")
        values.append(status)
    if priority in PRIORITIES:
        clauses.append(f"{prefix}priority=?")
        values.append(priority)
    if due == "Overdue":
        clauses.append(f"{prefix}due_date!='' AND {prefix}due_date<? AND {prefix}status NOT IN ('Done','Completed')")
        values.append(date.today().isoformat())
    if archived == "Archived":
        clauses.append(f"{prefix}is_archived=1")
    elif archived != "All":
        clauses.append(f"{prefix}is_archived=0")
    if search:
        field = "name" if alias == "p" else ("title" if alias == "t" else "")
        if field:
            clauses.append(f"{prefix}{field} LIKE ?")
            values.append(f"%{search}%")
    return " AND ".join(clauses), values


@app.route("/admin/projects")
@admin_required
def admin_projects():
    where, values = admin_record_filter(request.args, "p")
    requested_page = request.args.get("page", 1, type=int) or 1
    filters = request.args.copy()
    filters.pop("page", None)
    with get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM projects p WHERE {where}", values).fetchone()[0]
        paging = pagination(total, requested_page)
        projects = conn.execute(f"SELECT p.*,u.name owner_name,u.email owner_email FROM projects p JOIN users u ON u.id=p.owner_id WHERE {where} ORDER BY p.due_date,p.id DESC LIMIT ? OFFSET ?",
                                (*values, ADMIN_PAGE_SIZE, paging["offset"])).fetchall()
        owners = conn.execute("SELECT id,name FROM users ORDER BY name").fetchall()
    return admin_page("projects", "All projects", projects=projects, owners=owners, paging=paging, filters=filters)


@app.route("/admin/tasks")
@admin_required
def admin_tasks():
    where, values = admin_record_filter(request.args, "t")
    requested_page = request.args.get("page", 1, type=int) or 1
    filters = request.args.copy()
    filters.pop("page", None)
    with get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM tasks t WHERE {where}", values).fetchone()[0]
        paging = pagination(total, requested_page)
        tasks = conn.execute(f"SELECT t.*,u.name owner_name,u.email owner_email,p.name project_name FROM tasks t LEFT JOIN users u ON u.id=t.owner_id LEFT JOIN projects p ON p.id=t.project_id WHERE {where} ORDER BY t.due_date,t.id DESC LIMIT ? OFFSET ?",
                             (*values, ADMIN_PAGE_SIZE, paging["offset"])).fetchall()
        owners = conn.execute("SELECT id,name FROM users ORDER BY name").fetchall()
    return admin_page("tasks", "All tasks", tasks=tasks, owners=owners, paging=paging, filters=filters)


@app.route("/admin/projects/<int:project_id>/archive", methods=["POST"])
@admin_required
def admin_archive_project(project_id):
    archived = request.form.get("archived", "1") == "1"
    with get_db() as conn:
        project = conn.execute("SELECT name FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            abort(404)
        conn.execute("UPDATE projects SET is_archived=? WHERE id=?", (int(archived), project_id))
    record_admin_action("archived project" if archived else "restored project", "project", project_id, project["name"])
    flash(f"Project {('archived' if archived else 'restored')}.", "success")
    return redirect(request.form.get("next") if request.form.get("next", "").startswith("/admin") else url_for("admin_projects"))


@app.route("/admin/tasks/<int:task_id>/archive", methods=["POST"])
@admin_required
def admin_archive_task(task_id):
    archived = request.form.get("archived", "1") == "1"
    with get_db() as conn:
        task = conn.execute("SELECT title,project_id FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task:
            abort(404)
        conn.execute("UPDATE tasks SET is_archived=? WHERE id=?", (int(archived), task_id))
        refresh_project_progress(conn, task["project_id"])
    record_admin_action("archived task" if archived else "restored task", "task", task_id, task["title"])
    flash(f"Task {('archived' if archived else 'restored')}.", "success")
    return redirect(request.form.get("next") if request.form.get("next", "").startswith("/admin") else url_for("admin_tasks"))


@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    with get_db() as conn:
        roles = conn.execute("SELECT role,COUNT(*) count FROM users GROUP BY role ORDER BY count DESC").fetchall()
        registrations = conn.execute("SELECT substr(created_at,1,7) month,COUNT(*) count FROM users GROUP BY month ORDER BY month DESC LIMIT 12").fetchall()
        projects = conn.execute("SELECT status,COUNT(*) count FROM projects GROUP BY status ORDER BY count DESC").fetchall()
        tasks = conn.execute("SELECT status,COUNT(*) count FROM tasks GROUP BY status ORDER BY count DESC").fetchall()
        usage = {"messages": conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0], "team_members": conn.execute("SELECT COUNT(*) FROM team_members").fetchone()[0], "archived_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE is_archived=1").fetchone()[0], "archived_tasks": conn.execute("SELECT COUNT(*) FROM tasks WHERE is_archived=1").fetchone()[0]}
    return admin_page("analytics", "Platform analytics", roles=roles, registrations=registrations, project_statuses=projects, task_statuses=tasks, usage=usage)


@app.route("/admin/audit")
@admin_required
def admin_audit():
    search = request.args.get("q", "").strip()[:100]
    where, values = "1=1", []
    if search:
        where = "(admin_name LIKE ? OR action LIKE ? OR target_type LIKE ? OR details LIKE ?)"
        values = [f"%{search}%"] * 4
    requested_page = request.args.get("page", 1, type=int) or 1
    with get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM audit_logs WHERE {where}", values).fetchone()[0]
        paging = pagination(total, requested_page)
        logs = conn.execute(f"SELECT * FROM audit_logs WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?", (*values, ADMIN_PAGE_SIZE, paging["offset"])).fetchall()
    return admin_page("audit", "Audit logs", logs=logs, paging=paging, q=search)


@app.route("/admin/settings", methods=["GET", "POST"])
@super_admin_required
def admin_settings():
    if request.method == "POST":
        registration_enabled = request.form.get("registration_enabled") == "true"
        with get_db() as conn:
            conn.execute("INSERT INTO app_settings(key,value,updated_at) VALUES('registration_enabled',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                         ("true" if registration_enabled else "false", now()))
        record_admin_action("updated platform settings", "settings", None, f"registration_enabled={registration_enabled}")
        flash("Platform settings saved.", "success")
        return redirect(url_for("admin_settings"))
    with get_db() as conn:
        settings = {row["key"]: row["value"] for row in conn.execute("SELECT key,value FROM app_settings")}
        super_admins = conn.execute("SELECT id,name,email,status,created_at FROM users WHERE role='Super Admin' ORDER BY id").fetchall()
    return admin_page("settings", "Platform settings", settings=settings, super_admins=super_admins)


@app.errorhandler(403)
def access_denied(_error):
    if request.path.startswith("/admin"):
        return render_template("admin_denied.html"), 403
    return "Access denied", 403


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
