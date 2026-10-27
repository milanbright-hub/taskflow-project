import tempfile
import unittest
from pathlib import Path

fd, test_db = tempfile.mkstemp(suffix=".db")

import app as taskflow


class TaskFlowTests(unittest.TestCase):
    def setUp(self):
        taskflow.DB_PATH = Path(test_db)
        with taskflow.get_db() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            for table in ("project_members", "messages", "activity", "user_settings", "tasks", "projects", "team_members", "users"):
                conn.execute(f"DROP TABLE IF EXISTS {table}")
        taskflow.init_db()
        with taskflow.get_db() as conn:
            conn.execute("UPDATE app_settings SET value='true' WHERE key='registration_enabled'")
        self.client = taskflow.app.test_client()
        self.register(self.client)

    def tearDown(self):
        with taskflow.get_db() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            for table in ("project_members", "messages", "activity", "user_settings", "tasks", "projects", "team_members", "users"):
                conn.execute(f"DROP TABLE IF EXISTS {table}")

    @staticmethod
    def register(client, name="Taylor Reed", email="taylor@example.com", password="correct-horse-battery"):
        return client.post("/register", data={"name": name, "email": email, "password": password}, follow_redirects=True)

    @staticmethod
    def promote(email="taylor@example.com", role="Super Admin"):
        with taskflow.get_db() as conn:
            conn.execute("UPDATE users SET role=? WHERE email=?", (role, email))

    def admin_client(self, role="Super Admin"):
        self.promote(role=role)
        client = taskflow.app.test_client()
        client.post("/admin/login", data={"email": "taylor@example.com", "password": "correct-horse-battery"})
        client.get("/admin")
        return client

    @staticmethod
    def admin_token(client):
        with client.session_transaction() as browser_session:
            return browser_session["admin_csrf_token"]

    def test_home_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"TaskFlow", response.data)

    def test_dashboard_requires_login(self):
        client = taskflow.app.test_client()
        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_admin_requires_authentication_and_role(self):
        anonymous = taskflow.app.test_client()
        response = anonymous.get("/admin", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/login", response.location)
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        self.assertEqual(self.client.get("/admin/settings").status_code, 403)

    def test_registration_cannot_assign_admin_role(self):
        client = taskflow.app.test_client()
        self.register(client, name="Untrusted Role", email="role@example.com", password="another-secure-password")
        with taskflow.get_db() as conn:
            user = conn.execute("SELECT role FROM users WHERE email='role@example.com'").fetchone()
        self.assertEqual(user["role"], "User")

    def test_admin_pages_show_live_platform_data(self):
        client = self.admin_client()
        for path in ("/admin", "/admin/users", "/admin/users/1", "/admin/projects", "/admin/tasks", "/admin/analytics", "/admin/audit", "/admin/settings"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 200)
        response = client.get("/admin")
        self.assertIn(b"Registered users", response.data)
        self.assertIn(b"Recent registrations", response.data)

    def test_admin_project_and_task_pagination(self):
        with taskflow.get_db() as conn:
            for index in range(25):
                conn.execute("INSERT INTO projects(owner_id,name,created_at) VALUES(1,?,?)", (f"Page project {index}", taskflow.now()))
                conn.execute("INSERT INTO tasks(owner_id,title,created_at) VALUES(1,?,?)", (f"Page task {index}", taskflow.now()))
        admin = self.admin_client()
        self.assertEqual(admin.get("/admin/projects?page=2").status_code, 200)
        self.assertEqual(admin.get("/admin/tasks?page=2").status_code, 200)

    def test_admin_can_change_roles_and_suspend_user_safely(self):
        target = taskflow.app.test_client()
        self.register(target, name="Morgan User", email="morgan@example.com", password="secure-morgan-password")
        with taskflow.get_db() as conn:
            target_id = conn.execute("SELECT id FROM users WHERE email='morgan@example.com'").fetchone()[0]
        admin = self.admin_client()
        token = self.admin_token(admin)
        self.assertEqual(admin.post(f"/admin/users/{target_id}/role", data={"role": "Admin", "admin_csrf_token": token}).status_code, 302)
        with taskflow.get_db() as conn:
            self.assertEqual(conn.execute("SELECT role FROM users WHERE id=?", (target_id,)).fetchone()[0], "Admin")
        self.assertEqual(admin.post(f"/admin/users/{target_id}/status", data={"status": "Suspended", "admin_csrf_token": token}).status_code, 302)
        with taskflow.get_db() as conn:
            self.assertEqual(conn.execute("SELECT status FROM users WHERE id=?", (target_id,)).fetchone()[0], "Suspended")
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0], 0)
        self.assertEqual(target.get("/dashboard").status_code, 302)
        login = taskflow.app.test_client()
        response = login.post("/login", data={"email": "morgan@example.com", "password": "secure-morgan-password"}, follow_redirects=True)
        self.assertIn(b"account is suspended", response.data)

    def test_admin_cannot_change_roles_or_suspend_an_admin(self):
        self.promote(role="Admin")
        target = taskflow.app.test_client()
        self.register(target, name="Second Admin", email="second-admin@example.com", password="second-admin-password")
        with taskflow.get_db() as conn:
            conn.execute("UPDATE users SET role='Admin' WHERE email='second-admin@example.com'")
            target_id = conn.execute("SELECT id FROM users WHERE email='second-admin@example.com'").fetchone()[0]
        admin = taskflow.app.test_client()
        admin.post("/admin/login", data={"email": "taylor@example.com", "password": "correct-horse-battery"})
        admin.get("/admin")
        token = self.admin_token(admin)
        self.assertEqual(admin.post(f"/admin/users/{target_id}/role", data={"role": "User", "admin_csrf_token": token}).status_code, 403)
        self.assertEqual(admin.post(f"/admin/users/{target_id}/status", data={"status": "Suspended", "admin_csrf_token": token}).status_code, 403)

    def test_super_admin_cannot_remove_their_own_access(self):
        admin = self.admin_client()
        response = admin.post("/admin/users/1/role", data={"role": "User", "admin_csrf_token": self.admin_token(admin)}, follow_redirects=True)
        self.assertIn(b"cannot remove your own Super Admin role", response.data)
        with taskflow.get_db() as conn:
            self.assertEqual(conn.execute("SELECT role FROM users WHERE id=1").fetchone()[0], "Super Admin")

    def test_password_reset_link_is_one_time_and_expires(self):
        target = taskflow.app.test_client()
        self.register(target, name="Reset User", email="reset@example.com", password="reset-user-password")
        with taskflow.get_db() as conn:
            target_id = conn.execute("SELECT id FROM users WHERE email='reset@example.com'").fetchone()[0]
        admin = self.admin_client()
        response = admin.post(f"/admin/users/{target_id}/reset", data={"admin_csrf_token": self.admin_token(admin)})
        self.assertIn(b"Reset link created", response.data)
        import re
        token = re.search(rb"/reset-password/([A-Za-z0-9_-]+)", response.data).group(1).decode()
        reset = taskflow.app.test_client()
        self.assertEqual(reset.post(f"/reset-password/{token}", data={"password": "new-secure-password"}).status_code, 302)
        self.assertEqual(reset.get(f"/reset-password/{token}").status_code, 400)
        login = taskflow.app.test_client()
        self.assertEqual(login.post("/login", data={"email": "reset@example.com", "password": "new-secure-password"}).status_code, 302)

    def test_admin_posts_require_csrf_and_logout_is_audited(self):
        admin = self.admin_client()
        self.assertEqual(admin.post("/admin/settings", data={"registration_enabled": "true"}).status_code, 400)
        token = self.admin_token(admin)
        response = admin.post("/admin/settings", data={"registration_enabled": "false", "admin_csrf_token": token})
        self.assertEqual(response.status_code, 302)
        admin.post("/admin/logout", data={"admin_csrf_token": self.admin_token(admin)})
        with taskflow.get_db() as conn:
            actions = [row[0] for row in conn.execute("SELECT action FROM audit_logs ORDER BY id")]
            registration = conn.execute("SELECT value FROM app_settings WHERE key='registration_enabled'").fetchone()[0]
        self.assertIn("admin signed in", actions)
        self.assertIn("admin signed out", actions)
        self.assertEqual(registration, "false")

    def test_admin_archive_hides_records_from_workspace_and_can_restore(self):
        with taskflow.get_db() as conn:
            project_id = conn.execute("SELECT id FROM projects WHERE owner_id=1 LIMIT 1").fetchone()[0]
            task_id = conn.execute("SELECT id FROM tasks WHERE owner_id=1 LIMIT 1").fetchone()[0]
        admin = self.admin_client()
        token = self.admin_token(admin)
        self.assertEqual(admin.post(f"/admin/projects/{project_id}/archive", data={"archived": "1", "admin_csrf_token": token}).status_code, 302)
        self.assertEqual(admin.post(f"/admin/tasks/{task_id}/archive", data={"archived": "1", "admin_csrf_token": token}).status_code, 302)
        self.assertEqual(self.client.get(f"/projects/{project_id}").status_code, 404)
        self.assertEqual(self.client.get(f"/tasks/{task_id}/edit").status_code, 404)
        self.assertNotIn(b"Product launch", self.client.get("/projects").data)
        token = self.admin_token(admin)
        self.assertEqual(admin.post(f"/admin/projects/{project_id}/archive", data={"archived": "0", "admin_csrf_token": token}).status_code, 302)
        self.assertEqual(self.client.get(f"/projects/{project_id}").status_code, 200)

    def test_cli_bootstrap_creates_super_admin_with_hashed_password(self):
        runner = taskflow.app.test_cli_runner()
        result = runner.invoke(args=["create-super-admin", "--email", "root@example.com", "--name", "Root Admin"], input="unique-super-secret-pass\nunique-super-secret-pass\n")
        self.assertEqual(result.exit_code, 0, result.output)
        with taskflow.get_db() as conn:
            user = conn.execute("SELECT role,password_hash FROM users WHERE email='root@example.com'").fetchone()
        self.assertEqual(user["role"], "Super Admin")
        self.assertNotEqual(user["password_hash"], "unique-super-secret-pass")

    def test_registration_hashes_password(self):
        with taskflow.get_db() as conn:
            user = conn.execute("SELECT password_hash FROM users WHERE email=?", ("taylor@example.com",)).fetchone()
        self.assertNotEqual(user["password_hash"], "correct-horse-battery")
        self.assertTrue(taskflow.check_password_hash(user["password_hash"], "correct-horse-battery"))

    def test_login_and_logout(self):
        client = taskflow.app.test_client()
        response = client.post("/login", data={"email": "taylor@example.com", "password": "correct-horse-battery"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Dashboard", response.data)
        client.post("/logout", follow_redirects=True)
        self.assertEqual(client.get("/").status_code, 302)

    def test_create_task(self):
        response = self.client.post("/tasks", data={"title": "Test internship project", "priority": "High"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test internship project", response.data)

    def test_blank_task_rejected(self):
        response = self.client.post("/tasks", data={"title": "   "}, follow_redirects=True)
        self.assertIn(b"Please enter a task title", response.data)

    def test_task_update_edit_and_delete(self):
        self.client.post("/tasks", data={"title": "Lifecycle task"})
        with taskflow.get_db() as conn:
            task_id = conn.execute("SELECT id FROM tasks WHERE title='Lifecycle task'").fetchone()[0]
        response = self.client.post(f"/tasks/{task_id}/update", data={"status": "In progress"})
        self.assertEqual(response.status_code, 302)
        response = self.client.post(f"/tasks/{task_id}/edit", data={"title": "Renamed task", "description": "Updated", "status": "Done", "priority": "High"})
        self.assertEqual(response.status_code, 302)
        with taskflow.get_db() as conn:
            task = conn.execute("SELECT title,status FROM tasks WHERE id=?", (task_id,)).fetchone()
        self.assertEqual((task["title"], task["status"]), ("Renamed task", "Done"))
        self.assertEqual(self.client.post(f"/tasks/{task_id}/delete").status_code, 302)
        self.assertEqual(self.client.get(f"/tasks/{task_id}/edit").status_code, 404)

    def test_project_create_edit_detail_and_delete(self):
        response = self.client.post("/projects", data={"name": "Launch plan", "status": "Planning", "priority": "High"})
        self.assertEqual(response.status_code, 302)
        with taskflow.get_db() as conn:
            project_id = conn.execute("SELECT id FROM projects WHERE name='Launch plan'").fetchone()[0]
        self.assertEqual(self.client.get(f"/projects/{project_id}").status_code, 200)
        response = self.client.post(f"/projects/{project_id}/edit", data={"name": "Launch 2", "status": "In progress", "priority": "Medium"})
        self.assertEqual(response.status_code, 302)
        with taskflow.get_db() as conn:
            self.assertIsNotNone(conn.execute("SELECT id FROM projects WHERE name='Launch 2'").fetchone())
        self.assertEqual(self.client.post(f"/projects/{project_id}/delete").status_code, 302)
        self.assertEqual(self.client.get(f"/projects/{project_id}").status_code, 404)

    def test_private_data_is_not_visible_to_another_user(self):
        self.client.post("/tasks", data={"title": "Private work"})
        second = taskflow.app.test_client()
        self.register(second, name="Casey Park", email="casey@example.com", password="another-secure-password")
        self.assertNotIn(b"Private work", second.get("/tasks").data)
        self.assertEqual(second.get("/tasks/1/edit").status_code, 404)

    def test_workspace_pages_and_kanban_render(self):
        for path in ("/", "/projects", "/projects/1", "/projects/1/edit", "/tasks", "/tasks/1/edit", "/tasks?view=kanban", "/analytics", "/calendar", "/team", "/reports", "/messages", "/settings", "/search?q=launch"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                if path.endswith("/edit"):
                    self.assertEqual(response.data.count(b'class="surface form-surface narrow-form"'), 1)

    def test_csv_report_is_scoped_and_downloadable(self):
        self.client.post("/tasks", data={"title": "CSV row"})
        response = self.client.get("/reports/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"text/csv", response.content_type.encode())
        self.assertIn(b"CSV row", response.data)

    def test_legacy_tasks_migrate_to_first_registered_user(self):
        with taskflow.get_db() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            for table in ("project_members", "messages", "activity", "user_settings", "tasks", "projects", "team_members", "users"):
                conn.execute(f"DROP TABLE IF EXISTS {table}")
            conn.execute("CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT DEFAULT '', priority TEXT NOT NULL DEFAULT 'Medium', status TEXT NOT NULL DEFAULT 'To do', due_date TEXT DEFAULT '', created_at TEXT NOT NULL)")
            conn.execute("INSERT INTO tasks(title,created_at) VALUES('Existing legacy task','2025-01-01T10:00:00')")
        taskflow.init_db()
        client = taskflow.app.test_client()
        self.register(client)
        response = client.get("/tasks")
        self.assertIn(b"Existing legacy task", response.data)

    def test_schema_migration_preserves_existing_user_and_project(self):
        with taskflow.get_db() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            for table in ("project_members", "messages", "activity", "audit_logs", "app_settings", "user_settings", "tasks", "projects", "team_members", "users"):
                conn.execute(f"DROP TABLE IF EXISTS {table}")
            conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
            conn.execute("CREATE TABLE projects (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, name TEXT NOT NULL, description TEXT DEFAULT '', start_date TEXT DEFAULT '', due_date TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Planning', priority TEXT NOT NULL DEFAULT 'Medium', progress INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)")
            conn.execute("INSERT INTO users VALUES(41,'Legacy User','legacy@example.com','hashed','2024-01-02T03:04:05')")
            conn.execute("INSERT INTO projects VALUES(51,41,'Preserved project','Existing work','','','Planning','High',20,'2024-02-03T04:05:06')")
        taskflow.init_db()
        with taskflow.get_db() as conn:
            user = conn.execute("SELECT id,role,status FROM users WHERE id=41").fetchone()
            project = conn.execute("SELECT id,name,is_archived FROM projects WHERE id=51").fetchone()
        self.assertEqual((user["id"], user["role"], user["status"]), (41, "User", "Active"))
        self.assertEqual((project["id"], project["name"], project["is_archived"]), (51, "Preserved project", 0))

    def test_planner_api_returns_steps(self):
        response = self.client.post("/api/plan", json={"goal": "Build a website"})
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.get_json()["steps"]), 3)

    def test_planner_api_rejects_blank_goal(self):
        response = self.client.post("/api/plan", json={"goal": "  "})
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
