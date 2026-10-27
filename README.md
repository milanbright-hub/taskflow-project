# TaskFlow

TaskFlow is a responsive Flask project-management workspace for organizing projects, tasks, people, deadlines, reports, and team updates. It uses SQLite and server-side Flask sessions; no hosted service or paid API is required.

## Features

- Account registration, login, logout, password hashing, and private per-account workspaces
- Dashboard KPIs, project progress, upcoming deadlines, activity, and priority tasks
- Project creation, editing, assignment, filtering, sorting, details, and deletion
- Task create/edit/delete, priority and due dates, project/member assignment, list and Kanban views
- Team directory, analytics and workload summaries, deadline calendar, message board, profile settings, and CSV reports
- Separate `/admin` platform console with role-based access control, account moderation, global project/task inventory, analytics, audit logs, and registration settings
- Existing single-user `tasks` databases are upgraded in place; their unowned tasks are assigned to the first account registered
- New accounts receive a small Product launch sample project, tasks, and teammate. Existing account data is never reseeded or overwritten
- The original rule-based goal planner and `POST /api/plan` endpoint remain available

## Requirements

- Python 3.10 or newer
- Dependencies in `requirements.txt`

## Run locally

From the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Start the application:

```bash
python app.py
```

Open http://127.0.0.1:5000 and choose **Create an account**. The first registration is safe and self-service; there is no shared or hardcoded demo password. New workspaces receive sample records to make the dashboard immediately usable.

## Admin access

The admin console is at http://127.0.0.1:5000/admin/login. Public registration always creates a `User`; it never accepts a requested role. Bootstrap the first Super Admin from a trusted terminal in the project directory after installing dependencies:

```powershell
python -m flask --app app create-super-admin
```

The command interactively asks for the account name, email, and a confirmed password (minimum 12 characters). The password is not included in command-line arguments and is stored as a Werkzeug password hash. For an existing account, the command securely replaces its password and promotes it to Super Admin. Keep terminal/database access restricted and use a unique password from your secret manager. Do not run this bootstrap command in an untrusted environment.

`Super Admin` can assign any role and manage platform settings. `Admin` can manage users, moderate accounts, review platform records, and issue password-reset links for regular users, but cannot grant elevated roles or modify another admin. `User` has only their own workspace. Admin mutations require a session CSRF token and are written to the audit log. Admin-issued reset links are single-use, expire after 30 minutes, and are stored only as a hash; the plaintext link is shown once for secure handoff. The final active Super Admin cannot be suspended or demoted, and an admin cannot suspend their own account.

The default database is `tasks.db` beside `app.py`. Set `TASKFLOW_DB_PATH` to use another SQLite file. The database and tables are initialized automatically.

## Configuration and deployment

For deployment, set a persistent, randomly generated secret key and serve the app over HTTPS:

```powershell
$env:FLASK_SECRET_KEY = "use-a-long-random-secret-from-your-secret-manager"
$env:SESSION_COOKIE_SECURE = "1"
```

`SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SAMESITE=Lax` are enabled. `SESSION_COOKIE_SECURE=1` enables the Secure cookie flag for HTTPS. The development server is not intended for production; deploy behind a production WSGI server and HTTPS reverse proxy. The public JSON planner endpoint does not expose workspace records and remains unauthenticated for the original API demo.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests cover registration and password hashing, login/logout, user/admin route protection, role and suspension controls, CSRF, password resets, admin bootstrap, audit logging, private data isolation, project/task CRUD and archiving, legacy schema migration, admin/workspace page rendering, CSV export, and planner API validation.

## Planner API

```bash
curl -X POST http://127.0.0.1:5000/api/plan \
  -H "Content-Type: application/json" \
  -d '{"goal":"Build a portfolio website"}'
```

The response contains a locally generated checklist. The planner is rule-based and does not send user content to an AI service.

## Project layout

```text
app.py                 Flask routes, SQLite schema, authentication and queries
templates/             Authentication, workspace, project and Kanban views
static/                Responsive styles and small browser interactions
tests/test_app.py      Isolated SQLite integration tests
```
