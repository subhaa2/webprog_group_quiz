# Bug Tracking System

A web-based bug tracking system built with Rust (Actix-web) and SQLite, featuring role-based access control for administrators, developers, and QA testers.

## Features

- **Role-based Authentication**: Admin, Developer, and QA roles with different permissions
- **Project Management**: Create and manage projects (Admin only)
- **Bug Tracking**: Create, assign, update, and delete bug reports
- **Assignment System**: Role-based bug assignment rules
- **Session Management**: Secure session-based authentication
- **Web Interface**: HTML templates for bug assignment

## Role Permissions

### Admin
- Can create projects
- Can assign bugs to any developer
- Can create, update, and delete bugs
- Can view all bugs and assignments

### Developer
- Can create bugs
- Can only assign bugs to themselves
- Can update bugs
- Can view assigned bugs

### QA
- Can create bugs
- Can assign bugs to developers (not to themselves or other QAs)
- Can update bugs
- Can view all bugs

## Setup Instructions

### Prerequisites
- Rust (latest stable version)
- SQLite

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd webprog_group_quiz
   ```

2. **Install dependencies**
   ```bash
   cargo build
   ```

3. **Initialize the database**
   ```bash
   sqlite3 bugtrack.db < schema.sql
   ```

4. **Run the server**
   ```bash
   cargo run
   ```

The server will start at `http://localhost:8080`

## API Endpoints

### Authentication
- `POST /register` - Register a new user
- `POST /login` - Login user
- `GET /logout` - Logout user
- `GET /whoami` - Get current user info

### Projects
- `GET /api/projects` - List all projects
- `POST /api/projects` - Create a new project (Admin only)

### Bugs
- `GET /api/bugs` - List all bugs
- `POST /api/bugs` - Create a new bug
- `GET /api/bugs/{id}` - Get specific bug
- `PATCH /api/bugs/{id}` - Update a bug
- `DELETE /api/bugs/{id}` - Delete a bug

### Bug Assignment
- `GET /api/bugs/assign` - Show bug assignment form
- `POST /api/bugs/assign` - Assign a bug to a developer

## Testing with cURL

### 1. Register Users

**Register Admin (first user becomes admin automatically):**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin1", "password": "adminpass"}' \
  -c admin_cookie.txt
```

**Register Developer:**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "dev1", "password": "devpass", "role": "developer"}' \
  -c dev_cookie.txt
```

**Register QA:**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "qa1", "password": "qapass", "role": "qa"}' \
  -c qa_cookie.txt
```

### 2. Login Users

**Login as Admin:**
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin1", "password": "adminpass"}' \
  -c admin_cookie.txt
```

**Login as Developer:**
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "dev1", "password": "devpass"}' \
  -c dev_cookie.txt
```

**Login as QA:**
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "qa1", "password": "qapass"}' \
  -c qa_cookie.txt
```

**Alternative Windows CMD syntax:**
```cmd
curl -X POST http://localhost:8080/login ^
  -c cookies.txt ^
  -H "Content-Type: application/json" ^
  -d "{\"username\": \"admin1\", \"password\": \"adminpass\"}"
```

### 3. Create Projects (Admin Only)

```bash
curl -X POST http://localhost:8080/api/projects \
  -H "Content-Type: application/json" \
  -b admin_cookie.txt \
  -d '{"name": "Project Alpha", "description": "A new web application"}'
```

**Alternative Windows CMD syntax:**
```cmd
curl -b cookies.txt -X POST http://localhost:8080/api/projects -H "Content-Type: application/json" -d "{\"name\": \"HackProject\", \"description\": \"Break stuff\"}"
```

### 4. Create Bugs (All Roles)

**Create a bug as QA:**
```bash
curl -X POST http://localhost:8080/api/bugs \
  -H "Content-Type: application/json" \
  -b qa_cookie.txt \
  -d '{"project_id": 1, "bug_title": "Login button not working", "bug_description": "Users cannot click the login button", "bug_severity": "high"}'
```

**Create a bug as Developer:**
```bash
curl -X POST http://localhost:8080/api/bugs \
  -H "Content-Type: application/json" \
  -b dev_cookie.txt \
  -d '{"project_id": 1, "bug_title": "Database connection error", "bug_description": "Connection timeout after 30 seconds", "bug_severity": "medium"}'
```

**Alternative Windows CMD syntax:**
```cmd
curl -X POST http://localhost:8080/api/bugs ^
 -H "Content-Type: application/json" ^
 -d "{\"project_id\": 1, \"bug_title\": \"Died\", \"bug_description\": \"App crashes on startup\", \"bug_severity\": \"High\"}"
```

### 5. Assign Bugs

**Assign bug as QA to Developer:**
```bash
curl -X POST http://localhost:8080/api/bugs/assign \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b qa_cookie.txt \
  -d "bug_id=1&assignee_id=2"
```

**Assign bug as Admin to Developer:**
```bash
curl -X POST http://localhost:8080/api/bugs/assign \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b admin_cookie.txt \
  -d "bug_id=2&assignee_id=2"
```

### 6. View Bugs

**List all bugs:**
```bash
curl -X GET http://localhost:8080/api/bugs \
  -b admin_cookie.txt
```

**Get specific bug:**
```bash
curl -X GET http://localhost:8080/api/bugs/1 \
  -b admin_cookie.txt
```

### 7. Update Bugs

```bash
curl -X PATCH http://localhost:8080/api/bugs/1 \
  -H "Content-Type: application/json" \
  -b dev_cookie.txt \
  -d '{"bug_description": "Updated description", "bug_severity": "low"}'
```

### 8. Delete Bugs

```bash
curl -X DELETE http://localhost:8080/api/bugs/1 \
  -b admin_cookie.txt
```

### 9. Session Management

**Test access without logging in:**
```bash
curl http://localhost:8080/whoami
```

**Test access while logged in:**
```bash
curl http://localhost:8080/whoami -b cookies.txt
```

**Logout:**
```bash
curl http://localhost:8080/logout -b cookies.txt -c cookies.txt
```

## Web Interface

### Bug Assignment Form
Visit `http://localhost:8080/api/bugs/assign` in your browser to see:
- A form to assign bugs to developers
- A table showing current bug assignments
- Role-based assignee options

## Database Schema

The system uses SQLite with the following main tables:
- `users`: User accounts with roles
- `projects`: Project information
- `bugreport`: Bug reports with creator, assignee, and assignment tracking

## Project Structure

```
webprog_group_quiz/
├── src/
│   ├── main.rs          # Application entry point
│   ├── handlers.rs      # HTTP request handlers
│   ├── models.rs        # Data structures
│   ├── auth.rs          # Authentication logic
│   └── db.rs           # Database connection
├── templates/
│   ├── bug_assign_form.html # Bug assignment interface
│   ├── login.html       # Login page
│   └── ...
├── schema.sql          # Database schema
└── Cargo.toml         # Rust dependencies
```

## Security Features

- Session-based authentication
- Role-based access control
- SQL injection prevention with parameterized queries
- Secure password hashing
- CSRF protection through session validation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational purposes as part of a web programming course. 


## What we wanted to do but not successful
- We wanted to have the CRUD to have the webpage version of CRUD but was unable to suceed due to merge conflicts and git issues which leads us to debug pass the time limit. We then decided just cut the content of the html as we would pass the the dropbox closed timing also

List of templates for what we wanted
templates/
├── bug_assign_form.html
├── bugs_new.html
├── bugs_update.html
├── bugs.html
├── close_project_form.html
├── login.html
├── projects_add.html
├── projects.html
├── register.html
└── update_bug.html