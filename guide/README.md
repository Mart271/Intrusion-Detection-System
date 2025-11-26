# IDS System - Intrusion Detection System

A Flask-based Intrusion Detection System with authentication, threat detection, and security monitoring.

## Features

- User authentication with role-based access control (Admin, Analyst, User)
- Real-time threat detection (Brute Force, Distributed Attacks, Credential Stuffing)
- Security alerts and incident management
- Rate limiting and IP blocking
- Account lockout mechanisms
- Forensic logging
- Dashboard with statistics and reports

## Setup

### Prerequisites
- Python 3.8+
- pip

### Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd "IDS project"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

4. Access the application:
- Open browser: `http://localhost:5000`
- Default login credentials (development only):
  - Admin: `admin` / `Admin2024!Strong`
  - Analyst: `analyst` / `Analyst2024!Strong`
  - User: `testuser` / `User2024!Strong`

## Deployment

### Render.com

See `RENDER_COMPATIBILITY_CHECK.md` for detailed deployment instructions.

Quick setup:
1. Push to GitHub
2. Create Web Service on Render.com
3. Set Start Command: `gunicorn main:app --bind 0.0.0.0:$PORT`
4. Set environment variables (see Render dashboard)

## Environment Variables

For production, set these environment variables:

- `FLASK_ENV=production`
- `IDS_HOST=0.0.0.0`
- `IDS_SECRET_KEY=<random-secret-key>`
- `IDS_ADMIN_PASSWORD=<your-admin-password>`
- `IDS_ANALYST_PASSWORD=<your-analyst-password>`
- `IDS_USER_PASSWORD=<your-user-password>`
- `CORS_ORIGINS=<your-domain-url>`

## Project Structure

```
IDS project/
├── main.py                 # Main application file
├── requirements.txt       # Python dependencies
├── login.html            # Login page
├── admin.html            # Admin dashboard
├── analyst.html          # Analyst dashboard
├── change-password.html  # Password change page
├── *.css                 # Stylesheets
├── *.js                  # JavaScript files
└── front-end/            # Frontend testing files
```

## API Endpoints

### Public
- `POST /api/login` - User login
- `GET /api/health` - Health check

### Authenticated
- `POST /api/logout` - Logout
- `POST /api/change-password` - Change password
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/dashboard/alerts` - Get alerts
- `GET /api/dashboard/login-history` - Login history

### Admin Only
- `GET/POST /api/admin/config` - System configuration
- `GET/POST /api/admin/rules` - Detection rules
- `POST /api/admin/block-ip` - Block IP address
- `POST /api/admin/lock-account` - Lock user account
- And more...

### Analyst
- `GET /api/analyst/detections` - Get detections
- `POST /api/analyst/escalate-incident` - Escalate incident
- And more...

## Security Features

- Password hashing with bcrypt
- Session management with timeout
- Rate limiting
- IP blocking
- Account lockout
- CORS protection
- Security headers
- Input validation and sanitization

## License

[Your License Here]

## Author

[Your Name Here]

