# FastAPI-in-Action-Real-Time-API-Security-and-Anomaly-Detection
My project is a real-time API security solution built with FastAPI. It tackles one of today’s most critical problems: securing the communication between applications. Imagine APIs as digital doorways—if those doorways aren’t secure, attackers can easily break in. We use JWT tokens for authentication, which means each user gets a secure, short-lived digital ticket. If someone tries to steal or misuse a ticket, our system—through anomaly detection and IP monitoring—immediately flags and blocks that suspicious activity.

For example, if an attacker makes too many failed login attempts or even abuses valid logins, our system detects this unusual behavior and temporarily blocks the IP, just like a bouncer refusing entry to someone causing trouble at a club. This approach not only prevents brute-force attacks but also mitigates risks like token hijacking and DDoS attacks. In essence, my project provides a scalable and proactive defense mechanism that could have helped prevent real-world breaches like the Facebook token leak by stopping attackers before they cause harm


This project demonstrates a secure FastAPI-based web application that integrates real-time anomaly detection and brute-force mitigation. It features JWT-based authentication, role-based access, and an admin dashboard that displays live traffic statistics, as well as lists of blocked and suspicious IPs.

## Features
Authentication & Authorization:
  - User login using JWT tokens.
  - Role-based access control (admin and user).

Anomaly Detection:
  - Monitors IP request patterns.
  - Blocks IPs that exceed predefined request thresholds.

Brute-Force Mitigation:
  - Applies time buffers for excessive failed login attempts.
  - Blocks IPs after too many successful logins within a minute.
  - Differentiates between "suspicious" and "blocked" IPs based on the login activity.

Real-Time Dashboard:
  - Visualizes request statistics with Chart.js.
  - Displays lists of blocked and suspicious IPs.
  - Updates in real time via AJAX calls to the `/dashboard-data` endpoint.

Self-Healing Task:  
  - Background process to clean up outdated logs and reset blocks.

## Project Structure
your-project/
├── main.py
├── static/
│   ├── dashboard.js
│   └── Hamster thumbs up.jpg
└── templates/
    ├── dashboard.html
    ├── login.html
    └── user.html

## Run the application with Uvicorn (with auto-reload and SSL support)
uvicorn main:app --reload --ssl-keyfile key.pem --ssl-certfile cert.pem
