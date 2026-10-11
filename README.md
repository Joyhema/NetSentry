# NetSentry – Network Monitoring & Intrusion Detection System

## Project Overview
NetSentry is a Python-based network monitoring dashboard that displays network traffic statistics, active network connections, and recorded security events.

## Features
- Live network traffic statistics
- Active network connection count
- Security event dashboard
- SQLite database for storing events and network samples
- Flask-based web interface
- JSON API endpoints

## Technologies Used
- Python
- Flask
- psutil
- SQLite
- HTML and CSS
- JavaScript

## How to Run Locally
1. Install Python.
2. Install dependencies using `pip install -r requirements.txt`.
3. Run the application using `python app.py`.
4. Open `http://127.0.0.1:5000` in your browser.

## API Endpoints
- `/api/health` – Application health status
- `/api/stats` – Network statistics
- `/api/events` – Recorded security events

## Limitations
This is a basic monitoring and heuristic-alert prototype. It is not a production-grade intrusion detection system, and an empty alert list does not guarantee that a network is secure.

## Project Status

NetSentry is deployed on Render and provides a live monitoring dashboard.

- **Cloud Deployment:** Deployed on Render.
- **Laptop Monitoring:** CPU, memory, and disk metrics are collected by the Python agent.
- **API Integration:** Agent events are submitted through an API-key-protected endpoint.
- **Security Monitoring:** Keyword-based suspicious activity detection has been tested using a controlled test event.
- **Dashboard:** System metrics and security events are displayed on the dashboard.
- **Testing:** Basic API submission and alert detection tests have passed. Further testing and improvements are ongoing.

**Note:** The current suspicious activity detection is rule-based and does not confirm real cyberattacks.
