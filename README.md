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
Local dashboard running; cloud deployment and further testing are pending.