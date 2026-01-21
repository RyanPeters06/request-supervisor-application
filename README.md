# Supervisor Response System
A desktop application to request supervisor assistance with **push notifications via Pushover**.  
Supports emergency alerts, custom messages, response tracking, and CSV logging.
![Application Screenshot](https://github.com/RyanPeters06/request-supervisor-application/blob/325a28356b53e4ec5ec6de07bc60f7446e14c448/main-interface-screenshot.png)
---
## Features
- 🔔 **Push Notifications**: Notify multiple supervisors simultaneously  
- 🚨 **Emergency Alerts**: High-priority alerts with confirmation  
- 💬 **Custom Messages**: Personalized messages (up to 20 characters)  
- ⏱️ **Response Tracking**: Monitor response times and supervisor arrival  
- 🌐 **Web Interface**: Mobile-friendly supervisor response forms  
- 📊 **CSV Logging**: Automatic logging of requests and responses  
- ⚙️ **Settings Management**: Password-protected configuration
---
## Prerequisites
- Python 3.7+
- Internet connection for Pushover notifications
- Pushover account and application token
---
## Installation
1. **Clone the repository**
```bash
git clone https://github.com/RyanPeters06/request-supervisor-application.git
cd request-supervisor-application
```
2. **Install dependencies**
```bash
pip install -r requirements.txt
```
Dependencies:
- tkinter (usually included with Python)
- flask
- requests
- Pillow
- python-dotenv
3. **Configure environment variables**
```bash
cp .env.example .env
```
Fill in your .env file with your Pushover API credentials, settings password, and default log path.
4. **Add required images** (background.png, cogwheel.png, icon.ico) in the project directory.
5. **Run the application**
```bash
python requestsupervisor.py
```
---
## Usage
### First Launch
- Open Settings (cogwheel icon)
- Enter settings password (from .env)
- Add at least one supervisor with name and Pushover user key
- Set the log file path or use the default
### Sending Requests
- **Request**: Standard supervisor request
- **Send Message**: Custom message (max 20 characters)
- **🚨EMERGENCY🚨**: High-priority emergency alert
All supervisor responses are tracked and logged automatically.
---
## File Structure
```
supervisor-response-system/
├── requestsupervisor.py        # Main application
├── .env.example                # Example environment file
├── .gitignore                  # Git ignore rules
├── requirements.txt            # Python dependencies
├── settings.json               # User settings (gitignored)
├── background.png              # GUI background image
├── cogwheel.png                # Settings icon
├── icon.ico                    # Application icon
└── README.md                   # This file
```
