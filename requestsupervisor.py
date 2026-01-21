# ==============================================================================
# SUPERVISOR RESPONSE SYSTEM
# ==============================================================================

# NOTE: TO FIND CODE THAT SETS IMAGES WITHIN THE PROGRAM, USE CTRL + F AND LOOK FOR ".png"

# ------------------------------------------------------------------------------
# IMPORTS AND DEPENDENCIES
# ------------------------------------------------------------------------------
import tkinter as tk
from tkinter import PhotoImage, ttk, messagebox, filedialog
from flask import Flask, request
import requests
import socket
import threading
import time
import os
from PIL import Image, ImageTk, ImageDraw
import csv
from datetime import datetime
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ------------------------------------------------------------------------------
# CONFIGURATION AND CONSTANTS
# ------------------------------------------------------------------------------

# Pushover API Configuration
PUSHOVER_API_URL = os.getenv("PUSHOVER_API_URL")
PUSHOVER_APP_TOKEN = os.getenv("PUSHOVER_APP_TOKEN")
SETTINGS_PASSWORD = os.getenv("SETTINGS_PASSWORD", "")
DEFAULT_LOG_PATH = os.getenv("DEFAULT_LOG_PATH")

if not PUSHOVER_API_URL or not PUSHOVER_APP_TOKEN:
    raise RuntimeError("Missing Pushover API credentials. Check environment variables.")

if not SETTINGS_PASSWORD:
    raise RuntimeError("Missing SETTINGS_PASSWORD. Check environment variables.")

if not DEFAULT_LOG_PATH:
    raise RuntimeError("Missing DEFAULT_LOG_PATH. Check environment variables.")

# Settings Management
SETTINGS_FILE = "settings.json"
DEFAULT_SETTINGS = {
    "supervisors": [
        {"name": "Default Supervisor", "key": ""}
    ],
    "log_file_path": "St Thomas Supervisor Response log.csv"
}
# Default log file path (subject to change with location)
SHARED_LOG_PATH = DEFAULT_LOG_PATH

# ------------------------------------------------------------------------------
# FLASK APPLICATION SETUP
# ------------------------------------------------------------------------------
app = Flask(__name__)

# ------------------------------------------------------------------------------
# GLOBAL STATE VARIABLES
# ------------------------------------------------------------------------------
response_received = False  # Flag to track if supervisor has responded
responder_name = "Unknown"  # Name of the responding supervisor
supervisor_arrived = False  # Flag to track physical arrival
response_start_time = 0  # Timestamp when request was sent
message = ""
program_restarted = True  # This is here to stop recursive flashing when you press emergency

# Threading event to signal GUI updates
gui_update_event = threading.Event()


# ------------------------------------------------------------------------------
# SETTINGS MANAGEMENT FUNCTIONS
# ------------------------------------------------------------------------------

def load_settings():
    """
    Load application settings from JSON file.
    Returns default settings if file doesn't exist or on error.
    Handles both old and new format for backward compatibility.
    """
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)

                # Handle backward compatibility - convert old format to new format
                if "pushover_user_key" in settings and "supervisors" not in settings:
                    # Old format detected, convert to new format
                    old_key = settings.get("pushover_user_key", "")
                    settings["supervisors"] = [{"name": "Supervisor", "key": old_key}]
                    # Remove old key to avoid confusion
                    del settings["pushover_user_key"]
                    # Save converted settings
                    save_settings(settings)

                # Ensure supervisors list exists and is not empty
                if "supervisors" not in settings or not settings["supervisors"]:
                    settings["supervisors"] = DEFAULT_SETTINGS["supervisors"].copy()

                return settings
        else:
            return DEFAULT_SETTINGS.copy()
    except Exception as e:
        print(f"Error loading settings: {e}")
        return DEFAULT_SETTINGS.copy()


def save_settings(settings):
    """
    Save application settings to JSON file.
    Returns True on success, False on failure.
    """
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False

# ------------------------------------------------------------------------------
# SETTINGS GUI WINDOW
# ------------------------------------------------------------------------------
def open_settings_window(parent_root):
    """
    Create and display the settings configuration window.
    Allows users to configure multiple Pushover keys with supervisor names and log file paths.
    """
    # Window Setup
    settings_window = tk.Toplevel(parent_root)
    settings_window.title("Settings")
    settings_window.geometry("500x700")  # Optimized dimensions
    settings_window.resizable(False, False)
    settings_window.transient(parent_root)
    settings_window.grab_set()
    settings_window.configure(bg="#9CBECE")

    # Center the window relative to parent
    settings_window.geometry("+%d+%d" % (parent_root.winfo_rootx() + 50, parent_root.winfo_rooty() + 50))

    # Load current settings
    current_settings = load_settings()

    # ------------------------------------------------------------------------------
    # TTK STYLE CONFIGURATION
    # ------------------------------------------------------------------------------
    style = ttk.Style()

    # Label styles with enhanced contrast and spacing
    style.configure("Clean.TLabel",
                    font=("Segoe UI", 11),
                    foreground="#2c3e50",
                    background="#9CBECE",
                    padding=(0, 3))

    style.configure("CleanHeader.TLabel",
                    font=("Segoe UI", 18, "bold"),
                    foreground="#1a252f",
                    background="#9CBECE",
                    padding=(0, 8))

    style.configure("CleanSubLabel.TLabel",
                    font=("Segoe UI", 9),
                    foreground="#4a6741",
                    background="#9CBECE",
                    padding=(2, 2))

    style.configure("ColumnHeader.TLabel",
                    font=("Segoe UI", 9, "bold"),
                    foreground="#2c3e50",
                    background="#9CBECE",
                    padding=(2, 2))

    # Enhanced entry styles
    style.configure("Clean.TEntry",
                    fieldbackground="#ffffff",
                    borderwidth=2,
                    relief="solid",
                    bordercolor="#7ba7b7",
                    focuscolor="#5a9fd4",
                    insertcolor="#2c3e50",
                    padding=(10, 8))

    style.configure("Name.TEntry",
                    fieldbackground="#ffffff",
                    borderwidth=2,
                    relief="solid",
                    bordercolor="#7ba7b7",
                    focuscolor="#5a9fd4",
                    insertcolor="#2c3e50",
                    padding=(8, 6))

    style.configure("Key.TEntry",
                    fieldbackground="#ffffff",
                    borderwidth=2,
                    relief="solid",
                    bordercolor="#7ba7b7",
                    focuscolor="#5a9fd4",
                    insertcolor="#2c3e50",
                    padding=(8, 6))

    # Button styles with proper text colors for visibility
    style.configure("Clean.TButton",
                    font=("Segoe UI", 10, "bold"),
                    background="#7ba7b7",
                    foreground="#000000",  # Changed to black for visibility
                    borderwidth=1,
                    focuscolor="none",
                    padding=(15, 8))

    style.configure("Browse.TButton",
                    font=("Segoe UI", 9, "bold"),
                    background="#9CBECE",
                    foreground="#000000",  # Changed to black for visibility
                    borderwidth=1,
                    focuscolor="none",
                    padding=(12, 6))

    style.configure("Add.TButton",
                    font=("Segoe UI", 9, "bold"),
                    background="#9CBECE",
                    foreground="green",  # Changed to black for visibility
                    borderwidth=1,
                    focuscolor="none",
                    padding=(10, 6))

    style.configure("Remove.TButton",
                    font=("Segoe UI", 8, "bold"),
                    background="#9CBECE",
                    foreground="red",
                    borderwidth=0,
                    focuscolor="none",
                    padding=(8, 4))

    style.configure("Save.TButton",
                    font=("Segoe UI", 11, "bold"),
                    background="#9CBECE",
                    foreground="green",
                    borderwidth=1,
                    focuscolor="none",
                    padding=(18, 8))

    style.configure("Cancel.TButton",
                    font=("Segoe UI", 11, "bold"),
                    background="#9CBECE",
                    foreground="red",  # Changed to black for visibility
                    borderwidth=1,
                    focuscolor="none",
                    padding=(18, 8))

    # Disabled button style
    style.configure("Disabled.TButton",
                    font=("Segoe UI", 11, "bold"),
                    background="#9CBECE",
                    foreground="#606060",
                    borderwidth=1,
                    focuscolor="none",
                    padding=(18, 8))

    style.configure("Clean.TFrame", background="#9CBECE")

    # Button hover effects with proper text colors
    style.map("Clean.TButton",
              background=[('active', '#6ba3b3'),
                          ('pressed', '#5a8a9a')],
              foreground=[('active', '#000000'),
                          ('pressed', '#000000')])

    style.map("Browse.TButton",
              background=[('active', '#9CBECE'),
                          ('pressed', '#5a8a9a')],
              foreground=[('active', '#000000'),
                          ('pressed', '#000000')])

    style.map("Add.TButton",
              background=[('active', '#9CBECE'),
                          ('pressed', '#3a7fb4')],
              foreground=[('active', 'green'),
                          ('pressed', '#000000')])

    style.map("Remove.TButton",
              background=[('active', '#9CBECE'),
                          ('pressed', '#9CBECE')],
              foreground=[('active', 'red'),
                          ('pressed', 'red')])

    style.map("Save.TButton",
              background=[('active', '#9CBECE'),
                          ('pressed', '#3a7fb4')],
              foreground=[('active', 'green'),
                          ('pressed', '#000000')])

    style.map("Cancel.TButton",
              background=[('active', '#9CBECE'),
                          ('pressed', '#5a8a9a')],
              foreground=[('active', 'red'),
                          ('pressed', '#000000')])

    # ------------------------------------------------------------------------------
    # MAIN CONTAINER WITH SIMPLE SCROLLBAR
    # ------------------------------------------------------------------------------

    # Create main container frame
    main_frame = tk.Frame(settings_window, bg="#9CBECE")
    main_frame.pack(fill="both", expand=True)

    # Create canvas for scrolling content
    canvas = tk.Canvas(main_frame, bg="#9CBECE", highlightthickness=0)

    # Create scrollbar on the far right
    scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")

    # Pack canvas to fill remaining space
    canvas.pack(side="left", fill="both", expand=True)

    # Configure canvas scrolling
    canvas.configure(yscrollcommand=scrollbar.set)

    # Create scrollable frame inside canvas
    scrollable_frame = tk.Frame(canvas, bg="#9CBECE")
    canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

    # Configure scrollable area
    def configure_scroll_region(event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))

    scrollable_frame.bind("<Configure>", configure_scroll_region)

    # Configure canvas window width to match canvas
    def configure_canvas_width(event):
        canvas.itemconfig(canvas_window, width=event.width)

    canvas.bind("<Configure>", configure_canvas_width)

    # Add content with padding to the scrollable frame
    content_frame = tk.Frame(scrollable_frame, bg="#9CBECE")
    content_frame.pack(fill="both", expand=True, padx=25, pady=20)

    # Header section with title and separator
    header_frame = tk.Frame(content_frame, bg="#9CBECE")
    header_frame.pack(fill="x", pady=(0, 25))

    header_label = ttk.Label(header_frame, text="Settings Configuration", style="CleanHeader.TLabel")
    header_label.pack()

    # Visual separator line
    separator_frame = tk.Frame(header_frame, bg="#9CBECE", height=3)
    separator_frame.pack(fill="x", pady=(12, 0))
    separator_canvas = tk.Canvas(separator_frame, height=2, bg="#7ba7b7", highlightthickness=0)
    separator_canvas.pack(fill="x")

    # ------------------------------------------------------------------------------
    # PUSHOVER SUPERVISORS SECTION
    # ------------------------------------------------------------------------------

    pushover_section = tk.Frame(content_frame, bg="#9CBECE")
    pushover_section.pack(fill="x", pady=(0, 30))

    # Section title and help text
    pushover_label = ttk.Label(pushover_section, text="🔔 Pushover Supervisor Keys", style="Clean.TLabel")
    pushover_label.pack(anchor="w")

    pushover_help = ttk.Label(pushover_section,
                              text="Add supervisor names and their Pushover user keys for notifications",
                              style="CleanSubLabel.TLabel")
    pushover_help.pack(anchor="w", pady=(3, 15))

    # Column headers frame
    headers_frame = tk.Frame(pushover_section, bg="#9CBECE")
    headers_frame.pack(fill="x", pady=(0, 8))
    headers_frame.columnconfigure(0, weight=1)
    headers_frame.columnconfigure(1, weight=2)

    name_header = ttk.Label(headers_frame, text="Supervisor Name", style="ColumnHeader.TLabel")
    name_header.grid(row=0, column=0, sticky="w", padx=(2, 0))

    key_header = ttk.Label(headers_frame, text="Pushover User Key", style="ColumnHeader.TLabel")
    key_header.grid(row=0, column=1, sticky="w", padx=(10, 0))

    # Frame to hold all supervisor entries
    supervisors_frame = tk.Frame(pushover_section, bg="#9CBECE")
    supervisors_frame.pack(fill="x")

    # List to store supervisor entry widgets
    supervisor_entries = []

    # Load existing supervisors from settings
    existing_supervisors = current_settings.get("supervisors", [])
    if not existing_supervisors:
        # Default to one empty entry if no existing supervisors
        existing_supervisors = [{"name": "", "key": ""}]

    def create_supervisor_entry(name="", key=""):
        """Create a new supervisor name/key entry row"""
        entry_frame = tk.Frame(supervisors_frame, bg="#9CBECE")
        entry_frame.pack(fill="x", pady=(0, 10))
        entry_frame.columnconfigure(0, weight=1)
        entry_frame.columnconfigure(1, weight=2)

        # Supervisor name field
        name_var = tk.StringVar(value=name)
        name_entry = ttk.Entry(entry_frame, textvariable=name_var,
                               font=("Segoe UI", 10), style="Name.TEntry")
        name_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        # Pushover key field
        key_var = tk.StringVar(value=key)
        key_entry = ttk.Entry(entry_frame, textvariable=key_var,
                              font=("Consolas", 10), style="Key.TEntry")
        key_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))

        # Remove button
        def remove_entry():
            if len(supervisor_entries) > 1:  # Keep at least one entry
                supervisor_entries.remove(entry_data)
                entry_frame.destroy()
                configure_scroll_region()  # Update scroll region after removing

        remove_btn = ttk.Button(entry_frame, text="Remove", command=remove_entry,
                                style="Remove.TButton")
        remove_btn.grid(row=0, column=2, sticky="ns")

        # Store entry data
        entry_data = {
            'frame': entry_frame,
            'name_var': name_var,
            'key_var': key_var,
            'name_entry': name_entry,
            'key_entry': key_entry,
            'remove_btn': remove_btn
        }

        supervisor_entries.append(entry_data)
        configure_scroll_region()  # Update scroll region after adding
        return entry_data

    def add_supervisor_entry():
        """Add a new supervisor entry"""
        new_entry = create_supervisor_entry()
        new_entry['name_entry'].focus()

    # Create initial supervisor entries
    for supervisor in existing_supervisors:
        create_supervisor_entry(supervisor.get("name", ""), supervisor.get("key", ""))

    # Add supervisor button
    add_btn_frame = tk.Frame(pushover_section, bg="#9CBECE")
    add_btn_frame.pack(fill="x", pady=(10, 0))

    add_supervisor_btn = ttk.Button(add_btn_frame, text="+ Add Supervisor",
                                    command=add_supervisor_entry, style="Add.TButton")
    add_supervisor_btn.pack(side="left")

    # ------------------------------------------------------------------------------
    # LOG FILE PATH SECTION
    # ------------------------------------------------------------------------------

    log_section = tk.Frame(content_frame, bg="#9CBECE")
    log_section.pack(fill="x", pady=(0, 30))

    # Section title and help text
    log_label = ttk.Label(log_section, text="📁 Log File Path", style="Clean.TLabel")
    log_label.pack(anchor="w")

    log_help = ttk.Label(log_section, text="Choose where to save your log files",
                         style="CleanSubLabel.TLabel")
    log_help.pack(anchor="w", pady=(3, 12))

    # Path input frame with proper spacing
    path_frame = tk.Frame(log_section, bg="#9CBECE")
    path_frame.pack(fill="x")
    path_frame.columnconfigure(0, weight=1)

    # Log path input field
    log_path_var = tk.StringVar(value=current_settings.get("log_file_path", ""))
    log_path_entry = ttk.Entry(path_frame, textvariable=log_path_var,
                               font=("Consolas", 10), style="Clean.TEntry")
    log_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 12))

    # Browse button functionality
    def browse_log_file():
        """Open file dialog to select log file location"""
        filename = filedialog.asksaveasfilename(
            title="Select Log File Location",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="St Thomas Supervisor Response log.csv"
        )
        if filename:
            log_path_var.set(filename)

    browse_button = ttk.Button(path_frame, text="Browse...", command=browse_log_file,
                               style="Browse.TButton")
    browse_button.grid(row=0, column=1, sticky="ns")

    # ------------------------------------------------------------------------------
    # PASSWORD SECTION
    # ------------------------------------------------------------------------------

    password_section = tk.Frame(content_frame, bg="#9CBECE")
    password_section.pack(fill="x", pady=(0, 35))

    # Section title and help text
    password_label = ttk.Label(password_section, text="🔒 Password", style="Clean.TLabel")
    password_label.pack(anchor="w")

    password_help = ttk.Label(password_section, text="Enter password to save settings",
                              style="CleanSubLabel.TLabel")
    password_help.pack(anchor="w", pady=(3, 12))

    # Password input field
    password_var = tk.StringVar()
    password_entry = ttk.Entry(password_section, textvariable=password_var, show="*",
                               font=("Consolas", 11), style="Clean.TEntry")
    password_entry.pack(fill="x")

    # ------------------------------------------------------------------------------
    # ACTION BUTTONS SECTION
    # ------------------------------------------------------------------------------

    button_section = tk.Frame(content_frame, bg="#9CBECE")
    button_section.pack(fill="x", pady=(20, 0))

    # Container to center buttons
    button_container = tk.Frame(button_section, bg="#9CBECE")
    button_container.pack(anchor="center")

    # Save button functionality
    def save_and_close():
        """Validate inputs and save settings"""
        # Check password first
        if password_var.get() != SETTINGS_PASSWORD:
            messagebox.showerror("Access Denied",
                                 "❌ Incorrect password!\n\nPlease enter the correct password to save settings.")
            password_entry.focus()
            password_entry.select_range(0, tk.END)
            return

        # Collect supervisor data
        supervisors = []
        for entry in supervisor_entries:
            name = entry['name_var'].get().strip()
            key = entry['key_var'].get().strip()

            # Skip empty entries
            if not name and not key:
                continue

            # Validate that both name and key are provided
            if not name or not key:
                messagebox.showerror("Validation Error",
                                     "⚠️ Each supervisor must have both a name and Pushover key!\n\nPlease fill in all fields or remove empty entries.")
                if not name:
                    entry['name_entry'].focus()
                else:
                    entry['key_entry'].focus()
                return

            supervisors.append({"name": name, "key": key})

        # Validate that at least one supervisor is configured
        if not supervisors:
            messagebox.showerror("Validation Error",
                                 "⚠️ At least one supervisor must be configured!\n\nPlease add a supervisor with name and Pushover key.")
            return

        # Validate log path
        log_path = log_path_var.get().strip()
        if not log_path:
            messagebox.showerror("Validation Error",
                                 "⚠️ Log file path cannot be empty!\n\nPlease select a valid file path.")
            log_path_entry.focus()
            return

        # Save settings to file
        new_settings = {
            "supervisors": supervisors,
            "log_file_path": log_path
        }

        if save_settings(new_settings):
            # Update global variables
            global PUSHOVER_USER_KEYS, SHARED_LOG_PATH
            PUSHOVER_USER_KEYS = [supervisor["key"] for supervisor in supervisors]
            SHARED_LOG_PATH = log_path

            messagebox.showinfo("Success",
                                f"Settings saved successfully!\n\nConfigured {len(supervisors)} supervisor(s). Changes will take effect immediately.")
            settings_window.destroy()
        else:
            messagebox.showerror("Error",
                                 "❌ Failed to save settings!\n\nPlease try again or check file permissions.")

    # Function to check password and enable/disable save button
    def check_password(*args):
        """Enable/disable save button based on password"""
        if password_var.get() == SETTINGS_PASSWORD:
            save_btn.configure(style="Save.TButton", state="normal")
        else:
            save_btn.configure(style="Disabled.TButton", state="disabled")

    # Bind password checking to password field
    password_var.trace("w", check_password)

    # Cancel button functionality
    def cancel_and_close():
        """Close settings window without saving"""
        settings_window.destroy()

    # Create action buttons with proper spacing
    cancel_btn = ttk.Button(button_container, text="Cancel", command=cancel_and_close,
                            style="Cancel.TButton")
    cancel_btn.pack(side="left", padx=(0, 15))

    save_btn = ttk.Button(button_container, text="Save Settings", command=save_and_close,
                          style="Disabled.TButton", state="disabled")
    save_btn.pack(side="left")

    # ------------------------------------------------------------------------------
    # KEYBOARD NAVIGATION AND EVENT HANDLING
    # ------------------------------------------------------------------------------

    def on_enter_key(event):
        """Handle Enter key press - save settings if password is correct"""
        if password_var.get() == SETTINGS_PASSWORD:
            save_and_close()
        else:
            messagebox.showerror("Access Denied",
                                 "❌ Incorrect password!\n\nPlease enter the correct password to save settings.")

    def on_escape_key(event):
        """Handle Escape key press - cancel"""
        cancel_and_close()

    # Bind keyboard shortcuts
    settings_window.bind('<Return>', on_enter_key)
    settings_window.bind('<Escape>', on_escape_key)

    # Mouse wheel scrolling for canvas - bind to entire window and all widgets
    def on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # Bind mousewheel to the main window and all child widgets
    def bind_mousewheel_to_widget(widget):
        widget.bind("<MouseWheel>", on_mousewheel)
        for child in widget.winfo_children():
            bind_mousewheel_to_widget(child)

    # Bind to the settings window and all its children
    bind_mousewheel_to_widget(settings_window)

    # Set initial focus
    if supervisor_entries:
        supervisor_entries[0]['name_entry'].focus()

    # Ensure window visibility and focus
    settings_window.lift()
    settings_window.focus_force()


# ------------------------------------------------------------------------------
# LOGGING FUNCTIONS
# ------------------------------------------------------------------------------

def log_supervisor_response(supervisor_name, response_time_seconds, message=""):
    """
    Log supervisor response data to CSV file.
    Creates file and directory if they don't exist.
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(SHARED_LOG_PATH), exist_ok=True)
        file_exists = os.path.isfile(SHARED_LOG_PATH)

        # Write to CSV file
        with open(SHARED_LOG_PATH, mode='a', newline='') as file:
            writer = csv.writer(file)

            # Write header if file is new
            if not file_exists:
                writer.writerow(["Timestamp", "Supervisor Name", "Response Time (s)", "Message"])

            # Write response data
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                supervisor_name,
                round(response_time_seconds, 2),
                message
            ])

    except PermissionError:
        print("Could not write to log file — it may be open in another program like Excel.")
    except Exception as e:
        pass  # Silently handle other exceptions to prevent app crashes


# ------------------------------------------------------------------------------
# NETWORK UTILITY FUNCTIONS
# ------------------------------------------------------------------------------

def get_local_ip():
    """
    Get the local IP address of the machine.
    Returns 'localhost' if unable to determine IP.
    """
    try:
        # Connect to external DNS to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "localhost"


# ------------------------------------------------------------------------------
# PUSHOVER NOTIFICATION FUNCTIONS
# ------------------------------------------------------------------------------

def send_notification(custom_message=None):
    """
    Send standard priority notification to all configured Pushover users.
    Starts response timer and includes response link.
    """
    global response_start_time

    # Initialize response timer
    response_start_time = time.time()

    # Get system information for notification
    hostname = socket.gethostname()
    local_ip = get_local_ip()
    response_link = f"http://{local_ip}:5000/respond"

    success = False

    # Send to all configured users
    for user_key in PUSHOVER_USER_KEYS:
        # Customize message based on input
        if custom_message:
            message = f"{custom_message} - from {hostname}. Tap to respond."
            title = "Custom Supervisor Request"
        else:
            message = f"Help Requested from {hostname}. Tap to respond."
            title = "Supervisor Request"

        # Prepare notification data
        data = {
            "token": PUSHOVER_APP_TOKEN,
            "user": user_key,
            "title": title,
            "message": message,
            "priority": 1,  # High priority
            "url": response_link,
            "url_title": "I'm responding",
        }

        # Send notification
        try:
            response = requests.post(PUSHOVER_API_URL, data=data)
            print(f"Notification sent to {user_key}:", response.text)
            if response.status_code == 200:
                success = True
        except Exception as e:
            print(f"Error sending to {user_key}:", e)

    return success


def send_emergency_notification():
    """
    Send emergency HIGH PRIORITY notification to all configured Pushover users.
    Uses priority 2 with retry and expire settings for critical alerts.
    """
    global response_start_time

    # Initialize response timer
    response_start_time = time.time()

    # Get system information
    hostname = socket.gethostname()
    local_ip = get_local_ip()
    response_link = f"http://{local_ip}:5000/respond_emergency"

    success = False

    # Send emergency notification to all users
    for user_key in PUSHOVER_USER_KEYS:
        data = {
            "token": PUSHOVER_APP_TOKEN,
            "user": user_key,
            "title": "🚨 EMERGENCY - IMMEDIATE ASSISTANCE REQUIRED 🚨",
            "message": f"EMERGENCY HELP NEEDED at {hostname}! This requires IMMEDIATE response. Tap to acknowledge.",
            "priority": 2,  # Emergency priority
            "retry": 30,  # Retry every 30 seconds
            "expire": 30,  # Expire after the first retry
            "sound": "siren",  # Emergency sound
            "url": response_link,
            "url_title": "🚨 EMERGENCY RESPONSE"
        }

        try:
            response = requests.post(PUSHOVER_API_URL, data=data)
            print(f"Emergency notification sent to {user_key}:", response.text)
            if response.status_code == 200:
                success = True
        except Exception as e:
            print(f"Error sending emergency notification to {user_key}:", e)

    return success


def send_response_notification(responder):
    """
    Send confirmation notification that someone is responding to the request.
    Low priority notification to inform all users.
    """
    hostname = socket.gethostname()
    message = f"{responder} is responding to help request from {hostname}."

    for user_key in PUSHOVER_USER_KEYS:
        data = {
            "token": PUSHOVER_APP_TOKEN,
            "user": user_key,
            "title": "Response Received",
            "message": message,
            "priority": 0  # Normal priority
        }
        try:
            requests.post(PUSHOVER_API_URL, data=data)
        except Exception as e:
            print(f"Error sending response notification: {e}")

def send_cancel_notification():
    """
    Send notification that the help request has been cancelled.
    Normal priority notification to inform all supervisors.
    """
    hostname = socket.gethostname()
    message = f"Help request from {hostname} has been cancelled by the user."

    for user_key in PUSHOVER_USER_KEYS:
        data = {
            "token": PUSHOVER_APP_TOKEN,
            "user": user_key,
            "title": "Request Cancelled",
            "message": message,
            "priority": 0  # Normal priority
        }
        try:
            requests.post(PUSHOVER_API_URL, data=data)
        except Exception as e:
            print(f"Error sending cancel notification: {e}")

def send_emergency_response_notification(responder):
    """
    Send confirmation notification that someone is responding to emergency.
    High priority with distinctive sound for emergency responses.
    """
    hostname = socket.gethostname()
    message = f"🚨 {responder} is responding to EMERGENCY at {hostname}. Help is on the way!"

    for user_key in PUSHOVER_USER_KEYS:
        data = {
            "token": PUSHOVER_APP_TOKEN,
            "user": user_key,
            "title": "🚨 Emergency Response Confirmed",
            "message": message,
            "priority": 1,  # High priority
            "sound": "intermission"  # Distinctive sound
        }
        try:
            requests.post(PUSHOVER_API_URL, data=data)
        except Exception as e:
            print(f"Error sending emergency response notification: {e}")


# ------------------------------------------------------------------------------
# RESPONSE MONITORING FUNCTIONS
# ------------------------------------------------------------------------------

def monitor_response():
    """
    Monitor for supervisor response with timeout.
    Polls response flag for up to 5 minutes.
    """
    global response_received
    print("Waiting for supervisor to respond...")

    # Configuration
    timeout = 300  # 5 minutes timeout
    start_time = time.time()

    # Poll for response until timeout or response received
    while not response_received:
        # Check timeout condition
        if time.time() - start_time > timeout:
            print("Timeout waiting for response.")
            break

        time.sleep(1)  # Check every second

    # Log result
    if response_received:
        print(f"Supervisor ({responder_name}) is responding!")


# ------------------------------------------------------------------------------
# FLASK WEB ROUTES
# ------------------------------------------------------------------------------

@app.route("/respond")
def respond():
    """
    Flask route for displaying the supervisor response form.
    Shows mobile-friendly form to collect responder's name.
    """
    return f"""
    <html>
        <head>
            <title>Supervisor Request - Response</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                /* Modern, responsive styling for mobile and desktop */
                body {{ 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    margin: 0; 
                    padding: 0; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    min-height: 100vh;
                    background-color: #f5f7fa; 
                }}
                .container {{ 
                    max-width: 600px; 
                    width: 90%;
                    margin: 20px; 
                    padding: 30px; 
                    border-radius: 12px; 
                    box-shadow: 0 8px 24px rgba(0,0,0,0.12);
                    background-color: white;
                }}
                .header {{
                    display: flex;
                    align-items: center;
                    margin-bottom: 20px;
                }}
                .logo {{
                    width: 36px;
                    height: 36px;
                    background-color: #3a86ff;
                    border-radius: 8px;
                    color: white;
                    font-size: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-right: 10px;
                }}
                h2 {{ 
                    color: #2d3748; 
                    font-weight: 600;
                    margin: 0;
                }}
                p {{ 
                    color: #64748b;
                    margin: 20px 0;
                }}
                input[type="text"] {{ 
                    padding: 12px; 
                    width: 100%; 
                    margin: 10px 0 20px; 
                    border-radius: 8px; 
                    border: 1px solid #e2e8f0; 
                    font-family: inherit;
                    font-size: 16px;
                    box-sizing: border-box;
                }}
                button {{ 
                    background-color: #3a86ff; 
                    color: white; 
                    padding: 12px 24px; 
                    border: none; 
                    border-radius: 8px; 
                    cursor: pointer; 
                    font-size: 16px;
                    font-family: inherit;
                    font-weight: 500;
                    width: 100%;
                    transition: background-color 0.2s;
                }}
                button:hover {{ 
                    background-color: #2563eb; 
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Supervisor Request</h2>
                </div>
                <p>Please enter your name so we know who is responding:</p>
                <form action="/submit_response" method="post">
                    <input type="text" name="responder_name" placeholder="Your Name" required>
                    <button type="submit">Confirm Response</button>
                </form>
            </div>
        </body>
    </html>
    """


@app.route("/submit_response", methods=["POST"])
def submit_response():
    """
    Handle form submission and record the responder's name.
    Updates global state and sends confirmation notifications.
    """
    global response_received, responder_name

    # Extract and clean responder name from form
    responder = request.form.get("responder_name", "Unknown Supervisor").strip()

    # Handle edge case of empty/whitespace-only input
    if not responder:
        responder = "Unknown Supervisor"

    responder_name = responder

    # Update global response state
    response_received = True

    # Signal GUI thread to update interface
    gui_update_event.set()

    # Send confirmation notification to all users
    send_response_notification(responder)

    # Return success page
    return f"""
    <html>
        <head>
            <title>Response Confirmed</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                /* Success page styling */
                body {{ 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    margin: 0; 
                    padding: 0; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    min-height: 100vh;
                    background-color: #f5f7fa; 
                }}
                .container {{ 
                    max-width: 600px; 
                    width: 90%;
                    margin: 20px; 
                    padding: 30px; 
                    border-radius: 12px; 
                    box-shadow: 0 8px 24px rgba(0,0,0,0.12);
                    background-color: white;
                    text-align: center;
                }}
                .header {{
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-bottom: 20px;
                }}
                .logo {{
                    width: 36px;
                    height: 36px;
                    background-color: #3a86ff;
                    border-radius: 8px;
                    color: white;
                    font-size: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-right: 10px;
                }}
                .success-icon {{
                    width: 60px;
                    height: 60px;
                    background-color: #10b981;
                    border-radius: 50%;
                    color: white;
                    font-size: 40px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 20px;
                }}
                h2 {{ 
                    color: #10b981; 
                    font-weight: 600;
                    margin: 0;
                }}
                p {{ 
                    color: #64748b;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Supervisor Request</h2>
                </div>
                <div class="success-icon">✓</div>
                <h2>Thanks, {responder}!</h2>
                <p>Your response has been received and the user has been notified that you're on your way.</p>
            </div>
        </body>
    </html>
    """


# =============================================================================
# FLASK ROUTE HANDLERS - Emergency Response System
# =============================================================================

@app.route("/respond_emergency")
def respond_emergency():
    """
    Flask route for displaying the emergency response form.

    Returns:
        str: HTML page with emergency response form interface
    """
    return f"""
    <html>
        <head>
            <title>🚨 EMERGENCY RESPONSE 🚨</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                /* Base body styling with animated gradient background */
                body {{ 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    margin: 0; 
                    padding: 0; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    min-height: 100vh;
                    background: linear-gradient(135deg, #ff4444, #ff6b6b);
                    animation: pulse 2s infinite;
                }}

                /* Pulsing background animation for urgency */
                @keyframes pulse {{
                    0% {{ background: linear-gradient(135deg, #ff4444, #ff6b6b); }}
                    50% {{ background: linear-gradient(135deg, #ff6b6b, #ff8e8e); }}
                    100% {{ background: linear-gradient(135deg, #ff4444, #ff6b6b); }}
                }}

                /* Main container styling */
                .container {{ 
                    max-width: 600px; 
                    width: 90%;
                    margin: 20px; 
                    padding: 30px; 
                    border-radius: 12px; 
                    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
                    background-color: white;
                    border: 3px solid #ff4444;
                }}

                /* Header section with icon and title */
                .header {{
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-bottom: 20px;
                }}

                /* Emergency icon with flashing animation */
                .emergency-icon {{
                    font-size: 48px;
                    margin-right: 15px;
                    animation: flash 1s infinite;
                }}

                /* Flashing animation for emergency icon */
                @keyframes flash {{
                    0%, 50% {{ opacity: 1; }}
                    51%, 100% {{ opacity: 0.3; }}
                }}

                /* Main heading styling */
                h2 {{ 
                    color: #ff4444; 
                    font-weight: 700;
                    margin: 0;
                    font-size: 24px;
                    text-align: center;
                }}

                /* Paragraph text styling */
                p {{ 
                    color: #2d3748;
                    margin: 20px 0;
                    font-weight: 600;
                    text-align: center;
                }}

                /* Text input field styling */
                input[type="text"] {{ 
                    padding: 15px; 
                    width: 100%; 
                    margin: 15px 0 25px; 
                    border-radius: 8px; 
                    border: 2px solid #ff4444; 
                    font-family: inherit;
                    font-size: 18px;
                    box-sizing: border-box;
                    font-weight: 600;
                }}

                /* Submit button styling with gradient */
                button {{ 
                    background: linear-gradient(135deg, #ff4444, #ff6b6b);
                    color: white; 
                    padding: 15px 30px; 
                    border: none; 
                    border-radius: 8px; 
                    cursor: pointer; 
                    font-size: 18px;
                    font-family: inherit;
                    font-weight: 700;
                    width: 100%;
                    transition: all 0.2s;
                    text-transform: uppercase;
                }}

                /* Button hover effects */
                button:hover {{ 
                    background: linear-gradient(135deg, #e63946, #ff4444);
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Header with emergency icon -->
                <div class="header">
                    <div class="emergency-icon">🚨</div>
                </div>

                <!-- Main title -->
                <h2>EMERGENCY RESPONSE</h2>

                <!-- Instructions -->
                <p>Enter your name to confirm you are responding to this EMERGENCY:</p>

                <!-- Emergency response form -->
                <form action="/submit_emergency_response" method="post">
                    <input type="text" name="responder_name" placeholder="Your Name" required>
                    <button type="submit">🚨 CONFIRM EMERGENCY RESPONSE 🚨</button>
                </form>
            </div>
        </body>
    </html>
    """


@app.route("/submit_emergency_response", methods=["POST"])
def submit_emergency_response():
    """
    Handle emergency response form submission and process the response.

    This route processes the form data, updates global state variables,
    triggers GUI updates, and sends notifications.

    Returns:
        str: HTML confirmation page
    """
    # Access global variables for state management
    global response_received, responder_name

    # Extract and validate responder name from form data
    responder = request.form.get("responder_name", "Unknown Supervisor").strip()
    if not responder:
        responder = "Unknown Supervisor"
    responder_name = responder

    # Update global state to indicate response received
    response_received = True
    gui_update_event.set()  # Trigger GUI update event

    # Send notification about the emergency response
    send_emergency_response_notification(responder)

    # Return confirmation page
    return f"""
    <html>
        <head>
            <title>Emergency Response Confirmed</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                /* Success page body styling */
                body {{ 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    margin: 0; 
                    padding: 0; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    min-height: 100vh;
                    background: linear-gradient(135deg, #10b981, #34d399);
                }}

                /* Success page container */
                .container {{ 
                    max-width: 600px; 
                    width: 90%;
                    margin: 20px; 
                    padding: 30px; 
                    border-radius: 12px; 
                    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
                    background-color: white;
                    text-align: center;
                    border: 3px solid #10b981;
                }}

                /* Success checkmark icon */
                .success-icon {{
                    width: 80px;
                    height: 80px;
                    background-color: #10b981;
                    border-radius: 50%;
                    color: white;
                    font-size: 50px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 20px;
                    animation: checkmark 0.6s ease-in-out;
                }}

                /* Checkmark animation */
                @keyframes checkmark {{
                    0% {{ transform: scale(0); }}
                    50% {{ transform: scale(1.2); }}
                    100% {{ transform: scale(1); }}
                }}

                /* Success page heading */
                h2 {{ 
                    color: #10b981; 
                    font-weight: 700;
                    margin: 0;
                    font-size: 24px;
                }}

                /* Success page text */
                p {{ 
                    color: #2d3748;
                    margin: 20px 0;
                    font-weight: 600;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Success checkmark icon -->
                <div class="success-icon">✓</div>

                <!-- Confirmation heading -->
                <h2>EMERGENCY RESPONSE CONFIRMED</h2>

                <!-- Confirmation message with responder name -->
                <p><strong>{responder}</strong>, your emergency response has been acknowledged. The requester has been notified that you are responding immediately.</p>
            </div>
        </body>
    </html>
    """


# =============================================================================
# FLASK SERVER MANAGEMENT
# =============================================================================

def run_flask():
    """
    Run the Flask server for handling emergency response web interface.

    Starts the Flask application on all interfaces (0.0.0.0) port 5000
    with reloader disabled to prevent conflicts in multi-threaded environment.
    """
    app.run(host="0.0.0.0", port=5000, use_reloader=False)


# =============================================================================
# GUI UTILITY FUNCTIONS
# =============================================================================

def create_status_indicator(size=12, color="#10b981"):
    """
    Create a circular status indicator dot for GUI display.

    Args:
        size (int): Diameter of the status dot in pixels
        color (str): Hex color code for the indicator

    Returns:
        ImageTk.PhotoImage: Tkinter-compatible image object
    """
    # Create transparent image with specified size
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw filled circle as status indicator
    draw.ellipse((0, 0, size, size), fill=color)

    # Convert to Tkinter PhotoImage for display
    return ImageTk.PhotoImage(img)


def create_rounded_rectangle(canvas, x1, y1, x2, y2, radius=25, **kwargs):
    """
    Create a rounded rectangle shape on a Tkinter canvas.

    Args:
        canvas: Tkinter Canvas object to draw on
        x1, y1: Top-left coordinates
        x2, y2: Bottom-right coordinates
        radius (int): Corner radius for rounding
        **kwargs: Additional canvas drawing arguments (fill, outline, etc.)

    Returns:
        int: Canvas object ID for the created shape
    """
    # Calculate points for rounded rectangle using polygon
    points = [
        x1 + radius, y1,  # Top edge start
        x2 - radius, y1,  # Top edge end
        x2, y1,  # Top-right corner start
        x2, y1 + radius,  # Top-right corner end
        x2, y2 - radius,  # Right edge start
        x2, y2,  # Right edge end
        x2 - radius, y2,  # Bottom-right corner start
        x1 + radius, y2,  # Bottom edge start
        x1, y2,  # Bottom-left corner start
        x1, y2 - radius,  # Bottom-left corner end
        x1, y1 + radius,  # Left edge start
        x1, y1  # Left edge end
    ]

    # Create smooth polygon to simulate rounded rectangle
    return canvas.create_polygon(points, smooth=True, **kwargs)


def create_gui():
    """Create the modern GUI interface"""

    # ============================================================================
    # WINDOW INITIALIZATION AND POSITIONING
    # ============================================================================
    root = tk.Tk()
    root.title("Request Supervisor")

    # Calculate window positioning for center screen placement
    window_width = 400
    window_height = 360
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)

    # Configure window properties - fixed size, centered
    root.geometry(f"{window_width}x{window_height}+{x}+{y-150}")
    root.resizable(False, False)  # Prevent resizing

    # ============================================================================
    # COLOR SCHEME DEFINITION
    # ============================================================================
    primary_color = "#3a86ff"  # Blue
    success_color = "#10b981"  # Green
    warning_color = "#f59e0b"  # Orange
    danger_color = "#ef4444"  # Red
    text_dark = "#2d3748"  # Dark text
    text_light = "#64748b"  # Light text
    bg_color = "#D4DBE1"  # Light gray background
    message_color = "#8b5cf6"  # Purple for message button

    # ============================================================================
    # BACKGROUND IMAGE HANDLING
    # ============================================================================
    bg_image = None
    try:
        # Locate background image in script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))

    #    =========================  CHANGE BACKGROUND IMAGE NAME HERE  =========================

        image_path = os.path.join(script_dir, "background.png")

        if os.path.exists(image_path):
            # Load and configure background image
            bg_image = PhotoImage(file=image_path)

            # Create canvas container for background image
            bg_canvas = tk.Canvas(root, width=400, height=400, highlightthickness=0)
            bg_canvas.pack(fill="both", expand=True)

            # Place image on canvas at top-left anchor
            bg_canvas.create_image(0, 0, image=bg_image, anchor="nw")

            # Prevent garbage collection of image reference
            root.bg_image = bg_image

            # Set canvas as main container
            main_container = bg_canvas
        else:
            # Fallback: no background image found
            print(f"Background image not found at {image_path}")
            main_container = root
            main_frame = tk.Frame(main_container, bg=bg_color)
            main_frame.pack(fill="both", expand=True)

    except Exception as e:
        # Error handling: fallback to plain background
        print(f"Error loading background image: {e}")
        main_container = root
        main_frame = tk.Frame(main_container, bg=bg_color)
        main_frame.pack(fill="both", expand=True)

    # ============================================================================
    # TTK STYLE CONFIGURATION
    # ============================================================================
    style = ttk.Style()

    # Configure frame styles
    style.configure("TFrame", background=bg_color)

    # Configure label styles with different purposes
    style.configure("TLabel", background=bg_color, foreground=text_dark, font=("Segoe UI", 11))
    style.configure("Header.TLabel", foreground=text_dark, font=("Segoe UI", 18, "bold"))
    style.configure("Status.TLabel", foreground=text_dark, font=("Segoe UI", 12, "bold"))
    style.configure("StatusLabel.TLabel", foreground=text_light, font=("Segoe UI", 10))
    style.configure("Timer.TLabel", foreground=text_light, font=("Segoe UI", 10, "bold"))
    style.configure("Footer.TLabel", foreground=text_light, font=("Segoe UI", 9))

    # Configure button styles
    style.configure("TButton", font=("Segoe UI", 11))
    style.configure("Reset.TButton", font=("Segoe UI", 10))

    # ============================================================================
    # STATUS INDICATOR CREATION
    # ============================================================================
    # Create colored status indicators for different states
    status_indicator_green = create_status_indicator(size=12, color=success_color)  # Ready state
    status_indicator_orange = create_status_indicator(size=12, color=warning_color)  # Connecting state
    status_indicator_red = create_status_indicator(size=12, color=danger_color)  # Error state

    # ============================================================================
    # MAIN UI ELEMENTS - CANVAS OBJECTS
    # ============================================================================
    # Status indicator and text (top of interface)
    status_indicator_img = main_container.create_image(20, 20, image=status_indicator_green)
    status_text = main_container.create_text(200, 40, text="  Ready to request supervisor",
                                             fill=text_dark, font=("Segoe UI", 12, "bold"))

    # Timer display (initially hidden, shown during connection)
    timer_text = main_container.create_text(200, 70, text="Response time: 0s",
                                            fill=text_light, font=("Segoe UI", 10, "bold"))
    main_container.itemconfig(timer_text, state='hidden')

    # Connection status message (initially hidden, shown during connection attempt)
    connecting_text = main_container.create_text(200, 180, text="Connecting to supervisor...",
                                                 fill=text_dark, font=("Segoe UI", 12))
    main_container.itemconfig(connecting_text, state='hidden')

    # ============================================================================
    # BUTTON EVENT HANDLERS
    # ============================================================================
    def on_call_button_click():
        """
        Handle the call supervisor button click event
        Updates UI state and initiates supervisor connection process
        """
        # Update UI to show connecting state
        main_container.itemconfig(status_indicator_img, image=status_indicator_orange)
        main_container.itemconfig(status_text, text="Connecting...")

        # Hide main action buttons during connection
        main_container.itemconfig(call_button_bg, state='hidden')
        main_container.itemconfig(call_button_text, state='hidden')
        main_container.itemconfig(message_button_bg, state='hidden')
        main_container.itemconfig(message_button_text, state='hidden')
        main_container.itemconfig(emergency_button_bg, state='hidden')
        main_container.itemconfig(emergency_button_text, state='hidden')

        # Hide button shadows
        main_container.itemconfig(call_button_shadow, state='hidden')
        main_container.itemconfig(emergency_button_shadow, state='hidden')
        main_container.itemconfig(message_button_shadow, state='hidden')

        # Show connection-related UI elements
        main_container.itemconfig(connecting_text, state='normal')
        main_container.itemconfig(timer_text, state='normal')
        main_container.itemconfig(cancel_button_bg, state='normal')
        main_container.itemconfig(cancel_button_text, state='normal')
        main_container.itemconfig(cancel_button_shadow, state='normal')

        # Force UI update before starting background process
        root.update()

        # ========================================================================
        # BACKGROUND PROCESS HANDLER
        # ========================================================================
        def call_process():
            """Background thread function to handle supervisor notification"""
            global response_received, supervisor_arrived

            # Reset global state flags
            response_received = False
            supervisor_arrived = False

            # Attempt to send notification
            success = send_notification()

            if success:
                # Start response monitoring in separate thread
                monitor_thread = threading.Thread(target=monitor_response)
                monitor_thread.daemon = True
                monitor_thread.start()
            else:
                # Handle connection failure - update UI to error state
                main_container.itemconfig(status_indicator_img, image=status_indicator_red)
                main_container.itemconfig(status_text, text="Connection failed")

                # Hide connection-related UI elements
                main_container.itemconfig(connecting_text, state='hidden')
                main_container.itemconfig(timer_text, state='hidden')

                main_container.itemconfig(cancel_button_bg, state='hidden')
                main_container.itemconfig(cancel_button_text, state='hidden')
                main_container.itemconfig(cancel_button_shadow, state='hidden')

                main_container.itemconfig(reset_button_bg, state='normal')
                main_container.itemconfig(reset_button_text, state='normal')
                main_container.itemconfig(reset_button_shadow, state='normal')

                # Signal GUI update completion
                gui_update_event.set()

        # Start background process in daemon thread
        call_thread = threading.Thread(target=call_process)
        call_thread.daemon = True
        call_thread.start()

    # ============================================================================
    # MESSAGE INPUT DIALOG FUNCTION
    # ============================================================================
    def get_message():
        """
        Opens a modal dialog window to get message input from user

        Features:
        - 20 character limit with live counter
        - Input validation and character limiting
        - Modal dialog with proper focus handling
        - Keyboard shortcuts (Enter to send, Escape to cancel)
        - Visual feedback with color-coded character counter

        Returns:
            str: User entered message (max 20 chars) or None if cancelled
        """
        result = [None]  # Use list to avoid variable scoping issues with nested functions

        # ========================================================================
        # DIALOG EVENT HANDLERS
        # ========================================================================
        def on_send():
            """Process send action - validate and close dialog"""
            message = entry.get().strip()
            if message:
                result[0] = message
                dialog.destroy()

        def on_cancel():
            """Process cancel action - close dialog without saving"""
            result[0] = None
            dialog.destroy()

        def on_text_change(*args):
            """
            Handle text input changes
            - Enforce character limit
            - Update character counter with color coding
            - Enable/disable send button based on input
            """
            current_text = text_var.get()
            char_count = len(current_text)

            # Enforce 20 character limit
            if char_count > 20:
                text_var.set(current_text[:20])
                char_count = 20

            # Update character counter display
            counter_label.config(text=f"{char_count}/20")

            # Color-code counter based on character usage
            if char_count >= 20:
                counter_label.config(fg="#dc3545")  # Red - at limit
            elif char_count >= 15:
                counter_label.config(fg="#fd7e14")  # Orange - approaching limit
            else:
                counter_label.config(fg="#28a745")  # Green - plenty of space

            # Enable send button only if there's text input
            send_button.config(state="normal" if char_count > 0 else "disabled")

        # ========================================================================
        # KEYBOARD EVENT HANDLERS
        # ========================================================================
        def on_enter(event):
            """Handle Enter key - send message if button is enabled"""
            if send_button['state'] == 'normal':
                on_send()

        def on_escape(event):
            """Handle Escape key - cancel dialog"""
            on_cancel()

        # ========================================================================
        # DIALOG WINDOW SETUP
        # ========================================================================
        # Create modal dialog window
        dialog = tk.Toplevel()
        dialog.title("Send Message")
        dialog.geometry("320x160")
        dialog.resizable(False, False)
        dialog.configure(bg="#f8f9fa")

        # Configure as modal dialog
        dialog.transient()
        dialog.grab_set()

        # Center dialog on screen
        dialog.update_idletasks()
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        x = (screen_width - 320) // 2
        y = (screen_height - 160) // 2
        dialog.geometry(f"320x160+{x}+{y}")

        # ========================================================================
        # DIALOG UI COMPONENTS
        # ========================================================================
        # Main container frame
        main_frame = tk.Frame(dialog, bg="#f8f9fa", padx=20, pady=15)
        main_frame.pack(fill="both", expand=True)
        main_frame.config(bg="#9CBECE")

        # Dialog title
        title_label = tk.Label(
            main_frame,
            text="Enter Message",
            font=("Arial", 12, "bold"),
            fg="#2c3e50",
            bg="#9CBECE"
        )
        title_label.pack(pady=(0, 12))

        # Text input setup with change tracking
        text_var = tk.StringVar()
        text_var.trace("w", on_text_change)

        # Message input field
        entry = tk.Entry(
            main_frame,
            textvariable=text_var,
            font=("Arial", 11),
            bg="white",
            fg="#2c3e50",
            insertbackground="#2c3e50",
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightcolor="#3498db",
            highlightbackground="#dee2e6",
            width=25
        )
        entry.pack(pady=(0, 6), ipady=4)
        entry.focus_set()  # Set initial focus to input field

        # Character counter display
        counter_label = tk.Label(
            main_frame,
            text="0/20",
            font=("Arial", 9),
            fg="green",
            bg="#9CBECE"
        )
        counter_label.pack(anchor="e", pady=(0, 12))

        # ========================================================================
        # DIALOG BUTTONS SETUP
        # ========================================================================
        # Button container
        button_frame = tk.Frame(main_frame, bg="#9CBECE")
        button_frame.pack()

        # Cancel button
        cancel_button = tk.Button(
            button_frame,
            text="Cancel",
            font=("Arial", 10, "bold"),
            bg="#6c757d",
            fg="white",
            relief="flat",
            bd=0,
            padx=15,
            pady=6,
            cursor="hand2",
            command=on_cancel
        )
        cancel_button.pack(side="left", padx=(0, 45))

        # Send button (initially disabled)
        send_button = tk.Button(
            button_frame,
            text="Send",
            font=("Arial", 10, "bold"),
            bg="#007bff",
            fg="white",
            relief="flat",
            bd=0,
            padx=20,
            pady=6,
            cursor="hand2",
            state="disabled",
            command=on_send
        )
        send_button.pack(side="left")

        # ========================================================================
        # KEYBOARD BINDINGS AND HOVER EFFECTS
        # ========================================================================
        # Bind keyboard shortcuts
        entry.bind('<Return>', on_enter)
        dialog.bind('<Escape>', on_escape)

        # Button hover effect handlers
        def on_hover_send(event):
            """Send button hover effect"""
            if send_button['state'] == 'normal':
                send_button.config(bg="#0056b3")  # Darker blue

        def on_leave_send(event):
            """Send button leave effect"""
            if send_button['state'] == 'normal':
                send_button.config(bg="#007bff")  # Original blue

        def on_hover_cancel(event):
            """Cancel button hover effect"""
            cancel_button.config(bg="#545b62")  # Darker gray

        def on_leave_cancel(event):
            """Cancel button leave effect"""
            cancel_button.config(bg="#6c757d")  # Original gray

        # Bind hover effects to buttons
        send_button.bind("<Enter>", on_hover_send)
        send_button.bind("<Leave>", on_leave_send)
        cancel_button.bind("<Enter>", on_hover_cancel)
        cancel_button.bind("<Leave>", on_leave_cancel)

        # Handle window close event (X button)
        dialog.protocol("WM_DELETE_WINDOW", on_cancel)

        # Wait for dialog to close before returning result
        dialog.wait_window()

        return result[0]

    # ============================================================================
    # EVENT HANDLERS - Button Click Functions
    # ============================================================================

    def on_message_button_click():
        """Handle the send message button click"""
        # Get custom message from user input dialog
        global message
        message = get_message()
        if message is None:
            return

        # Update UI to show message sending state
        main_container.itemconfig(status_indicator_img, image=status_indicator_orange)
        main_container.itemconfig(status_text, text="Sending message...")

        # Hide main action buttons during message sending
        main_container.itemconfig(call_button_bg, state='hidden')
        main_container.itemconfig(call_button_text, state='hidden')
        main_container.itemconfig(message_button_bg, state='hidden')
        main_container.itemconfig(message_button_text, state='hidden')
        main_container.itemconfig(emergency_button_bg, state='hidden')
        main_container.itemconfig(emergency_button_text, state='hidden')

        # Show status information and hide button shadows
        main_container.itemconfig(connecting_text, text=f"Sent: {message}")
        main_container.itemconfig(connecting_text, state='normal')
        main_container.itemconfig(timer_text, state='normal')
        main_container.itemconfig(cancel_button_bg, state='normal')
        main_container.itemconfig(cancel_button_text, state='normal')
        main_container.itemconfig(cancel_button_shadow, state='normal')
        main_container.itemconfig(call_button_shadow, state='hidden')
        main_container.itemconfig(emergency_button_shadow, state='hidden')
        main_container.itemconfig(message_button_shadow, state='hidden')
        root.update()

        # Handle message sending in separate thread to prevent UI blocking
        def message_process():
            global response_received, supervisor_arrived
            response_received = False  # Reset response flags
            supervisor_arrived = False

            success = send_notification(custom_message=message)
            if success:
                # Start monitoring for supervisor response
                monitor_thread = threading.Thread(target=monitor_response)
                monitor_thread.daemon = True
                monitor_thread.start()
            else:
                # Handle failed message sending - restore UI to initial state
                main_container.itemconfig(status_indicator_img, image=status_indicator_red)
                main_container.itemconfig(status_text, text="Message failed to send")
                main_container.itemconfig(connecting_text, state='hidden')
                main_container.itemconfig(timer_text, state='hidden')
                main_container.itemconfig(call_button_bg, state='hidden')
                main_container.itemconfig(call_button_text, state='hidden')
                main_container.itemconfig(message_button_bg, state='hidden')
                main_container.itemconfig(message_button_text, state='hidden')
                main_container.itemconfig(cancel_button_bg, state='hidden')
                main_container.itemconfig(cancel_button_text, state='hidden')
                main_container.itemconfig(cancel_button_shadow, state='hidden')
                main_container.itemconfig(reset_button_bg, state='normal')
                main_container.itemconfig(reset_button_text, state='normal')
                main_container.itemconfig(reset_button_shadow, state='normal')
                gui_update_event.set()

        # Start message processing thread
        message_thread = threading.Thread(target=message_process)
        message_thread.daemon = True
        message_thread.start()

    def on_arrived_button_click():
        """Handle the supervisor arrived button click"""
        global supervisor_arrived, responder_name, message
        supervisor_arrived = True

        # Update UI to show supervisor has arrived
        main_container.itemconfig(status_indicator_img, image=status_indicator_green)
        main_container.itemconfig(status_text, text="Supervisor arrived")
        main_container.itemconfig(connecting_text, text="")

        # Calculate and display total response time
        if response_start_time > 0:
            total_time = time.time() - response_start_time
            main_container.itemconfig(timer_text, text=f"Total time: {int(total_time)}s")
        else:
            total_time = 0

        # Log the supervisor response for record keeping
        log_supervisor_response(responder_name, round(total_time), message=message)

        # Hide arrived button and show reset button
        main_container.itemconfig(arrived_button_bg, state='hidden')
        main_container.itemconfig(arrived_button_text, state='hidden')
        main_container.itemconfig(arrived_button_shadow, state='hidden')
        main_container.itemconfig(reset_button_bg, state='normal')
        main_container.itemconfig(reset_button_text, state='normal')
        main_container.itemconfig(reset_button_shadow, state='normal')

    def reset_system():
        """Reset the system to initial state"""
        global response_received, responder_name, response_start_time, supervisor_arrived, message, program_restarted

        # Reset all global state variables
        program_restarted = True
        response_received = False
        responder_name = "Unknown"
        response_start_time = 0
        supervisor_arrived = False
        message = ""

        # Reset UI to initial ready state
        main_container.itemconfig(status_indicator_img, image=status_indicator_green)
        main_container.itemconfig(status_text, text="  Ready to request supervisor")

        # Hide status and timer elements
        main_container.itemconfig(connecting_text, text="Connecting to supervisor...")
        main_container.itemconfig(connecting_text, state='hidden')
        main_container.itemconfig(timer_text, state='hidden')

        # Hide action result buttons
        main_container.itemconfig(arrived_button_bg, state='hidden')
        main_container.itemconfig(arrived_button_text, state='hidden')
        main_container.itemconfig(arrived_button_shadow, state='hidden')
        main_container.itemconfig(reset_button_bg, state='hidden')
        main_container.itemconfig(reset_button_text, state='hidden')
        main_container.itemconfig(reset_button_shadow, state='hidden')
        main_container.itemconfig(cancel_button_bg, state='hidden')
        main_container.itemconfig(cancel_button_text, state='hidden')
        main_container.itemconfig(cancel_button_shadow, state='hidden')

        # Show main action buttons
        main_container.itemconfig(call_button_bg, state='normal')
        main_container.itemconfig(call_button_text, state='normal')
        main_container.itemconfig(message_button_bg, state='normal')
        main_container.itemconfig(message_button_text, state='normal')
        main_container.itemconfig(emergency_button_bg, state='normal')
        main_container.itemconfig(emergency_button_text, state='normal')

        # Show button shadows for visual depth
        main_container.itemconfig(call_button_shadow, state='normal')
        main_container.itemconfig(emergency_button_shadow, state='normal')
        main_container.itemconfig(message_button_shadow, state='normal')

    # ============================================================================
    # UI ELEMENT CREATION - Main Action Buttons
    # ============================================================================

    # Request Supervisor Button (Call Button)
    call_button_shadow = create_rounded_rectangle(main_container, 132, 104 - 15, 272, 164 - 15, radius=25,
                                                  fill="#444444")
    call_button_bg = create_rounded_rectangle(main_container, 130, 100 - 15, 270, 160 - 15, radius=25,
                                              fill=primary_color, outline="")
    call_button_text = main_container.create_text(200, 130 - 15, text="Request",
                                                  fill="white", font=('Segoe UI', 12, "bold"))

    # Send Custom Message Button
    message_button_shadow = create_rounded_rectangle(main_container, 132, 174 - 15, 272, 234 - 15, radius=25,
                                                     fill="#444444")
    message_button_bg = create_rounded_rectangle(main_container, 130, 170 - 15, 270, 230 - 15, radius=25,
                                                 fill=message_color, outline="")
    message_button_text = main_container.create_text(200, 200 - 15, text="Send Message",
                                                     fill="white", font=('Segoe UI', 12, "bold"))

    # Emergency Alert Button
    emergency_button_shadow = create_rounded_rectangle(main_container, 132, 244 - 15, 272, 304 - 15, radius=25,
                                                       fill="#444444")
    emergency_button_bg = create_rounded_rectangle(main_container, 130, 240 - 15, 270, 300 - 15, radius=25,
                                                   fill="#ef4444", outline="")
    emergency_button_text = main_container.create_text(200, 270 - 15, text="🚨EMERGENCY🚨",
                                                       fill="white", font=('Segoe UI', 11, "bold"))

    # ============================================================================
    # SETTINGS COGWHEEL - Image Loading and Hover Effects
    # ============================================================================

    # Load and prepare settings cogwheel images
    settings_script_dir = os.path.dirname(os.path.abspath(__file__))
    settings_image_path = os.path.join(settings_script_dir, "cogwheel.png")
    settings_image = Image.open(settings_image_path).convert("RGBA")

    # Create shadow effect
    def create_shadow(image, offset=(3, 3), blur_radius=2, shadow_color=(0, 0, 0, 100)):
        """Create a shadow effect for an image"""
        # Create shadow by making a copy and filling with shadow color
        shadow = Image.new("RGBA", image.size, (0, 0, 0, 0))

        # Create shadow mask from the alpha channel of the original image
        shadow_mask = image.split()[-1]  # Get alpha channel

        # Create shadow with specified color
        shadow_layer = Image.new("RGBA", image.size, shadow_color)
        shadow.paste(shadow_layer, mask=shadow_mask)

        # Optional: Apply blur to shadow (requires PIL >= 10.0.0)
        try:
            from PIL import ImageFilter
            shadow = shadow.filter(ImageFilter.GaussianBlur(radius=blur_radius))
        except:
            pass  # Skip blur if not available

        # Create final image with shadow offset
        final_size = (image.size[0] + abs(offset[0]), image.size[1] + abs(offset[1]))
        final_image = Image.new("RGBA", final_size, (0, 0, 0, 0))

        # Paste shadow first (behind)
        shadow_pos = (max(0, offset[0]), max(0, offset[1]))
        final_image.paste(shadow, shadow_pos, shadow)

        # Paste original image on top
        image_pos = (max(0, -offset[0]), max(0, -offset[1]))
        final_image.paste(image, image_pos, image)

        return final_image

    # Create images with shadow (darker shadow)
    settings_image_with_shadow = create_shadow(settings_image, offset=(4, 4), blur_radius=3,
                                               shadow_color=(0, 0, 0, 180))
    hover_image = settings_image.point(lambda p: min(255, int(p * 0.6)))  # Brighten for hover effect
    hover_image_with_shadow = create_shadow(hover_image, offset=(4, 4), blur_radius=3, shadow_color=(0, 0, 0, 180))

    # Convert to PhotoImage
    photo_normal = ImageTk.PhotoImage(settings_image_with_shadow)
    photo_hover = ImageTk.PhotoImage(hover_image_with_shadow)

    # Create cogwheel image on canvas
    cogwheel_id = bg_canvas.create_image(360, 320, image=photo_normal, anchor="center")

    # Prevent garbage collection of images
    bg_canvas.photo_normal = photo_normal
    bg_canvas.photo_hover = photo_hover

    # Cogwheel hover effect handlers
    def on_hover(event):
        bg_canvas.itemconfig(cogwheel_id, image=photo_hover)

    def on_leave(event):
        bg_canvas.itemconfig(cogwheel_id, image=photo_normal)

    def on_click(event):
        open_settings_window(root)

    # Bind cogwheel events
    bg_canvas.tag_bind(cogwheel_id, "<Enter>", on_hover)
    bg_canvas.tag_bind(cogwheel_id, "<Leave>", on_leave)
    bg_canvas.tag_bind(cogwheel_id, "<Button-1>", on_click)

    # ============================================================================
    # BUTTON EVENT BINDING - Click Handlers and Hover Effects
    # ============================================================================

    # Request Button (Call Button) Events
    def on_call_click(event):
        on_call_button_click()

    def on_call_enter(event):
        main_container.itemconfig(call_button_bg, fill="#2F6FDA")

    def on_call_leave(event):
        main_container.itemconfig(call_button_bg, fill=primary_color)

    # Bind call button events
    main_container.tag_bind(call_button_bg, "<Button-1>", on_call_click)
    main_container.tag_bind(call_button_text, "<Button-1>", on_call_click)
    main_container.tag_bind(call_button_bg, "<Enter>", on_call_enter)
    main_container.tag_bind(call_button_bg, "<Leave>", on_call_leave)
    main_container.tag_bind(call_button_text, "<Enter>", on_call_enter)
    main_container.tag_bind(call_button_text, "<Leave>", on_call_leave)

    # Message Button Events
    def on_message_click(event):
        on_message_button_click()

    def on_message_enter(event):
        main_container.itemconfig(message_button_bg, fill="#7B4CE2")

    def on_message_leave(event):
        main_container.itemconfig(message_button_bg, fill=message_color)

    # Bind message button events
    main_container.tag_bind(message_button_bg, "<Button-1>", on_message_click)
    main_container.tag_bind(message_button_text, "<Button-1>", on_message_click)
    main_container.tag_bind(message_button_bg, "<Enter>", on_message_enter)
    main_container.tag_bind(message_button_bg, "<Leave>", on_message_leave)
    main_container.tag_bind(message_button_text, "<Enter>", on_message_enter)
    main_container.tag_bind(message_button_text, "<Leave>", on_message_leave)

    # ============================================================================
    # EMERGENCY FUNCTIONALITY - Confirmation Dialog and Event Handlers
    # ============================================================================

    def show_emergency_confirmation():
        """Display confirmation dialog for emergency button"""

        def on_confirm():
            result[0] = True
            popup.destroy()

        def on_cancel():
            result[0] = False
            popup.destroy()

        # Use mutable type to store result from nested functions
        result = [None]

        # Create confirmation popup window
        popup = tk.Toplevel()
        popup.title("Emergency Confirmation")
        popup.geometry("360x280")
        popup.configure(bg="#9CBECE")
        popup.resizable(False, False)
        popup.withdraw()

        # Center popup on screen
        popup.update_idletasks()
        x = (popup.winfo_screenwidth() - popup.winfo_width()) // 2
        y = (popup.winfo_screenheight() - popup.winfo_height()) // 2
        popup.geometry(f"+{x}+{y}")
        popup.deiconify()

        # Warning icon and title
        icon_label = tk.Label(popup, text="⚠️ WARNING ⚠️", font=("Segoe UI", 18, "bold"),
                              bg="#9CBECE", fg="#D32F2F")
        icon_label.pack(pady=(20, 10))

        # Warning message text
        message = (
            "This will send a HIGH PRIORITY emergency notification to ALL supervisors.\n\n"
            "Only use this for genuine emergencies!\n\n"
            "Are you sure you want to continue?"
        )
        message_label = tk.Label(popup, text=message, font=("Segoe UI", 11), bg="#9CBECE",
                                 fg="#333333", wraplength=360, justify="center")
        message_label.pack(pady=(0, 20))

        # Confirmation buttons
        button_frame = tk.Frame(popup, bg="#9CBECE")
        button_frame.pack()

        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 10), padding=8, background="#7ba7b7")

        yes_btn = ttk.Button(button_frame, text="Yes, Send Emergency", command=on_confirm)
        yes_btn.grid(row=0, column=0, padx=10)

        cancel_btn = ttk.Button(button_frame, text="Cancel", command=on_cancel)
        cancel_btn.grid(row=0, column=1, padx=10)

        # Make popup modal and wait for user response
        popup.grab_set()
        popup.wait_window()

        return result[0]

    def on_emergency_button_click():
        global program_restarted

        #Handle the emergency button click with confirmation
        # Show confirmation dialog first
        confirm = show_emergency_confirmation()
        if not confirm:
            return

        program_restarted = False
        # Update UI for emergency state
        main_container.itemconfig(status_indicator_img, image=status_indicator_red)
        main_container.itemconfig(status_text, text="🚨 EMERGENCY - Notifying supervisors")

        # Hide all main action buttons during emergency
        main_container.itemconfig(call_button_bg, state='hidden')
        main_container.itemconfig(call_button_text, state='hidden')
        main_container.itemconfig(message_button_bg, state='hidden')
        main_container.itemconfig(message_button_text, state='hidden')
        main_container.itemconfig(emergency_button_bg, state='hidden')
        main_container.itemconfig(emergency_button_text, state='hidden')

        # Show emergency status and hide button shadows
        main_container.itemconfig(connecting_text, text="EMERGENCY ALERT SENT")
        main_container.itemconfig(connecting_text, state='normal')
        main_container.itemconfig(timer_text, state='normal')
        main_container.itemconfig(call_button_shadow, state='hidden')
        main_container.itemconfig(emergency_button_shadow, state='hidden')
        main_container.itemconfig(message_button_shadow, state='hidden')
        main_container.itemconfig(cancel_button_bg, state='normal')
        main_container.itemconfig(cancel_button_text, state='normal')
        main_container.itemconfig(cancel_button_shadow, state='normal')

        # Add flashing effect to emphasize emergency status
        def flash_emergency_status():
            if program_restarted:
                main_container.itemconfig(status_text, fill=text_dark)
                return
            current_color = main_container.itemcget(status_text, "fill")
            new_color = "#ef4444" if current_color != "#ef4444" else "#2d3748"
            main_container.itemconfig(status_text, fill=new_color)
            if not response_received:
                root.after(500, flash_emergency_status)


        flash_emergency_status()
        root.update()

        # Handle emergency notification in separate thread
        def emergency_process():
            global response_received, supervisor_arrived, message, program_restarted
            response_received = False
            supervisor_arrived = False
            message = "EMERGENCY"

            success = send_emergency_notification()
            if success:
                # Start monitoring for emergency response
                monitor_thread = threading.Thread(target=monitor_response)
                monitor_thread.daemon = True
                monitor_thread.start()
            else:
                # Handle failed emergency notification - restore UI
                program_restarted = True
                main_container.itemconfig(status_indicator_img, image=status_indicator_red)
                main_container.itemconfig(status_text, text="Emergency notification failed")
                main_container.itemconfig(connecting_text, state='hidden')
                main_container.itemconfig(timer_text, state='hidden')
                main_container.itemconfig(call_button_bg, state='hidden')
                main_container.itemconfig(call_button_text, state='hidden')
                main_container.itemconfig(message_button_bg, state='hidden')
                main_container.itemconfig(message_button_text, state='hidden')
                main_container.itemconfig(emergency_button_bg, state='hidden')
                main_container.itemconfig(emergency_button_text, state='hidden')
                main_container.itemconfig(cancel_button_bg, state='hidden')
                main_container.itemconfig(cancel_button_text, state='hidden')
                main_container.itemconfig(cancel_button_shadow, state='hidden')
                main_container.itemconfig(reset_button_bg, state='normal')
                main_container.itemconfig(reset_button_text, state='normal')
                main_container.itemconfig(reset_button_shadow, state='normal')
                gui_update_event.set()

        # Start emergency processing thread
        emergency_thread = threading.Thread(target=emergency_process)
        emergency_thread.daemon = True
        emergency_thread.start()

    # Emergency Button Events
    def on_emergency_click(event):
        on_emergency_button_click()

    def on_emergency_enter(event):
        main_container.itemconfig(emergency_button_bg, fill="#dc2626")

    def on_emergency_leave(event):
        main_container.itemconfig(emergency_button_bg, fill="#ef4444")

    # Bind emergency button events
    main_container.tag_bind(emergency_button_bg, "<Button-1>", on_emergency_click)
    main_container.tag_bind(emergency_button_text, "<Button-1>", on_emergency_click)
    main_container.tag_bind(emergency_button_bg, "<Enter>", on_emergency_enter)
    main_container.tag_bind(emergency_button_bg, "<Leave>", on_emergency_leave)
    main_container.tag_bind(emergency_button_text, "<Enter>", on_emergency_enter)
    main_container.tag_bind(emergency_button_text, "<Leave>", on_emergency_leave)

    # ============================================================================
    # RESPONSE BUTTONS - Supervisor Arrived and Reset Functionality
    # ============================================================================

    # Supervisor Arrived Button (initially hidden)
    arrived_button_shadow = create_rounded_rectangle(main_container, 112, 224, 292, 284, radius=20,
                                                     fill="#444444")
    arrived_button_bg = create_rounded_rectangle(main_container, 110, 220, 290, 280, radius=20,
                                                 fill=success_color, outline="")
    arrived_button_text = main_container.create_text(200, 250, text="Supervisor Arrived",
                                                     fill="white", font=('Segoe UI', 14, "bold"))
    main_container.itemconfig(arrived_button_bg, state='hidden')
    main_container.itemconfig(arrived_button_text, state='hidden')
    main_container.itemconfig(arrived_button_shadow, state='hidden')

    # Arrived Button Events
    def on_arrived_click(event):
        on_arrived_button_click()

    def on_arrived_enter(event):
        main_container.itemconfig(arrived_button_bg, fill="#0d9669")

    def on_arrived_leave(event):
        main_container.itemconfig(arrived_button_bg, fill=success_color)

    # Bind arrived button events
    main_container.tag_bind(arrived_button_bg, "<Button-1>", on_arrived_click)
    main_container.tag_bind(arrived_button_text, "<Button-1>", on_arrived_click)
    main_container.tag_bind(arrived_button_bg, "<Enter>", on_arrived_enter)
    main_container.tag_bind(arrived_button_bg, "<Leave>", on_arrived_leave)
    main_container.tag_bind(arrived_button_text, "<Enter>", on_arrived_enter)
    main_container.tag_bind(arrived_button_text, "<Leave>", on_arrived_leave)

    # Reset Button (initially hidden)
    reset_button_shadow = create_rounded_rectangle(main_container, 112, 224, 292, 284, radius=20,
                                                   fill="#444444")
    reset_button_bg = create_rounded_rectangle(main_container, 110, 220, 290, 280, radius=20,
                                               fill=text_light, outline="")
    reset_button_text = main_container.create_text(200, 250, text="Reset",
                                                   fill="white", font=('Segoe UI', 14, "bold"))
    main_container.itemconfig(reset_button_bg, state='hidden')
    main_container.itemconfig(reset_button_text, state='hidden')
    main_container.itemconfig(reset_button_shadow, state='hidden')

    # Cancel Button (initially hidden)
    cancel_button_shadow = create_rounded_rectangle(main_container, 112, 224, 292, 284, radius=20,
                                                   fill="#444444")
    cancel_button_bg = create_rounded_rectangle(main_container, 110, 220, 290, 280, radius=20,
                                               fill=text_light, outline="")
    cancel_button_text = main_container.create_text(200, 250, text="Cancel",
                                                   fill="white", font=('Segoe UI', 14, "bold"))
    main_container.itemconfig(cancel_button_bg, state='hidden')
    main_container.itemconfig(cancel_button_text, state='hidden')
    main_container.itemconfig(cancel_button_shadow, state='hidden')

    # Reset Button Shadow

    ## Confirmation Function for canceling a request
    def show_cancel_confirmation():
        """Display confirmation dialog for cancel button"""

        def on_confirm():
            result[0] = True
            popup.destroy()

        def on_cancel():
            result[0] = False
            popup.destroy()

        # Use mutable type to store result from nested functions
        result = [None]

        # Create confirmation popup window
        popup = tk.Toplevel()
        popup.title("Cancel Confirmation")
        popup.geometry("370x240")
        popup.configure(bg="#9CBECE")
        popup.resizable(False, False)

        # Hide window initially to prevent flash
        popup.withdraw()

        # Center popup on screen
        popup.update_idletasks()
        x = (popup.winfo_screenwidth() - popup.winfo_width()) // 2
        y = (popup.winfo_screenheight() - popup.winfo_height()) // 2
        popup.geometry(f"+{x}+{y}")

        # Show window after positioning
        popup.deiconify()

        # Warning icon and title
        icon_label = tk.Label(popup, text="⚠️ WARNING ⚠️", font=("Segoe UI", 18, "bold"),
                              bg="#9CBECE", fg="#D32F2F")
        icon_label.pack(pady=(20, 10))

        # Warning message text
        message = (
            "This will cancel the current operation and all supervisors will be notified of a false alarm.\n\n"
            "Are you sure you want to proceed?"
        )
        message_label = tk.Label(popup, text=message, font=("Segoe UI", 11), bg="#9CBECE",
                                 fg="#333333", wraplength=360, justify="center")
        message_label.pack(pady=(0, 20))

        # Confirmation buttons
        button_frame = tk.Frame(popup, bg="#9CBECE")
        button_frame.pack()

        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 10), padding=8, background="#7ba7b7")

        yes_btn = ttk.Button(button_frame, text="Yes, Cancel", command=on_confirm)
        yes_btn.grid(row=0, column=0, padx=10)

        cancel_btn = ttk.Button(button_frame, text="No, Continue", command=on_cancel)
        cancel_btn.grid(row=0, column=1, padx=10)

        # Make popup modal and wait for user response
        popup.grab_set()
        popup.wait_window()

        return result[0]



    # Cancel Button Events
    def on_cancel_click(event):
        user_confirmation = show_cancel_confirmation()
        if user_confirmation:
            send_cancel_notification()
            reset_system()

    def on_cancel_enter(event):
        main_container.itemconfig(cancel_button_bg, fill="#4b5563")

    def on_cancel_leave(event):
        main_container.itemconfig(cancel_button_bg, fill=text_light)

    # Reset Button Events
    def on_reset_click(event):
        reset_system()

    def on_reset_enter(event):
        main_container.itemconfig(reset_button_bg, fill="#4b5563")

    def on_reset_leave(event):
        main_container.itemconfig(reset_button_bg, fill=text_light)

    # Bind reset button events
    main_container.tag_bind(reset_button_bg, "<Button-1>", on_reset_click)
    main_container.tag_bind(reset_button_text, "<Button-1>", on_reset_click)
    main_container.tag_bind(reset_button_bg, "<Enter>", on_reset_enter)
    main_container.tag_bind(reset_button_bg, "<Leave>", on_reset_leave)
    main_container.tag_bind(reset_button_text, "<Enter>", on_reset_enter)
    main_container.tag_bind(reset_button_text, "<Leave>", on_reset_leave)

    # Bind cancel button events
    main_container.tag_bind(cancel_button_bg, "<Button-1>", on_cancel_click)
    main_container.tag_bind(cancel_button_text, "<Button-1>", on_cancel_click)
    main_container.tag_bind(cancel_button_bg, "<Enter>", on_cancel_enter)
    main_container.tag_bind(cancel_button_bg, "<Leave>", on_cancel_leave)
    main_container.tag_bind(cancel_button_text, "<Enter>", on_cancel_enter)
    main_container.tag_bind(cancel_button_text, "<Leave>", on_cancel_leave)

    # ============================================================================
    # TIMER AND STATUS MONITORING - Background Tasks
    # ============================================================================

    def update_timer():
        """Update the elapsed time display every second"""
        global response_start_time
        if response_start_time > 0 and not supervisor_arrived:
            elapsed = time.time() - response_start_time
            main_container.itemconfig(timer_text, text=f"Time elapsed: {int(elapsed)}s")

        # Schedule next timer update
        root.after(1000, update_timer)

    def check_status():
        """Monitor response status and update UI accordingly"""
        if response_received and not supervisor_arrived:
            # Supervisor has responded but not yet arrived
            main_container.itemconfig(status_indicator_img, image=status_indicator_orange)
            main_container.itemconfig(status_text, text="Supervisor is on the way")
            main_container.itemconfig(connecting_text, text=f"{responder_name} is responding!")

            # Hide reset button and show arrived button
            main_container.itemconfig(reset_button_bg, state='hidden')
            main_container.itemconfig(reset_button_text, state='hidden')
            main_container.itemconfig(reset_button_shadow, state='hidden')
            main_container.itemconfig(cancel_button_bg, state='hidden')
            main_container.itemconfig(cancel_button_text, state='hidden')
            main_container.itemconfig(cancel_button_shadow, state='hidden')
            main_container.itemconfig(arrived_button_bg, state='normal')
            main_container.itemconfig(arrived_button_text, state='normal')
            main_container.itemconfig(arrived_button_shadow, state='normal')

        elif supervisor_arrived:
            # Status already handled by arrived button click handler
            pass
        elif main_container.itemcget(status_text, "text") in ["Connecting...", "Sending message..."]:
            # Still waiting for response, no changes needed
            pass

        # Reset the GUI update event flag
        gui_update_event.clear()

        # Schedule next status check
        root.after(500, lambda: check_status_or_wait(root))

    def check_status_or_wait(root):
        """Check if GUI update is needed or schedule next check"""
        if gui_update_event.is_set():
            check_status()
        else:
            # Schedule another check if no update event
            root.after(500, lambda: check_status_or_wait(root))

    # ============================================================================
    # INITIALIZATION - Start Background Tasks and Prevent Garbage Collection
    # ============================================================================

    # Start the timer update function
    update_timer()

    # Start status monitoring
    check_status()

    # Prevent garbage collection of status indicator images
    root.status_indicator_green = status_indicator_green
    root.status_indicator_orange = status_indicator_orange
    root.status_indicator_red = status_indicator_red

    return root


# ============================================================================
# MAIN EXECUTION - Application Startup
# ============================================================================

if __name__ == "__main__":
    # Load application settings from configuration file
    settings = load_settings()
    # Extract supervisor keys from the new format
    supervisors = settings.get("supervisors", [])
    PUSHOVER_USER_KEYS = [supervisor["key"] for supervisor in supervisors if supervisor["key"]]
    SHARED_LOG_PATH = settings["log_file_path"]

    # Start Flask web server in background thread for API communication
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Create and start the main GUI application
    root = create_gui()
    root.mainloop()