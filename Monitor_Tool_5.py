from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json
import os
import socket

app = Flask(__name__, template_folder=r'C:\Users\Soudwip\PycharmProjects\pythonProject1\Template')
app.secret_key = 'your_secret_key'  # Needed for session management

# Path to the JSON file for storing device data
DEVICE_STATUS_FILE = 'device_status.json'

# Default username and password
DEFAULT_USERNAME = "ptl"
DEFAULT_PASSWORD = "ptl"

# In-memory storage for users and AD servers (for demonstration purposes)
local_users = {}
ad_servers = []


def load_device_status():
    if os.path.exists(DEVICE_STATUS_FILE):
        with open(DEVICE_STATUS_FILE, 'r') as file:
            return json.load(file)
    return []


def save_device_status(device_status):
    with open(DEVICE_STATUS_FILE, 'w') as file:
        json.dump(device_status, file)


# Load initial device status from the JSON file
device_status = load_device_status()


# Function to check the status of the devices
def check_device_status():
    for device in device_status:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Set timeout to 1 second
            result = sock.connect_ex((device['ip_or_hostname'], device['port_number']))
            if result == 0:
                device['status'] = 'online'
            else:
                device['status'] = 'offline'
            sock.close()
        except Exception as e:
            device['status'] = 'offline'
            print(f"Error checking status for {device['device_name']}: {e}")
    save_device_status(device_status)


# Sample function to simulate AD server communication
def is_ad_server_reachable(ip, auth_method):
    # Simulate a reachability check (replace with actual logic)
    return True if auth_method.lower() in ['ldap', 'kerberos'] else False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
        session['logged_in'] = True
        # Redirect to the welcome page after successful login
        return redirect(url_for('welcome'))
    elif username in local_users and local_users[username] == password:
        session['logged_in'] = True
        return redirect(url_for('welcome'))
    else:
        # Display error message if username or password is incorrect
        return "Invalid username or password."


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))


@app.route('/welcome')
def welcome():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html')


@app.route('/monitor_device')
def monitor_device():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    # Check device status before rendering the template
    check_device_status()
    return render_template('dashboard.html', device_status=device_status)


@app.route('/add_device', methods=['POST'])
def add_device_route():
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    # Retrieve device details from the form
    device_name = request.form['device_name']
    ip_or_hostname = request.form['ip_or_hostname']
    port_number = int(request.form['port_number'])
    transport = request.form['transport']

    # Check for duplicate device
    for device in device_status:
        if device['device_name'] == device_name or (
                device['ip_or_hostname'] == ip_or_hostname and device['port_number'] == port_number):
            return "Device with the same name or IP/Hostname and port number already exists."

    # Add the new device to the device_status list
    device_status.append({
        "device_name": device_name,
        "ip_or_hostname": ip_or_hostname,
        "port_number": port_number,
        "transport": transport,
        "status": "offline"  # Default to offline, will be checked on next refresh
    })

    # Save the updated device status to the JSON file
    save_device_status(device_status)

    # Redirect back to the monitor_device page
    return redirect(url_for('monitor_device'))


@app.route('/delete_device/<device_name>', methods=['POST'])
def delete_device_route(device_name):
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    global device_status
    device_status = [device for device in device_status if device['device_name'] != device_name]
    save_device_status(device_status)
    return redirect(url_for('monitor_device'))


@app.route('/set_theme', methods=['POST'])
def set_theme():
    theme = request.json['theme']
    session['theme'] = theme
    return jsonify(success=True)


@app.route('/create_local_user', methods=['POST'])
def create_local_user():
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    username = request.form['username']
    password = request.form['password']

    if username in local_users:
        return jsonify({'status': 'error', 'message': 'Username already exists.'})
    else:
        local_users[username] = password
        return jsonify({'status': 'success', 'message': 'Local user successfully created.'})


@app.route('/add_ad_server', methods=['POST'])
def add_ad_server():
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    ad_server = request.form['ad_server']
    auth_method = request.form['auth_method']
    reachable = is_ad_server_reachable(ad_server, auth_method)
    status = 'Online' if reachable else 'Offline'

    ad_servers.append({'ad_server': ad_server, 'auth_method': auth_method, 'status': status})
    return jsonify({'status': 'success', 'message': 'AD server added successfully.', 'ad_server': ad_server,
                    'auth_method': auth_method, 'status': status})


if __name__ == '__main__':
    app.run(debug=True)
