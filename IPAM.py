from pywebio import start_server, config
from pywebio.input import *
from pywebio.output import *
from pywebio.session import go_app
import socket
import os
import datetime
import pytz

# Sample data for demonstration
devices = [
    {"name": "Device1", "ip_hostname": "192.168.1.2", "port": "22", "transport": "TCP"},
    {"name": "Device2", "ip_hostname": "example.com", "port": "80", "transport": "UDP"}
]

# Sample data for local users
local_users = [{"username": "ptl", "password": "ptl"}]

# Sample data for AD servers
ad_servers = [{"ip_hostname": "ad.example.com", "authentication": "LDAP", "status": "Checking..."}]

# Initialize global variables
hostname = "DefaultHostname"
selected_timezone = "UTC"
gmt_offset = "+00:00"
ntp_server = "pool.ntp.org"

# Function to check device reachability
def check_reachability(ip_hostname, transport):
    if transport == "TCP":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif transport == "UDP":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        return "Unknown", "gray"

    s.settimeout(1)

    try:
        s.connect((ip_hostname, 80))
        return "Online", "green"
    except Exception as e:
        return f"Offline ({e})", "red"
    finally:
        s.close()

# Initialize global variable to track login state
logged_in = False

# Login function
def login():
    global logged_in
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('Welcome to the PTL')

    # Check if already logged in
    if logged_in:
        put_text("Already logged in!")
        go_app('dashboard', new_window=False)
        return

    data = input_group("Login", [
        input("Enter your username:", name='username', type=TEXT),
        input("Enter your password:", name='password', type=PASSWORD)
    ])

    username = data['username']
    password = data['password']

    if any(user['username'] == username and user['password'] == password for user in local_users):
        put_text("Login successful!")
        logged_in = True  # Set login state to True
        go_app('dashboard', new_window=False)
    else:
        put_text("Invalid username or password. Please try again.")

# Dashboard function


def logout():
    global logged_in
    logged_in = False
    go_app('login', new_window=False)

# Function to handle logo upload
def upload_logo():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('## Upload Logo')

    file_info = file_upload(label="Upload Logo File", accept="image/*")
    if file_info is None:
        put_error("No file uploaded. Please upload a file.")
        return

    filename = file_info['filename']
    file_path = os.path.join('uploads', filename)

    # Create the 'uploads' directory if it doesn't exist
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    # Save the uploaded logo file
    with open(file_path, 'wb') as f:
        f.write(file_info['content'])

    put_success(f"Logo uploaded successfully to {file_path}!")

# Function to handle device monitoring
def monitor_device():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# Monitor Device')

    # Display hostname
    put_markdown(f"Hostname: {hostname}")

    # Display device table
    device_rows = []
    for device in devices:
        status, color = check_reachability(device["ip_hostname"], device["transport"])
        device_rows.append([
            device["name"],
            device["ip_hostname"],
            device["port"],
            device["transport"],
            put_markdown(f"<span style='color:{color}'>{status}</span>"),
            put_buttons(["Delete"], onclick=[lambda d=device: delete_device(d)]),
            put_buttons(["SSH"], onclick=[lambda d=device: ssh_to_device(d)]),
            put_buttons(["Pin"], onclick=[lambda d=device: pin_device(d)])  # Add Pin button
        ])

    # Display add device button
    put_buttons(['Add Device'], onclick=[add_device])

    put_table([
        ["Device Name", "IP/Hostname", "Port Number", "Transport", "Status", "Action", "SSH", "Pin"],
        *device_rows
    ])

# Function to display devices in the SNMP tab
def snmp_monitoring():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# SNMP Monitoring')

    # Display device table
    device_rows = []
    for device in devices:
        device_rows.append([
            device["name"],
            device["ip_hostname"],
            device["port"],
            device["transport"],
            put_buttons(["Pin"], onclick=[lambda d=device: pin_device(d)])  # Add Pin button
        ])

    put_table([
        ["Device Name", "IP/Hostname", "Port Number", "Transport", "Pin"],
        *device_rows
    ])

# Function to pin a device
def pin_device(device):
    global pinned_device
    pinned_device = device
    # Update the dashboard to show the graphs for the pinned device
    dashboard()

def add_device():
    data = input_group("Add Device", [
        input("Device Name", name="name"),
        input("IP or Hostname", name="ip_hostname"),
        input("Port Number", name="port"),
        select("Transport", ["TCP", "UDP"], name="transport"),
    ])
    devices.append(data)
    monitor_device()

def delete_device(device):
    global devices
    devices = [d for d in devices if d != device]
    monitor_device()

# Function to handle settings
def settings():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)

    put_markdown('# Settings')

    global hostname, selected_timezone, gmt_offset, ntp_server  # Access global variables

    # Hostname configuration
    hostname = input("Enter the hostname:", type=TEXT, value=hostname)

    # Time synchronization method
    time_sync_method = select("Select Time Synchronization Method:", options=["NTP", "Manual"])

    if time_sync_method == "Manual":
        selected_timezone = select("Select Timezone:", options=pytz.all_timezones, value=selected_timezone)
        timezone = pytz.timezone(selected_timezone)
        gmt_offset = timezone.utcoffset(datetime.datetime.now()).total_seconds() / 3600
        hours = int(gmt_offset)
        minutes = int((gmt_offset - hours) * 60)
        gmt_offset = f"{hours:+03d}:{minutes:02d}"
    else:
        ntp_server = input("Enter NTP Server Address:", type=TEXT, value=ntp_server)

    put_text(f"Hostname: {hostname}")
    put_text(f"Selected Timezone: {selected_timezone} (GMT Offset: {gmt_offset})")
    put_text(f"NTP Server: {ntp_server}")

def snmp_monitoring():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# SNMP Monitoring')

    # Add input fields for SNMP parameters
    version = select("Select SNMP Version:", options=["SNMPv2c", "SNMPv3"])
    community = ""
    username = ""
    auth_protocol = ""
    auth_key = ""
    priv_protocol = ""
    priv_key = ""
    ip_address = input("Enter IP address of the device:", type=TEXT)

    # Additional input fields for CPU, memory, and bandwidth OIDs
    cpu_oid = input("Enter CPU OID:", type=TEXT)
    memory_oid = input("Enter Memory OID:", type=TEXT)
    bandwidth_oid = input("Enter Bandwidth OID:", type=TEXT)

    if version == "SNMPv2c":
        community = input("Enter SNMP community string:", type=TEXT)
    elif version == "SNMPv3":
        username = input("Enter SNMPv3 username:", type=TEXT)
        auth_protocol = select("Select Authentication Protocol:", options=["MD5", "SHA"])
        auth_key = input("Enter Authentication Key:", type=PASSWORD)
        priv_protocol = select("Select Privacy Protocol:", options=["DES", "AES"])
        priv_key = input("Enter Privacy Key:", type=PASSWORD)

    # SNMP get request for CPU utilization
    cpu_utilization = perform_snmp_get(ip_address, version, community, username, auth_protocol, auth_key, priv_protocol, priv_key, cpu_oid)

    # SNMP get request for memory utilization
    memory_utilization = perform_snmp_get(ip_address, version, community, username, auth_protocol, auth_key, priv_protocol, priv_key, memory_oid)

    # SNMP get request for bandwidth utilization
    bandwidth_utilization = perform_snmp_get(ip_address, version, community, username, auth_protocol, auth_key, priv_protocol, priv_key, bandwidth_oid)

    # Display the results
    put_markdown(f"CPU Utilization: {cpu_utilization}")
    put_markdown(f"Memory Utilization: {memory_utilization}")
    put_markdown(f"Bandwidth Utilization: {bandwidth_utilization}")

# Function to perform SNMP GET request
def perform_snmp_get(ip_address, version, community, username, auth_protocol, auth_key, priv_protocol, priv_key, oid):
    # Perform SNMP GET request based on the specified version and parameters
    # Return the SNMP response
    return "Sample Response"

# Function to handle authentication settings
def authentication():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# Authentication')

    global local_users, ad_servers

    # Display local users table
    local_user_rows = []
    for user in local_users:
        local_user_rows.append([
            user["username"],
            user["password"],
            put_buttons(["Delete"], onclick=[lambda u=user: delete_local_user(u)])
        ])

    put_buttons(['Add Local User'], onclick=[add_local_user])
    put_table([
        ["Username", "Password", "Action"],
        *local_user_rows
    ])

    # Display AD server table
    ad_server_rows = []
    for server in ad_servers:
        ad_server_rows.append([
            server["ip_hostname"],
            server["authentication"],
            put_markdown(f"<span id='{server['ip_hostname']}_status'>{server['status']}</span>"),
            put_buttons(["Delete"], onclick=[lambda s=server: delete_ad_server(s)])
        ])

    put_buttons(['Add AD Server'], onclick=[add_ad_server])
    put_table([
        ["AD Server IP/Hostname", "Authentication", "Status", "Action"],
        *ad_server_rows
    ])

def add_local_user():
    global local_users
    data = input_group("Add Local User", [
        input("Username", name="username"),
        input("Password", name="password", type=PASSWORD)
    ])
    local_users.append(data)
    authentication()

def delete_local_user(user):
    global local_users
    local_users = [u for u in local_users if u != user]
    authentication()

def add_ad_server():
    global ad_servers
    data = input_group("Add AD Server", [
        input("AD Server IP/Hostname", name="ip_hostname"),
        select("Authentication Method", ["LDAP", "RADIUS"], name="authentication")
    ])
    ad_servers.append(data)
    authentication()

def delete_ad_server(server):
    global ad_servers
    ad_servers = [s for s in ad_servers if s != server]
    authentication()

# Function to handle logout


import paramiko


def ssh_access(ip_hostname, port, username, password, command):
    try:
        # Create an SSH client instance
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the SSH server
        ssh_client.connect(ip_hostname, port=port, username=username, password=password)

        # Execute the command
        stdin, stdout, stderr = ssh_client.exec_command(command)

        # Read and return the command output
        output = stdout.read().decode('utf-8')
        return output
    except Exception as e:
        return f"Error: {e}"
    finally:
        # Close the SSH connection
        ssh_client.close()


def monitor_device():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# Monitor Device')

    # Display hostname
    put_markdown(f"Hostname: {hostname}")

    # Display device table
    device_rows = []
    for device in devices:
        status, color = check_reachability(device["ip_hostname"], device["transport"])
        device_rows.append([
            device["name"],
            device["ip_hostname"],
            device["port"],
            device["transport"],
            put_markdown(f"<span style='color:{color}'>{status}</span>"),
            put_buttons(["Delete"], onclick=[lambda d=device: delete_device(d)]),
            put_buttons(["SSH"], onclick=[lambda d=device: ssh_to_device(d)])
        ])

    # Display add device button
    put_buttons(['Add Device'], onclick=[add_device])

    put_table([
        ["Device Name", "IP/Hostname", "Port Number", "Transport", "Status", "Action", "SSH"],
        *device_rows
    ])


def ssh_to_device(device):
    # Define SSH command to execute (e.g., "ls -l")
    command = "ls -l"  # Replace with your desired command

    # Perform SSH access
    output = ssh_access(device["ip_hostname"], int(device["port"]), "your_ssh_username", "your_ssh_password", command)

    # Display the SSH command output
    put_markdown(f"SSH Command Output for {device['name']}:")
    put_code(output)



# Define the logout function
def logout():
    global logged_in
    logged_in = False
    go_app('login', new_window=False)

# Your other functions and code snippets here...

# Dashboard function

import webbrowser

def ssh_to_device(device):
    # Define SSH parameters
    ip_hostname = device["ip_hostname"]
    port = device["port"]
    username = "your_ssh_username"  # Replace with your SSH username
    password = "your_ssh_password"  # Replace with your SSH password

    # Generate the PuTTY SSH command
    putty_command = f"putty.exe -ssh {username}@{ip_hostname} -P {port}"

    # Launch PuTTY using the generated command
    webbrowser.open(putty_command)

    # Return a message indicating that PuTTY has been launched
    return "PuTTY has been launched. Please check your browser's downloads bar for the file download prompt."


import subprocess


# Modify your dashboard function to include a button for packet captur

# Function to start packet capture

def start_packet_capture():
    # Run Wireshark to capture packets
    try:
        subprocess.Popen(['wireshark'])
        put_text("Wireshark has been opened for packet capture.")
    except Exception as e:
        put_text(f"Error: {e}")


# Function to handle search functionality (searching through captured packets)
def search_packets(source_ip=None, destination_ip=None, port=None):
    # You can use pyshark or tshark for packet analysis
    # For simplicity, let's assume you've saved packets to a file
    capture_file = 'capture.pcap'

    try:
        # Use tshark to filter packets based on search criteria
        command = f'tshark -r {capture_file}'
        if source_ip:
            command += f' -Y "ip.src == {source_ip}"'
        if destination_ip:
            command += f' -Y "ip.dst == {destination_ip}"'
        if port:
            command += f' -Y "tcp.port == {port}" or udp.port == {port}"'

        # Execute the command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout

        # Display the search result
        put_code(output)
    except Exception as e:
        put_text(f"Error: {e}")


# Your other functions and code snippets...

# Modify your dashboard function to include a button for packet search


# Function to handle packet search
def search_packet():
    # Get search criteria from user
    data = input_group("Packet Search", [
        input("Source IP:", name="source_ip", type=TEXT),
        input("Destination IP:", name="destination_ip", type=TEXT),
        input("Port:", name="port", type=NUMBER)
    ])

    # Search for packets based on the provided criteria
    search_packets(data['source_ip'], data['destination_ip'], data['port'])
import plotly.graph_objects as go

# Assume you have a function to retrieve SNMP data for a device
def get_snmp_data(device_ip):
    # Dummy function, replace with actual implementation
    # Returns dummy SNMP data
    return {'cpu_utilization': [10, 20, 30, 40], 'memory_usage': [30, 40, 50, 60]}

# Assume you have a function to retrieve monitoring data for a device
def get_monitoring_data(device_id):
    # Dummy function, replace with actual implementation
    # Returns dummy monitoring data
    return {'bandwidth_usage': [100, 200, 150, 180]}

# Function to plot a graph using Plotly
def plot_graph(data, title):
    fig = go.Figure()
    for metric, values in data.items():
        fig.add_trace(go.Scatter(x=list(range(len(values))), y=values, mode='lines', name=metric))
    fig.update_layout(title=title, xaxis_title='Time', yaxis_title='Value')
    return fig

# Dashboard function with graph display

    # Your existing dashboard code continues...


import tempfile
import shutil
import os

# Function to generate a report
def generate_report():
    # Generate the report content (replace this with your actual report generation logic)
    report_content = "This is a sample report content.\nYou can customize it based on your requirements."

    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()

    # Define the path for the report file
    report_file_path = os.path.join(temp_dir, "report.txt")

    # Write the report content to the file
    with open(report_file_path, "w") as f:
        f.write(report_content)

    return report_file_path

# Function to handle report download
def download_report():
    # Generate the report
    report_file_path = generate_report()

    # Provide the user with a link to download the report
    put_markdown("## Report Download")
    put_text("Click the link below to download the report:")
    put_file("Download Report", path=report_file_path, label="report.txt")

    # Clean up: delete the temporary directory and its contents
    shutil.rmtree(os.path.dirname(report_file_path))

# Modify your dashboard function to include a button for report download

# Import necessary libraries
import plotly.graph_objects as go

# Function to retrieve data for the graph (assuming you have this function)
def get_graph_data():
    # Dummy function, replace with actual implementation
    # Returns dummy graph data
    return {'x_values': [1, 2, 3, 4], 'y_values': [10, 20, 15, 25]}

# Function to plot the graph
def plot_graph():
    # Retrieve data for the graph
    graph_data = get_graph_data()

    # Create a Plotly figure
    fig = go.Figure()

    # Add data to the figure
    fig.add_trace(go.Scatter(x=graph_data['x_values'], y=graph_data['y_values'], mode='lines', name='Graph'))

    # Customize the layout if needed
    fig.update_layout(title='Sample Graph', xaxis_title='X Axis', yaxis_title='Y Axis')

    return fig

# Modify your dashboard function to include the graph
# Import necessary libraries for firewall automation (e.g., paramiko for SSH)
import paramiko

# Function to add firewall rule
def add_firewall_rule(device, rule):
    # Implement the logic to add the firewall rule to the device
    # Use SSH or any other method supported by your firewall device
    pass

# Function to update firewall rule
def update_firewall_rule(device, rule_id, new_rule):
    # Implement the logic to update the firewall rule on the device
    pass

# Function to delete firewall rule
def delete_firewall_rule(device, rule_id):
    # Implement the logic to delete the firewall rule from the device
    pass

# Function to display firewall automation tab
def firewall_automation():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# Firewall Automation')

    # Display form to input firewall rule
    data = input_group("Firewall Rule", [
        input("Device Name:", name="device_name", type=TEXT),
        input("Rule ID:", name="rule_id", type=NUMBER),
        input("Rule:", name="rule", type=TEXT),
        select("Action:", options=["Add", "Update", "Delete"], name="action")
    ])

    device_name = data['device_name']
    rule_id = data['rule_id']
    rule = data['rule']
    action = data['action']

    # Find the device based on the entered name
    device = next((d for d in devices if d["name"] == device_name), None)

    if device:
        if action == "Add":
            add_firewall_rule(device, rule)
            put_text("Firewall rule added successfully.")
        elif action == "Update":
            update_firewall_rule(device, rule_id, rule)
            put_text("Firewall rule updated successfully.")
        elif action == "Delete":
            delete_firewall_rule(device, rule_id)
            put_text("Firewall rule deleted successfully.")
    else:
        put_text("Device not found. Please enter a valid device name.")

# Modify your dashboard function to include the firewall automation tab

def dashboard():
    # Clear the previous content
    clear()

    # Display the graph
    put_html("<div class='main-content'>")
    put_markdown('# Dashboard')
    put_markdown(f"Hostname: {hostname}")  # Display hostname on dashboard

    # Plot and display the graph
    graph_fig = plot_graph()
    put_html(graph_fig.to_html(full_html=False, include_plotlyjs='cdn'))

    put_html("</div>")
# Function to add advanced firewall rule
# Function to add advanced firewall rule
def add_advanced_firewall_rule(device, source_ip, destination_ip, service, application, transport):
    # Implement the logic to add the advanced firewall rule to the device
    # Use SSH or any other method supported by your firewall device
    pass

# Function to update advanced firewall rule
def update_advanced_firewall_rule(device, rule_id, source_ip, destination_ip, service, application, transport):
    # Implement the logic to update the advanced firewall rule on the device
    pass

# Function to delete advanced firewall rule
def delete_advanced_firewall_rule(device, rule_id):
    # Implement the logic to delete the advanced firewall rule from the device
    pass

# Function to display advanced firewall automation tab
def advanced_firewall_automation():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# Advanced Firewall Automation')

    # Display form to input advanced firewall rule
    data = input_group("Advanced Firewall Rule", [
        input("Device Name:", name="device_name", type=TEXT),
        input("Rule ID:", name="rule_id", type=NUMBER),
        input("Source IP:", name="source_ip", type=TEXT),
        input("Destination IP:", name="destination_ip", type=TEXT),
        input("Service:", name="service", type=TEXT),
        input("Application:", name="application", type=TEXT),
        select("Transport:", options=["TCP", "UDP", "ICMP"], name="transport"),
        select("Action:", options=["Add", "Update", "Delete"], name="action")
    ])

    device_name = data['device_name']
    rule_id = data['rule_id']
    source_ip = data['source_ip']
    destination_ip = data['destination_ip']
    service = data['service']
    application = data['application']
    transport = data['transport']
    action = data['action']

    # Find the device based on the entered name
    device = next((d for d in devices if d["name"] == device_name), None)

    if device:
        if action == "Add":
            add_advanced_firewall_rule(device, source_ip, destination_ip, service, application, transport)
            put_text("Advanced firewall rule added successfully.")
        elif action == "Update":
            update_advanced_firewall_rule(device, rule_id, source_ip, destination_ip, service, application, transport)
            put_text("Advanced firewall rule updated successfully.")
        elif action == "Delete":
            delete_advanced_firewall_rule(device, rule_id)
            put_text("Advanced firewall rule deleted successfully.")
    else:
        put_text("Device not found. Please enter a valid device name.")

# Modify your dashboard function to include the advanced firewall automation tab
import sqlite3

# Create a connection and cursor
conn = sqlite3.connect('syslog.db')
cursor = conn.cursor()

# Create table to store syslog messages
cursor.execute('''
CREATE TABLE IF NOT EXISTS syslog_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Commit changes and close connection
conn.commit()
conn.close()

import socketserver
class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        message = data.decode('utf-8')
        print(f"{self.client_address[0]}: {message}")

        # Log message to database
        conn = sqlite3.connect('syslog.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO syslog_messages (message) VALUES (?)', (message,))
        conn.commit()
        conn.close()
# Function to display syslog messages in the web UI
def start_syslog_server():
    with socketserver.UDPServer(('0.0.0.0', 514), SyslogUDPHandler) as server:
        server.serve_forever()
def display_syslog_messages():
    conn = sqlite3.connect('syslog.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM syslog_messages')
    messages = cursor.fetchall()
    conn.close()

    message_rows = [[msg[0], msg[1], msg[2]] for msg in messages]
    put_table(message_rows, header=["ID", "Message", "Timestamp"])

# Function to handle filtering of syslog messages
# Function to filter syslog messages based on severity level
def filter_syslog_messages(severity_level):
    conn = sqlite3.connect('syslog.db')
    cursor = conn.cursor()

    if severity_level.lower() == "all":
        cursor.execute('SELECT * FROM syslog_messages')
    else:
        cursor.execute('SELECT * FROM syslog_messages WHERE message LIKE ?', ('%' + severity_level.upper() + '%',))

    messages = cursor.fetchall()
    conn.close()

    message_rows = [[msg[0], msg[1], msg[2]] for msg in messages]
    put_table(message_rows, header=["ID", "Message", "Timestamp"])


def syslog_tab():
    # Display syslog messages here
    display_syslog_messages()


import socket
from pywebio import start_server
from pywebio.input import input_group, input, actions
from pywebio.output import clear, put_html, put_markdown, put_buttons, put_table, toast
from pywebio.session import go_app
from dnslib import DNSRecord, RR, QTYPE, A, PTR
from dnslib.server import DNSServer, DNSHandler, BaseResolver

# Global variables to store DNS server and DNS record information
dns_records = {}
reverse_dns_records = {}
dns_server_ip = "0.0.0.0"
dns_server_port = 53

# DNS Resolver to handle incoming queries
class SimpleResolver(BaseResolver):
    def __init__(self, records, reverse_records):
        self.records = records
        self.reverse_records = reverse_records

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        print(f"Query: {qname} ({qtype})")

        if qtype == "A" and str(qname) in self.records:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A(self.records[str(qname)])))
        elif qtype == "PTR" and str(qname) in self.reverse_records:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.PTR, rclass=1, ttl=60, rdata=PTR(self.reverse_records[str(qname)])))
        else:
            reply.header.rcode = 3  # NXDOMAIN

        return reply

# Function to start the DNS server
def start_dns_server(ip, port, records, reverse_records):
    resolver = SimpleResolver(records, reverse_records)
    handler = DNSHandler
    handler.resolver = resolver
    server = DNSServer(resolver, port=port, address=ip, handler=handler)
    server.start_thread()
    print(f"DNS Server started on {ip}:{port}")

# Function to add a DNS record
def add_dns_record():
    global dns_records, reverse_dns_records
    data = input_group("Add DNS Record", [
        input("Domain", name="domain"),
        input("IP Address", name="ip_address")
    ])
    dns_records[data["domain"] + "."] = data["ip_address"]

    # Add reverse DNS record
    reverse_ip = '.'.join(reversed(data["ip_address"].split('.'))) + ".in-addr.arpa."
    reverse_dns_records[reverse_ip] = data["domain"] + "."

    dns_server_tab()

# Function to delete a DNS record
def delete_dns_record(domain):
    global dns_records, reverse_dns_records
    ip_address = dns_records[domain]
    reverse_ip = '.'.join(reversed(ip_address.split('.'))) + ".in-addr.arpa."
    del dns_records[domain]
    del reverse_dns_records[reverse_ip]
    dns_server_tab()

# Function to start DNS server from UI
def start_dns_server_ui():
    global dns_server_ip, dns_server_port
    start_dns_server(dns_server_ip, dns_server_port, dns_records, reverse_dns_records)
    toast(f"DNS Server started on {dns_server_ip}:{dns_server_port}")

# Function to set DNS server IP and port
def set_dns_server_ip_port():
    global dns_server_ip, dns_server_port
    data = input_group("Set DNS Server IP and Port", [
        input("IP Address", name="ip", value=dns_server_ip),
        input("Port", name="port", type="number", value=dns_server_port)
    ])
    dns_server_ip = data["ip"]
    dns_server_port = int(data["port"])
    dns_server_tab()

# Function to query DNS records
def query_dns_record():
    query = input_group("Query DNS Record", [
        input("Domain", name="domain", required=False),
        input("IP Address", name="ip_address", required=False)
    ])
    domain_query = query.get("domain")
    ip_query = query.get("ip_address")

    results = []
    if domain_query:
        domain_query += "."
        if domain_query in dns_records:
            results.append([domain_query, dns_records[domain_query]])
        else:
            results.append([domain_query, "Not found"])

    if ip_query:
        reverse_ip_query = '.'.join(reversed(ip_query.split('.'))) + ".in-addr.arpa."
        if reverse_ip_query in reverse_dns_records:
            results.append([reverse_dns_records[reverse_ip_query], ip_query])
        else:
            results.append([ip_query, "Not found"])

    if not results:
        results.append(["No matching records found", ""])

    put_table([
        ["Domain", "IP Address"],
        *results
    ])

# Function to display DNS server tab
def dns_server_tab():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
    }
    </style>
    """)
    put_markdown('# DNS Server Management')

    # Display DNS records table
    dns_records_rows = []
    for domain, ip in dns_records.items():
        dns_records_rows.append([
            domain,
            ip,
            put_buttons(["Delete"], onclick=[lambda d=domain: delete_dns_record(d)])
        ])

    put_buttons(['Add DNS Record'], onclick=[add_dns_record])
    put_buttons(['Query DNS Record'], onclick=[query_dns_record])
    put_buttons(['Set DNS Server IP and Port'], onclick=[set_dns_server_ip_port])
    put_table([
        ["Domain", "IP Address", "Action"],
        *dns_records_rows
    ])

    put_buttons(['Start DNS Server'], onclick=[start_dns_server_ui])


import os
import sqlite3
from pywebio import start_server
from pywebio.output import put_text, put_html, put_markdown, put_buttons, clear, put_table, put_row, put_column
from pywebio.input import input_group, input, actions

# Use an absolute path for the database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'ipam.db')

# Function to create database and table
def create_database():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        print(f"Connected to database at {DATABASE_PATH}")

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ipam (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                hostname TEXT NOT NULL,
                device_name TEXT,
                status TEXT
            )
        ''')
        print("ipam table created or already exists.")

        conn.commit()
        conn.close()
        print("Database and table creation successful.")
    except Exception as e:
        print("Error creating database and table:", e)

# Function to add IP address to IPAM table
def add_ip_address(ip_address, hostname, device_name):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO ipam (ip_address, hostname, device_name, status) VALUES (?, ?, ?, ?)',
                       (ip_address, hostname, device_name, 'available'))
        conn.commit()
        conn.close()
        put_text(f"IP address {ip_address} added successfully.")
    except Exception as e:
        put_text(f"Error adding IP address: {e}")

# Function to retrieve all IP addresses from IPAM table
def get_all_ip_addresses():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM ipam')
        ip_addresses = cursor.fetchall()
        conn.close()
        return ip_addresses
    except Exception as e:
        put_text(f"Error retrieving IP addresses: {e}")
        return []

# Function to update IP address information in IPAM table
def update_ip_address(ip_address, hostname, device_name, status):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE ipam SET hostname=?, device_name=?, status=? WHERE ip_address=?',
                       (hostname, device_name, status, ip_address))
        conn.commit()
        conn.close()
        put_text(f"IP address {ip_address} updated successfully.")
    except Exception as e:
        put_text(f"Error updating IP address: {e}")

# Function to delete IP address from IPAM table
def delete_ip_address(ip_id):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ipam WHERE id=?', (ip_id,))
        conn.commit()
        conn.close()
        put_text(f"IP address with ID {ip_id} deleted successfully.")
    except Exception as e:
        put_text(f"Error deleting IP address: {e}")

# Function to display IPAM table on dashboard
def display_ipam_table():
    clear()
    ip_addresses = get_all_ip_addresses()
    if ip_addresses:
        table = [[id, ip, hostname, device, status, put_buttons(['Delete'], onclick=[lambda id=id: delete_ipam_entry(id)])] for (id, ip, hostname, device, status) in ip_addresses]
        put_table(table, header=["ID", "IP Address", "Hostname", "Device Name", "Status", "Actions"])
    else:
        put_text("No IP addresses found in the IPAM table.")
    put_buttons(['Add IP Address', 'Back to Dashboard'], onclick=[add_ipam_entry, dashboard])

# Function to handle adding new IP addresses
def add_ipam_entry():
    data = input_group("Add IP Address or Subnet", [
        input("IP Address", name="ip_address", type="text", required=True),
        input("Hostname", name="hostname", type="text", required=True),
        input("Device Name", name="device_name", type="text", required=False)
    ])
    add_ip_address(data['ip_address'], data['hostname'], data['device_name'])
    display_ipam_table()

# Function to handle deleting IP addresses
def delete_ipam_entry(ip_id):
    delete_ip_address(ip_id)
    display_ipam_table()

# Modify the dashboard function to include IPAM tab
def dashboard():
    clear()
    put_html("""
    <style>
    body {
        background-color: white;
        color: black;
        margin: 0;
        display: flex;
    }
    .sidebar {
        width: 20%;
        padding: 10px;
        box-sizing: border-box;
    }
    .main-content {
        width: 80%;
        padding: 10px;
        box-sizing: border-box;
    }
    </style>
    """)

    put_html("<div class='sidebar'>")
    put_markdown('## Dashboard Menu')
    put_buttons(['Monitor Device', 'Settings', 'SNMP Monitoring', 'Authentication', 'Upload Logo', 'Logout'],
                onclick=[monitor_device, settings, snmp_monitoring, authentication, upload_logo, logout])
    put_buttons(['Start Packet Capture', 'Search Packet', 'Download Report', 'Firewall Automation', 'Advanced Firewall Automation', 'Syslog', 'IPAM'],
                onclick=[start_packet_capture, search_packet, download_report, firewall_automation, advanced_firewall_automation, syslog_tab, ipam])
    put_html("</div>")
    put_html("<div class='main-content'>")
    put_markdown('# Dashboard')
    put_html("</div>")

# Function to handle IPAM button click
def ipam():
    clear()
    put_markdown("## IP Address Management")
    display_ipam_table()

# Dummy functions for other tabs (to be implemented as needed)

# Main function to start the server
def main():
    create_database()  # Ensure the database is created before starting the server
    start_server({
        'login': login,
        'dashboard': dashboard,
        'upload_logo': upload_logo,
        'monitor_device': monitor_device,
        'settings': settings,
        'snmp_monitoring': snmp_monitoring,
        'authentication': authentication,
        'ipam': ipam  # Added IPAM function to start server
    }, port=8000)

# Dummy login function (to be implemented as needed)

if __name__ == "__main__":
    main()
