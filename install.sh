#!/bin/bash

# ForenWAF Monitor Installation Script

# --- Configuration ---
INSTALL_DIR="/opt/forenwaf_monitor"
SERVICE_NAME="forenwaf_monitor"
PYTHON_CMD="python3"
PIP_CMD="pip3"
PROJECT_USER="forenwaf"
PROJECT_GROUP="forenwaf"
MODSEC_LOG_DEFAULT="/var/log/modsec_audit.json"

# --- Helper Functions ---
echo_info() {
    echo "[INFO] $1"
}

echo_warn() {
    echo "[WARN] $1"
}

echo_error() {
    echo "[ERROR] $1" >&2
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo_error "Command not found: $1. Please install it."
        exit 1
    fi
}

# --- Main Installation Logic ---

# 1. Check Prerequisites
check_root
echo_info "Checking prerequisites..."
check_command "$PYTHON_CMD"
check_command "$PIP_CMD"
check_command "git" # Assuming source code is retrieved via git

# 2. System Dependencies (Debian/Ubuntu)
echo_info "Updating package list and installing system dependencies (python3-venv)..."
apt-get update > /dev/null
apt-get install -y python3-venv > /dev/null
if [ $? -ne 0 ]; then
    echo_error "Failed to install system dependencies."
    exit 1
fi

# 3. Create Project User and Group
echo_info "Creating user and group 	'$PROJECT_USER'..."
if ! getent group "$PROJECT_GROUP" > /dev/null; then
    groupadd --system "$PROJECT_GROUP"
else
    echo_warn "Group '$PROJECT_GROUP' already exists."
fi

if ! id "$PROJECT_USER" > /dev/null; then
    useradd --system --gid "$PROJECT_GROUP" --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$PROJECT_USER"
else
    echo_warn "User '$PROJECT_USER' already exists."
fi

# 4. Create Installation Directory
echo_info "Creating installation directory '$INSTALL_DIR'..."
mkdir -p "$INSTALL_DIR"

# 5. Clone/Copy Project Files
# Assuming the script is run from the directory containing the project source
# or modify this to clone from a Git repository
echo_info "Copying project files to '$INSTALL_DIR'..."
# Check if requirements.txt exists in the current directory
if [ ! -f "requirements.txt" ]; then
    echo_error "'requirements.txt' not found in the current directory. Make sure you run this script from the project root or adjust the script."
    exit 1
fi

# Copy all files and directories, adjust if structure is different
cp -r ./* "$INSTALL_DIR/"
if [ $? -ne 0 ]; then
    echo_error "Failed to copy project files."
    exit 1
fi

# 6. Create Python Virtual Environment
echo_info "Creating Python virtual environment in '$INSTALL_DIR/venv'..."
"$PYTHON_CMD" -m venv "$INSTALL_DIR/venv"
if [ $? -ne 0 ]; then
    echo_error "Failed to create virtual environment."
    exit 1
fi

# 7. Install Python Dependencies
echo_info "Installing Python dependencies from 'requirements.txt'..."
"$INSTALL_DIR/venv/bin/$PIP_CMD" install --no-cache-dir -r "$INSTALL_DIR/requirements.txt"
if [ $? -ne 0 ]; then
    echo_error "Failed to install Python dependencies."
    exit 1
fi

# 8. Create .env Configuration File
echo_info "Creating .env configuration file..."

# Prompt user for essential variables
read -p "Enter InfluxDB URL: " INFLUX_URL
read -s -p "Enter InfluxDB Token: " INFLUX_TOKEN
read -p "Enter InfluxDB Org [default: ForenWAF]: " INFLUX_ORG
INFLUX_ORG=${INFLUX_ORG:-ForenWAF}
read -p "Enter InfluxDB Bucket Name [default: waf_data]: " INFLUX_BUCKET
INFLUX_BUCKET=${INFLUX_BUCKET:-waf_data}
read -p "Enter InfluxDB Predictions Bucket Name [default: waf_predictions]: " INFLUX_PREDICTIONS_BUCKET
INFLUX_PREDICTIONS_BUCKET=${INFLUX_PREDICTIONS_BUCKET:-waf_predictions}
echo # Newline after password input
read -s -p "Enter Gemini API Key: " GEMINI_API_KEY
echo # Newline after password input
read -p "Enter ModSecurity Log Path [default: $MODSEC_LOG_DEFAULT]: " MODSEC_LOG_PATH
MODSEC_LOG_PATH=${MODSEC_LOG_PATH:-$MODSEC_LOG_DEFAULT}
read -p "Enter polling interval in seconds [default: 10]: " POLL_INTERVAL
POLL_INTERVAL=${POLL_INTERVAL:-10}

# Create .env file
cat << EOF > "$INSTALL_DIR/.env"
INFLUX_URL=$INFLUX_URL
INFLUX_TOKEN=$INFLUX_TOKEN
INFLUX_ORG=$INFLUX_ORG
INFLUX_BUCKET=$INFLUX_BUCKET
INFLUX_PREDICTIONS_BUCKET=$INFLUX_PREDICTIONS_BUCKET
GEMINI_API_KEY=$GEMINI_API_KEY
GEMINI_MODEL=gemini-2.0-flash
MODSEC_LOG_PATH=$MODSEC_LOG_PATH
TIMEZONE=UTC
POLL_INTERVAL=$POLL_INTERVAL
RUN_INITIAL_ANALYSIS=true
EOF

echo_info ".env file created. You can edit it later at '$INSTALL_DIR/.env' if needed."

# 9. Set Permissions
echo_info "Setting permissions for '$INSTALL_DIR'..."
chown -R "$PROJECT_USER":"$PROJECT_GROUP" "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR" # Read/execute for owner/group, nothing for others
chmod 640 "$INSTALL_DIR/.env" # Read for owner/group

# Ensure the project user can read the ModSecurity log file
# This might require adding the user to a specific group (e.g., adm) or adjusting log permissions
echo_warn "Please ensure the user '$PROJECT_USER' has read permissions for the ModSecurity log file: '$MODSEC_LOG_PATH'."
echo_warn "You might need to add the user to the group that owns the log file (e.g., 'sudo usermod -a -G adm $PROJECT_USER') or adjust log rotation settings."

# 10. Create systemd Service File
echo_info "Creating systemd service file '/etc/systemd/system/$SERVICE_NAME.service'..."

cat << EOF > "/etc/systemd/system/$SERVICE_NAME.service"
[Unit]
Description=ForenWAF Monitor Service
After=network.target

[Service]
User=$PROJECT_USER
Group=$PROJECT_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/main.py
Restart=on-failure
RestartSec=5s
StandardOutput=append:$INSTALL_DIR/Forenwaf_monitor.log
StandardError=append:$INSTALL_DIR/Forenwaf_monitor.log

[Install]
WantedBy=multi-user.target
EOF

# 11. Enable and Start Service
echo_info "Reloading systemd daemon, enabling and starting '$SERVICE_NAME' service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service"
systemctl start "$SERVICE_NAME.service"

# 12. Final Status Check
echo_info "Checking service status..."
systemctl status "$SERVICE_NAME.service" --no-pager

echo_info "Installation complete!"
echo_info "The service '$SERVICE_NAME' is running."
echo_info "Logs are stored in '$INSTALL_DIR/Forenwaf_monitor.log'."
echo_info "Configuration is in '$INSTALL_DIR/.env'."

exit 0

