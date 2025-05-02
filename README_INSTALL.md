# ForenWAF Monitor Installation Automation

This document provides instructions on how to use the provided `install.sh` script to automate the installation of the ForenWAF Monitor project on a Debian-based Linux system (like Ubuntu).

## Prerequisites

Before running the installation script, ensure your system meets the following requirements:

1.  **Operating System:** A Debian-based Linux distribution (e.g., Ubuntu 20.04 or later). The script uses `apt-get` for system dependencies.
2.  **Root Access:** You need `sudo` privileges to run the installation script, as it installs packages, creates users/groups, and sets up a systemd service.
3.  **Required Commands:** The following commands must be available:
    *   `python3`
    *   `pip3`
    *   `git` (The script assumes project files are copied from the current directory, but `git` might be needed if you modify it to clone from a repository).
    *   `curl` or `wget` (If you need to download the script itself).
4.  **Internet Connection:** Required to download system packages and Python dependencies.
5.  **ModSecurity:** A running ModSecurity instance configured to output audit logs in JSON format to a file (e.g., `/var/log/modsec_audit.json`). The installation script will prompt for the path to this log file.
6.  **API Keys:** You will need API keys/tokens for:
    *   InfluxDB (URL and Token)
    *   Google Gemini API

## Installation Steps

1.  **Download/Copy Files:** Obtain the ForenWAF Monitor project source code, including:
    *   All Python files (`main.py`, `settings.py`, `modsecurity.py`, etc.)
    *   `requirements.txt`
    *   `install.sh` (this installation script)
    Place all these files in a single directory on the target server.

2.  **Make Script Executable:** Open a terminal, navigate to the directory containing the files, and run:
    ```bash
    chmod +x install.sh
    ```

3.  **Run Installation Script:** Execute the script using sudo:
    ```bash
    sudo ./install.sh
    ```

4.  **Follow Prompts:** The script will guide you through the installation process:
    *   It will check prerequisites and install necessary system packages (`python3-venv`).
    *   It will create a dedicated system user (`forenwaf`) and group (`forenwaf`).
    *   It will copy the project files to `/opt/forenwaf_monitor`.
    *   It will set up a Python virtual environment and install dependencies.
    *   **Crucially, it will prompt you to enter:**
        *   Your InfluxDB URL.
        *   Your InfluxDB Token (input will be hidden).
        *   Your Google Gemini API Key (input will be hidden).
        *   The path to your ModSecurity JSON audit log file (defaults to `/var/log/modsec_audit.json`).
    *   It will create the `.env` configuration file with the details you provide.
    *   It will set appropriate file permissions.
    *   It will create and enable a systemd service file (`forenwaf_monitor.service`).
    *   It will start the service and display its status.

## Post-Installation

1.  **Verify Service Status:** You can check the service status at any time using:
    ```bash
    sudo systemctl status forenwaf_monitor.service
    ```

2.  **Check Logs:** Application logs are stored in `/opt/forenwaf_monitor/Forenwaf_monitor.log`. You can view them using:
    ```bash
    sudo tail -f /opt/forenwaf_monitor/Forenwaf_monitor.log
    ```
    Or, for systemd logs:
    ```bash
    sudo journalctl -u forenwaf_monitor.service -f
    ```

3.  **ModSecurity Log Permissions:** As noted by the script, ensure the `forenwaf` user has read permissions for the ModSecurity log file (`/var/log/modsec_audit.json` or the path you specified). This often involves adding the `forenwaf` user to the group that owns the log file (commonly `adm` on Debian/Ubuntu):
    ```bash
    sudo usermod -a -G adm forenwaf
    ```
    You might need to restart the `forenwaf_monitor` service after changing group membership:
    ```bash
    sudo systemctl restart forenwaf_monitor.service
    ```
    Alternatively, adjust log file permissions or use ACLs, but be mindful of security implications.

4.  **Configuration Changes:** If you need to change API keys, the log path, or other settings later, edit the `.env` file:
    ```bash
    sudo nano /opt/forenwaf_monitor/.env
    ```
    After editing, restart the service:
    ```bash
    sudo systemctl restart forenwaf_monitor.service
    ```

## Uninstallation (Manual)

The script does not include an uninstallation option. To remove the installation:

1.  Stop and disable the service:
    ```bash
    sudo systemctl stop forenwaf_monitor.service
    sudo systemctl disable forenwaf_monitor.service
    ```
2.  Remove the systemd service file:
    ```bash
    sudo rm /etc/systemd/system/forenwaf_monitor.service
    sudo systemctl daemon-reload
    ```
3.  Remove the installation directory:
    ```bash
    sudo rm -rf /opt/forenwaf_monitor
    ```
4.  (Optional) Remove the user and group:
    ```bash
    sudo userdel forenwaf
    sudo groupdel forenwaf
    ```

