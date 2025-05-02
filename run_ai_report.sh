#!/bin/bash
sudo rm -f /opt/forenwaf_monitor/last_position.json
sudo systemctl restart forenwaf_monitor.service && echo "Gemini AI analysis will run on fresh logs."
