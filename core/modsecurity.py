import json
import os
import re
import pytz
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from config.settings import settings
from utils.geoip import GeoIPLookup

logger = logging.getLogger(__name__)

class ModSecurityParser:
    def __init__(self, geoip: Optional[GeoIPLookup] = None):
        self.log_path = Path(settings.LOG_PATH)
        self.timezone = pytz.timezone(settings.TIMEZONE)
        self.geoip = geoip or GeoIPLookup()
        self.last_position = 0
        self.last_processed_time = None
        self.position_file = "last_position.json"
        self._load_last_position()

    def _load_last_position(self):
        """Load last processed position from file"""
        if os.path.exists(self.position_file):
            try:
                with open(self.position_file, 'r') as f:
                    data = json.load(f)
                    self.last_position = data.get('position', 0)
                    last_time = data.get('last_time')
                    if last_time:
                        self.last_processed_time = datetime.fromisoformat(last_time)
                    logger.info(f"Loaded last position: {self.last_position}")
            except Exception as e:
                logger.error(f"Error loading last position: {e}")

    def _save_last_position(self):
        """Save last processed position"""
        try:
            data = {
                'position': self.last_position,
                'last_time': self.last_processed_time.isoformat() if self.last_processed_time else None
            }
            with open(self.position_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Error saving last position: {e}")

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Convert datetime text to datetime object"""
        try:
            dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S.%f %z")
            return dt.astimezone(self.timezone)
        except ValueError as e:
            logger.error(f"Error parsing timestamp '{timestamp_str}': {e}")
            return datetime.now(self.timezone)

    def _extract_security_level(self, messages: List[Dict]) -> str:
        """Extract security level"""
        severity_levels = {
            "CRITICAL": 4,
            "ERROR": 3,
            "WARNING": 2,
            "NOTICE": 1,
            "INFO": 0
        }
        current_level = 0
        highest_severity = "INFO"

        for message in messages:
            severity = message.get('severity', '').upper()
            if severity in severity_levels and severity_levels[severity] > current_level:
                current_level = severity_levels[severity]
                highest_severity = severity

        return highest_severity

    def _extract_audit_data(self, audit_data: Dict) -> Dict:
        """Audit data processing"""
        result = {
            'messages': [],
            'rule_ids': [],
            'attack_types': [],
            'security_level': 'INFO',
            'anomaly_score': 0
        }

        if not audit_data:
            return result

        messages_raw = audit_data.get('messages', [])
        messages = []

        for msg_raw in messages_raw:
            msg_obj = {}
            # Extract Rule ID
            rule_match = re.search(r'\[id\s+"(\d+)"\]', msg_raw)
            if rule_match:
                rule_id = rule_match.group(1)
                msg_obj['id'] = rule_id
                result['rule_ids'].append(rule_id)

            # Extract message
            msg_match = re.search(r'\[msg\s+"([^"]+)"\]', msg_raw)
            if msg_match:
                msg_obj['msg'] = msg_match.group(1)

            # Extract severity
            severity_match = re.search(r'\[severity\s+"([^"]+)"\]', msg_raw)
            if severity_match:
                msg_obj['severity'] = severity_match.group(1)

            # Extract tags
            tags = re.findall(r'\[tag\s+"([^"]+)"\]', msg_raw)
            if tags:
                msg_obj['tag'] = tags

            # Extract Anomaly Score
            anomaly_match = re.search(r'COMBINED_SCORE=(\d+)', msg_raw)
            if anomaly_match:
                try:
                    result['anomaly_score'] = int(anomaly_match.group(1))
                except ValueError:
                    pass

            messages.append(msg_obj)

        result['messages'] = messages
        result['attack_types'] = self._extract_attack_type(messages)
        result['security_level'] = self._extract_security_level(messages)
        return result

    def _extract_attack_type(self, messages: List[Dict]) -> List[str]:
        """Extract attack type"""
        rule_id_ranges = {
            (941000, 941999): "XSS",
            (942000, 942999): "SQL Injection",
            (930000, 930999): "Local File Inclusion",
            (931000, 931999): "Remote File Inclusion",
            (932000, 932999): "Remote Command Execution",
            (933000, 933999): "PHP Injection",
            (920000, 920999): "Protocol Violation",
            (913000, 913999): "Scanner Detection",
            (950000, 950999): "Data Leakage"
        }

        attack_patterns = {
            "SQL Injection": r"\bSQL\s+Injection\b|\bSQLi\b",
            "XSS": r"\bXSS\b|\bCross[\s-]Site\s+Scripting\b",
            "Remote File Inclusion": r"\bRemote\s+File\s+Inclusion\b|\bRFI\b",
            "Local File Inclusion": r"\bLocal\s+File\s+Inclusion\b|\bLFI\b|\bPath\s+Traversal\b",
            "Remote Command Execution": r"\bRemote\s+Command\s+Execution\b|\bRCE\b|\bOS\s+Command\s+Injection\b",
            "PHP Injection": r"\bPHP\s+Injection\b|\bPHPi\b",
            "Scanner Detection": r"\bScanner\s+Detection\b|\bWeb\s+Scanner\b"
        }

        # First try by rule ID
        rule_ids = []
        for msg in messages:
            if 'id' in msg and msg['id']:
                try:
                    rule_id = int(msg['id'])
                    rule_ids.append(rule_id)
                    for (start, end), attack_type in rule_id_ranges.items():
                        if start <= rule_id <= end:
                            return [attack_type]
                except (ValueError, TypeError):
                    continue

        # Then try by message patterns
        attack_indicators = {}
        for msg in messages:
            msg_text = msg.get('msg', '')
            if not msg_text:
                continue

            for attack, pattern in attack_patterns.items():
                matches = re.findall(pattern, msg_text, re.IGNORECASE)
                if matches:
                    attack_indicators[attack] = attack_indicators.get(attack, 0) + len(matches)

        if attack_indicators:
            return [max(attack_indicators.items(), key=lambda x: x[1])[0]]

        return ["Unclassified"]

    def parse_logs(self) -> List[Dict]:
        """Reading and analyzing ModSecurity logs"""
        if not self.log_path.exists():
            logger.error(f"Log file not found: {self.log_path}")
            return []

        log_entries = []
        try:
            with open(self.log_path, 'r') as f:
                f.seek(self.last_position)
                line_num = 0

                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        log_json = json.loads(line)
                        transaction = log_json.get('transaction', {})
                        timestamp_str = transaction.get('time')
                        if not timestamp_str:
                            logger.warning(f"Line {line_num}: Missing timestamp")
                            continue

                        timestamp = self._parse_timestamp(timestamp_str)
                        if self.last_processed_time and timestamp <= self.last_processed_time:
                            continue

                        request = log_json.get('request', {})
                        request_line = request.get('request_line', '')
                        headers = request.get('headers', {})

                        # Extract method and URI
                        request_method, uri = None, None
                        if request_line:
                            parts = request_line.split()
                            if len(parts) >= 2:
                                request_method = parts[0]
                                uri = parts[1]

                        # Extract client IP
                        client_ip = "unknown"
                        remote_address = transaction.get("remote_address", "unknown")
                        transaction_headers = transaction.get("headers", {})

                        if transaction_headers:
                            forwarded_ip = transaction_headers.get("X-Forwarded-For", "")
                            if forwarded_ip:
                                client_ip = forwarded_ip.split(",")[0].strip()
                            else:
                                client_ip = remote_address

                        if client_ip == "unknown" and headers:
                            forwarded_ip = headers.get("X-Forwarded-For", "")
                            if forwarded_ip:
                                client_ip = forwarded_ip.split(",")[0].strip()

                        # Get country info
                        country_info = self.geoip.get_country(client_ip)

                        # Process audit data
                        audit_data = log_json.get('audit_data', {})
                        audit_info = self._extract_audit_data(audit_data)

                        # Create log entry
                        entry = {
                            'timestamp': timestamp,
                            'transaction_id': transaction.get('transaction_id'),
                            'client_ip': client_ip,
                            'country_code': country_info['code'],
                            'country_name': country_info['name'],
                            'remote_address': remote_address,
                            'request_method': request_method,
                            'uri': uri,
                            'user_agent': headers.get('User-Agent'),
                            'rule_ids': audit_info['rule_ids'],
                            'attack_types': audit_info['attack_types'],
                            'severity': audit_info['security_level'],
                            'anomaly_score': audit_info['anomaly_score'],
                            'intercepted': audit_data.get('action', {}).get('intercepted', False),
                            'server': audit_data.get('server', '')
                        }

                        log_entries.append(entry)
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON decode error in line {line_num}: {e}")
                    except Exception as e:
                        logger.error(f"Error processing line {line_num}: {e}")

                self.last_position = f.tell()
                if log_entries:
                    self.last_processed_time = max(entry['timestamp'] for entry in log_entries)
                self._save_last_position()

        except Exception as e:
            logger.error(f"Error reading log file: {e}")

        return log_entries
