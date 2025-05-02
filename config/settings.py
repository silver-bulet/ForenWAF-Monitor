import os
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env file

class Settings:
    # Settings InfluxDB
    INFLUX_URL = os.getenv("INFLUX_URL", "")
    INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "")
    INFLUX_ORG = os.getenv("INFLUX_ORG", "ForenWAF")
    INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "waf_data")
    INFLUX_PREDICTIONS_BUCKET = os.getenv("INFLUX_PREDICTIONS_BUCKET", "waf_predictions")

    # Settings Gemini AI
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    # Settings ModSecurity
    LOG_PATH = os.getenv("MODSEC_LOG_PATH", "/var/log/modsec_audit.json")
    TIMEZONE = os.getenv("TIMEZONE", "UTC")
    POLL_INTERVAL = int(os.getenv("POLL_INTERVAL") or 20)

settings = Settings()
