from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from config.settings import settings
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class InfluxDBManager:
    def __init__(self):
        self.client = InfluxDBClient(
            url=settings.INFLUX_URL,
            token=settings.INFLUX_TOKEN,
            org=settings.INFLUX_ORG
        )
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.query_api = self.client.query_api()

    def export_log_entries(self, log_entries: List[Dict]) -> int:
        """Export ModSecurity logs to InfluxDB"""
        if not log_entries:
            logger.debug("No log entries to export")
            return 0

        points = []
        for entry in log_entries:
            try:
                # Create stats points for attack types
                for attack_type in entry.get('attack_types', []):
                    stats_point = Point("waf_stats") \
                        .tag("ip", entry.get('client_ip', 'unknown')) \
                        .tag("country_code", entry.get('country_code', 'XX')) \
                        .tag("country", entry.get('country_name', 'Unknown')) \
                        .tag("type", "attack_type") \
                        .tag("value", attack_type) \
                        .tag("severity", entry.get('severity', 'unknown')) \
                        .tag("transaction_id", entry.get('transaction_id', 'unknown')) \
                        .field("count", 1) \
                        .field("anomaly_score", entry.get('anomaly_score', 0)) \
                        .field("intercepted", entry.get('intercepted', False)) \
                        .field("method", entry.get('request_method', 'unknown')) \
                        .field("uri", entry.get('uri', 'unknown')) \
                        .time(entry['timestamp'])

                    points.append(stats_point)

                # Create country-based statistics
                country_point = Point("waf_countries") \
                    .tag("country_code", entry.get('country_code', 'XX')) \
                    .tag("country", entry.get('country_name', 'Unknown')) \
                    .tag("attack_type", ",".join(entry.get('attack_types', ['Unknown']))) \
                    .tag("severity", entry.get('severity', 'unknown')) \
                    .field("count", 1) \
                    .time(entry['timestamp'])

                points.append(country_point)

            except Exception as e:
                logger.error(f"Error creating data point: {e}")

        try:
            if points:
                self.write_api.write(bucket=settings.INFLUX_BUCKET, record=points)
                logger.info(f"Exported {len(points)} data points to InfluxDB")
                return len(points)
        except Exception as e:
            logger.error(f"Error exporting to InfluxDB: {e}")
            return 0

    def save_analysis_result(self, analysis_result: str) -> bool:
        """Export ModSecurity logs to InfluxDB"""
        try:
            point = Point("ai_analysis") \
                .field("summary", analysis_result)

            self.write_api.write(
                bucket=settings.INFLUX_PREDICTIONS_BUCKET,
                org=settings.INFLUX_ORG,
                record=point
            )
            logger.info("AI analysis saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save AI analysis: {e}")
            return False
