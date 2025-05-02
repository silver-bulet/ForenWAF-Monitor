import json
import pandas as pd
import google.generativeai as genai
from config.settings import settings
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class AIAnalyzer:
    def __init__(self):
        genai.configure(api_key=settings.GEMINI_API_KEY)
        self.model = genai.GenerativeModel(settings.GEMINI_MODEL)

    def analyze_last_24h(self, influx_manager):
        try:
            query = f'''
            from(bucket: "{settings.INFLUX_BUCKET}")
            |> range(start: -24h)
            |> filter(fn: (r) => r["_measurement"] == "waf_stats")
            |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
            '''

            # Replace query_data_frame with a direct query to improve performance.
            result = influx_manager.query_api.query(query)

            if not result:
                logger.warning("No data returned from InfluxDB query")
                return None

            # Convert results to a DataFrame manually
            records = []
            for table in result:
                for record in table.records:
                    records.append(record.values)

            if not records:
                return None

            df = pd.DataFrame(records)
            df["_time"] = pd.to_datetime(df["_time"])

            return self._generate_analysis_report(df)

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return None

    def _generate_analysis_report(self, df):
        """Create an analysis report from a DataFrame"""
        if df.empty:
            return None

        json_data = json.dumps(df.to_dict(orient="records"), default=str)
        prompt = self._build_analysis_prompt(json_data)

        try:
            response = self.model.generate_content(prompt)
            return response.text if hasattr(response, "text") else None
        except Exception as e:
            logger.error(f"AI generation failed: {e}")
            return None


    def _build_analysis_prompt(self, json_data: str) -> str:
        """Building an AI Message"""
        return f"""
            Analyze the following WAF logs and generate a security report with the following five sections:

            1. **Incident Summary**: List the top 3 most frequent attack types, with the number of attempts for each.
            2. **Critical Findings**: Identify the most dangerous or repeated incidents based on behavior (e.g., brute-force, mass scanning, evasion attempts).
            3. **Attack Patterns**: Highlight common attacker IPs, time windows of activity, and frequently targeted endpoints.
            4. **7-Day Threat Forecast**: Predict attack trends for the next 7 days, with estimated percentage change and a confidence level (High/Medium/Low).
            5. **Actionable Recommendations**: Provide a maximum of 3 clear security actions or mitigations based on the above findings.

            Output must be:
            - Written in plain text using clear bullet points.
            - Concise and focused on security insights.
            - End with the timestamp of the analysis in UTC.

            Assume the log format includes timestamp, IP, target URL, attack type, status code, and WAF action.

            Logs: {json_data}
                """
