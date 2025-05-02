import time
import logging
from config.settings import settings
from core.influx_manager import InfluxDBManager
from core.modsecurity import ModSecurityParser
from core.ai_analyzer import AIAnalyzer

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("Forenwaf_monitor.log"),
            logging.StreamHandler()
        ]
    )

def main():
    setup_logging()
    logger = logging.getLogger("WAFMonitor")

    logger.info("Starting WAF Monitoring System")

    try:
        # Initialize components
        influx = InfluxDBManager()
        parser = ModSecurityParser()
        analyzer = AIAnalyzer()

        # First: Export existing logs to waf_data
        initial_logs = parser.parse_logs()
        if initial_logs:
            exported = influx.export_log_entries(initial_logs)
            logger.info(f"Initial export: Processed {len(initial_logs)} logs, exported {exported} points")

            # Second: Run analysis ONLY after successful export
            logger.info("Running initial analysis after export...")
            analysis_result = analyzer.analyze_last_24h(influx)
            if analysis_result:
                influx.save_analysis_result(analysis_result)
                print("\n=== Gemini AI Analysis ===")
                print(analysis_result)
                print("========================")
                logger.info("Initial analysis saved to waf_predictions")
        else:
            logger.warning("No initial logs found to export")

        last_analysis_time = time.time()

        # Main loop
        while True:
            logs = parser.parse_logs()
            if logs:
                exported = influx.export_log_entries(logs)
                logger.debug(f"Exported {len(logs)} logs")  # Reduced verbosity
                
         # Optional: Run Gemini analysis on recent logs
        if settings.RUN_INITIAL_ANALYSIS and exported > 0:
            logger.info("Running Gemini analysis on latest data...")
            analysis_result = analyzer.analyze_last_24h(influx)
            if analysis_result:
                influx.save_analysis_result(analysis_result)
                logger.info("Gemini analysis result saved.")
                
            # Periodic analysis (every 24 hours)
            current_time = time.time()
            if current_time - last_analysis_time >= 86400:
                if logs:  # Only analyze if new logs were processed
                    logger.info("Running periodic analysis...")
                    analysis_result = analyzer.analyze_last_24h(influx)
                    if analysis_result:
                        influx.save_analysis_result(analysis_result)
                        logger.info("Periodic analysis saved")
                last_analysis_time = current_time

            time.sleep(settings.POLL_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Shutting down WAF monitor...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)

if __name__ == "__main__":
    main()
