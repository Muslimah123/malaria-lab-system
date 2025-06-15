import logging
import os
from logging.handlers import RotatingFileHandler
import sys

def setup_logging(log_dir: str = "logs", log_file: str = "app.log", log_level: int = logging.INFO) -> logging.Logger:
    """Configure logging with file rotation only."""
    try:
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, log_file)

        logger = logging.getLogger()
        logger.setLevel(log_level)

        # Remove existing handlers to prevent duplicate logging
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # File handler with rotation
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
        )
        logger.addHandler(file_handler)

        logger.info("Logging configuration completed")
        return logger

    except Exception as e:
        print(f"Failed to setup logging: {str(e)}", file=sys.stderr)
        raise