import logging
import os
import time
from typing import Optional


class LocalTimezoneFormatter(logging.Formatter):
    """Custom formatter that uses local timezone"""

    def formatTime(
        self, record: logging.LogRecord, datefmt: Optional[str] = None
    ) -> str:
        # Convert UTC to local time
        ct = self.converter(record.created)
        if datefmt:
            return time.strftime(datefmt, ct)
        return time.strftime("%Y-%m-%d %H:%M:%S", ct)


# Define format
FORMATTER = LocalTimezoneFormatter(
    fmt="%(asctime)s | %(levelname)-8s | %(filename)s:%(lineno)d | %(funcName)s() | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def get_logger(
    name: str = __name__,
    level: int = os.getenv("APP_LOG_LEVEL", logging.WARNING),
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    #
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Console handler
    add_handler_to_logger(logger)

    return logger


def add_handler_to_logger(logger):
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(FORMATTER)
    logger.addHandler(console_handler)
