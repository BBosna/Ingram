import os
from collections import defaultdict
from loguru import logger

from . import timer


class ErrorLogger:
    def __init__(self, config):
        self.error_file = os.path.join(config.out_dir, "error_details.log")
        self.error_summary = defaultdict(lambda: defaultdict(int))

    def log_error(self, error_type, ip, port, details):
        timestamp = timer.get_time_formatted()
        error_msg = f"[{timestamp}] {error_type} - {ip}:{port} - {details}"

        logger.error(error_msg)
        self.error_summary[error_type]["count"] += 1
        self.error_summary[error_type]["last_seen"] = timestamp

        with open(self.error_file, "a") as f:
            f.write(f"{error_msg}\n")

    def get_summary(self):
        return {
            error_type: {"count": stats["count"], "last_seen": stats["last_seen"]}
            for error_type, stats in self.error_summary.items()
        }
