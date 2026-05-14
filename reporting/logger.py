"""
Structured Logging for CamHunter v2.0
"""

import logging
import sys
import os
from logging.handlers import RotatingFileHandler

def setup_logger(cfg: dict):
    log_cfg = cfg.get("logging", {})
    level_name = log_cfg.get("level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    
    log_file = log_cfg.get("file", "logs/camhunter.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = logging.getLogger("camhunter")
    logger.setLevel(level)
    
    # Formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '[%(levelname)s] %(message)s'
    )
    
    # File Handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=log_cfg.get("max_file_size", 10485760),
        backupCount=log_cfg.get("backup_count", 5)
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console Handler
    if log_cfg.get("console", True):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        # We might want to keep console cleaner if using 'rich'
        # logger.addHandler(console_handler) 
    
    # Redirect other loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    return logger
