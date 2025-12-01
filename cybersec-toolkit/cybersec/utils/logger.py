"""Professional logging system for the Cybersecurity Toolkit."""
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

# Custom formatter with colors
class ColoredFormatter(logging.Formatter):
    """Custom colored formatter for console output."""
    
    # Color codes
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    def format(self, record):
        # Add color to levelname
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        
        return super().format(record)


class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for machine-readable logs."""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'getMessage', 'exc_info', 
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry)


class LoggerManager:
    """Manages logging configuration for the Cybersecurity Toolkit."""
    
    def __init__(self, name: str = "cybersec", log_level: str = "INFO"):
        """Initialize logger manager.
        
        Args:
            name: Name of the logger
            log_level: Initial log level
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_console_handler()
            self._setup_file_handler()
    
    def _setup_console_handler(self):
        """Setup console logging handler with colored output."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Use colored formatter for console
        colored_format = "%(levelname)s | %(asctime)s | %(name)s | %(funcName)s:%(lineno)d | %(message)s"
        colored_formatter = ColoredFormatter(colored_format, datefmt="%Y-%m-%d %H:%M:%S")
        console_handler.setFormatter(colored_formatter)
        
        self.logger.addHandler(console_handler)
    
    def _setup_file_handler(self):
        """Setup file logging handler with structured output."""
        # Create logs directory
        log_dir = Path.home() / ".cybersec" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler for detailed logs
        log_file = log_dir / "cybersec.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Use structured formatter for files
        structured_formatter = StructuredFormatter()
        file_handler.setFormatter(structured_formatter)
        
        self.logger.addHandler(file_handler)
    
    def set_level(self, level: str):
        """Set logging level.
        
        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.logger.setLevel(getattr(logging, level.upper()))
    
    def enable_json_logging(self):
        """Enable JSON structured logging."""
        # Remove existing file handlers
        for handler in self.logger.handlers[:]:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                self.logger.removeHandler(handler)
        
        # Create logs directory
        log_dir = Path.home() / ".cybersec" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON file handler
        json_log_file = log_dir / "cybersec.json"
        json_handler = logging.handlers.RotatingFileHandler(
            json_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
        )
        json_handler.setLevel(logging.DEBUG)
        
        # Use structured formatter
        structured_formatter = StructuredFormatter()
        json_handler.setFormatter(structured_formatter)
        
        self.logger.addHandler(json_handler)
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance.
        
        Returns:
            Configured logger instance
        """
        return self.logger


# Global logger instance
_logger_manager: Optional[LoggerManager] = None
_global_logger: Optional[logging.Logger] = None


def get_logger(name: str = "cybersec", log_level: str = "INFO") -> logging.Logger:
    """Get logger instance with specified name and level.
    
    Args:
        name: Name of the logger
        log_level: Logging level
        
    Returns:
        Configured logger instance
    """
    global _logger_manager, _global_logger
    
    if _global_logger is None or _logger_manager.name != name:
        _logger_manager = LoggerManager(name, log_level)
        _global_logger = _logger_manager.get_logger()
    
    return _global_logger


def setup_logging(config_log_level: str = "INFO") -> logging.Logger:
    """Setup logging based on configuration.
    
    Args:
        config_log_level: Log level from configuration
        
    Returns:
        Configured logger instance
    """
    return get_logger("cybersec", config_log_level)