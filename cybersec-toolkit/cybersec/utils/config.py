"""Configuration management for the Cybersecurity Toolkit."""
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "log_level": "INFO",
    "output_format": "markdown",
    "scan": {
        "cores": 4,
        "deep_scan": False,
        "check_hidden_files": True,
        "timeout": 30,
        "max_file_size": 10485760,  # 10MB
    },
    "network": {
        "ports_to_check": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080],
        "timeout": 5,
        "scan_range": "192.168.1.0/24",
    },
    "firewall": {
        "ban_duration": 3600,  # 1 hour
        "threshold": 5,
        "auto_ban": True,
        "ban_reason": "Automated security ban",
    },
    "docker": {
        "check_running_containers": True,
        "check_exposed_ports": True,
        "internal_networks": ["bridge", "host"],
        "ignored_ports": [53, 123],  # DNS, NTP
    },
    "reporting": {
        "output_dir": "~/cybersec_reports",
        "keep_history": 10,
        "include_sensitive": False,
    }
}


class ConfigManager:
    """Manages configuration for the Cybersecurity Toolkit."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_path: Optional path to config file. If None, will search in standard locations.
        """
        self.config_path = config_path
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file or use defaults."""
        config_paths = [
            self.config_path,
            os.path.expanduser("~/.cybersec/config.yaml"),
            "/etc/cybersec/config.yaml",
            os.path.join(os.path.dirname(__file__), "../../config/cybersec.yaml")
        ]
        
        for path in config_paths:
            if path and os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        file_config = yaml.safe_load(f)
                        if file_config:
                            # Deep merge config
                            self._deep_merge(self.config, file_config)
                            logger.info(f"Loaded configuration from {path}")
                            return
                except Exception as e:
                    logger.warning(f"Could not load config from {path}: {e}")
        
        logger.info("Using default configuration")
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        """Deep merge override dict into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (dot notation).
        
        Args:
            key: Configuration key in dot notation (e.g., 'network.timeout')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key (dot notation).
        
        Args:
            key: Configuration key in dot notation
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save_config(self, path: str) -> None:
        """Save current configuration to file.
        
        Args:
            path: Path to save configuration file
        """
        path_obj = Path(path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to default values."""
        self.config = DEFAULT_CONFIG.copy()
    
    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config.copy()


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get global configuration manager instance.
    
    Returns:
        Configuration manager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager