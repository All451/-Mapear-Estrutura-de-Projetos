"""Configuration manager module for the cybersecurity toolkit."""
import yaml
import logging
from typing import Any, Dict, Optional


class ConfigManager:
    """Configuration manager for the cybersecurity toolkit."""

    def __init__(self, config_file: str):
        """
        Initialize the configuration manager.
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
        self.load_config()

    def load_config(self):
        """Load configuration from file."""
        try:
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f)
            self.logger.info(f"Configuration loaded from {self.config_file}")
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {self.config_file}")
            raise
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing YAML configuration: {e}")
            raise

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation (e.g., 'logging.level')
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any):
        """
        Set a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation
            value: Value to set
        """
        keys = key.split('.')
        config_ref = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config_ref:
                config_ref[k] = {}
            config_ref = config_ref[k]
        
        # Set the final key
        config_ref[keys[-1]] = value

    def update(self, updates: Dict[str, Any]):
        """
        Update configuration with a dictionary of values.
        
        Args:
            updates: Dictionary of configuration updates
        """
        for key, value in updates.items():
            self.set(key, value)

    def save_config(self, config_file: Optional[str] = None):
        """
        Save the current configuration to a file.
        
        Args:
            config_file: File to save to (uses original if not provided)
        """
        save_file = config_file or self.config_file
        try:
            with open(save_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            self.logger.info(f"Configuration saved to {save_file}")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")