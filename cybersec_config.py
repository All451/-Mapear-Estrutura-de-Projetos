"""
Cybersecurity Toolkit Configuration System
This module provides configuration management for the cybersecurity toolkit.
"""
import os
import json
import yaml
from typing import Dict, Any, Optional


class CybersecConfig:
    """
    Configuration management for the cybersecurity toolkit
    """
    
    def __init__(self, config_file: str = "cybersec.config.yaml"):
        """
        Initialize the configuration system
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file or use defaults
        
        Returns:
            Dictionary containing configuration values
        """
        # Default configuration
        default_config = {
            "general": {
                "log_level": "INFO",
                "output_format": "markdown",
                "color_output": True,
                "verbose": False
            },
            "security": {
                "scan_depth": 2,
                "include_hidden": False,
                "check_permissions": True,
                "detect_sensitive_files": True
            },
            "network": {
                "ufw_enabled": True,
                "check_ports": [22, 80, 443, 3306, 5432],
                "scan_network_interfaces": True
            },
            "firewall": {
                "ban_duration": 3600,
                "auto_ban_threshold": 5,
                "log_file": "/var/log/auth.log"
            },
            "docker": {
                "check_exposure": True,
                "internal_networks": ["172.17.0.0/16"],
                "check_running_containers": True
            }
        }
        
        # Try to load from file if it exists
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = yaml.safe_load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._merge_config(default_config, file_config)
            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")
                return default_config
        else:
            return default_config
    
    def _merge_config(self, default: Dict, override: Optional[Dict]) -> Dict:
        """
        Merge default configuration with override configuration
        
        Args:
            default: Default configuration dictionary
            override: Override configuration dictionary
            
        Returns:
            Merged configuration dictionary
        """
        if override is None:
            return default
            
        result = default.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
                
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation
        
        Args:
            key: Configuration key in dot notation (e.g., 'general.log_level')
            default: Default value if key is not found
            
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
        """
        Set a configuration value using dot notation
        
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
    
    def save(self, config_file: Optional[str] = None) -> bool:
        """
        Save configuration to file
        
        Args:
            config_file: File to save to (uses default if not provided)
            
        Returns:
            True if successful, False otherwise
        """
        if config_file is None:
            config_file = self.config_file
            
        try:
            with open(config_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get the entire configuration dictionary
        
        Returns:
            Complete configuration dictionary
        """
        return self.config


def create_sample_config(filename: str = "cybersec.config.yaml") -> None:
    """
    Create a sample configuration file
    
    Args:
        filename: Name of the configuration file to create
    """
    sample_config = {
        "general": {
            "log_level": "INFO",
            "output_format": "markdown",
            "color_output": True,
            "verbose": False
        },
        "security": {
            "scan_depth": 2,
            "include_hidden": False,
            "check_permissions": True,
            "detect_sensitive_files": True
        },
        "network": {
            "ufw_enabled": True,
            "check_ports": [22, 80, 443, 3306, 5432],
            "scan_network_interfaces": True
        },
        "firewall": {
            "ban_duration": 3600,
            "auto_ban_threshold": 5,
            "log_file": "/var/log/auth.log"
        },
        "docker": {
            "check_exposure": True,
            "internal_networks": ["172.17.0.0/16"],
            "check_running_containers": True
        }
    }
    
    with open(filename, 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False)
    
    print(f"Sample configuration created: {filename}")


if __name__ == "__main__":
    # Example usage
    config = CybersecConfig()
    
    print("Current configuration:")
    print(json.dumps(config.get_all(), indent=2))
    
    print(f"\nLog level: {config.get('general.log_level')}")
    print(f"Scan depth: {config.get('security.scan_depth')}")
    
    # Example of creating a sample config
    if not os.path.exists("cybersec.config.yaml"):
        create_sample_config()