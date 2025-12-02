"""Unit tests for the config module."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
import yaml

from cybersec.utils.config import ConfigManager


class TestConfigManager:
    """Test class for ConfigManager."""

    def test_config_manager_initialization(self, temp_config_file):
        """Test config manager initialization."""
        config_manager = ConfigManager(temp_config_file)
        
        assert config_manager.config_file == temp_config_file
        assert 'logging' in config_manager.config
        assert 'scanner' in config_manager.config

    def test_load_config_success(self, temp_config_file):
        """Test loading config from file."""
        config_manager = ConfigManager(temp_config_file)
        
        # Config should be loaded during initialization
        assert config_manager.config is not None
        assert 'logging' in config_manager.config
        assert 'level' in config_manager.config['logging']

    def test_load_config_file_not_found(self):
        """Test loading config from non-existent file."""
        with pytest.raises(FileNotFoundError):
            ConfigManager('/nonexistent/config.yaml')

    @patch('builtins.open', side_effect=PermissionError("Permission denied"))
    def test_load_config_permission_error(self, mock_open, temp_config_file):
        """Test loading config when permission is denied."""
        with pytest.raises(PermissionError):
            ConfigManager(temp_config_file)

    @patch('yaml.safe_load', side_effect=yaml.YAMLError("Invalid YAML"))
    def test_load_config_invalid_yaml(self, mock_yaml_load, temp_config_file):
        """Test loading config from invalid YAML file."""
        with pytest.raises(yaml.YAMLError):
            ConfigManager(temp_config_file)

    def test_get_config_value_success(self, temp_config_file):
        """Test getting a specific config value."""
        config_manager = ConfigManager(temp_config_file)
        
        level = config_manager.get('logging.level')
        assert level == 'INFO'
        
        timeout = config_manager.get('network.timeout')
        assert timeout == 5

    def test_get_config_value_nested(self, temp_config_file):
        """Test getting a nested config value."""
        config_manager = ConfigManager(temp_config_file)
        
        format_value = config_manager.get('logging.format')
        assert 'levelname' in format_value

    def test_get_config_value_default(self, temp_config_file):
        """Test getting a config value with default."""
        config_manager = ConfigManager(temp_config_file)
        
        # Test with existing key
        value = config_manager.get('logging.level', 'DEBUG')
        assert value == 'INFO'  # Should return actual value, not default
        
        # Test with non-existing key
        value = config_manager.get('nonexistent.key', 'default_value')
        assert value == 'default_value'

    def test_get_config_value_nonexistent(self, temp_config_file):
        """Test getting a non-existent config value."""
        config_manager = ConfigManager(temp_config_file)
        
        value = config_manager.get('nonexistent.key')
        assert value is None

    def test_set_config_value(self, temp_config_file):
        """Test setting a config value."""
        config_manager = ConfigManager(temp_config_file)
        
        # Set a new value
        config_manager.set('logging.level', 'DEBUG')
        
        # Verify it was set
        assert config_manager.get('logging.level') == 'DEBUG'

    def test_set_config_value_nested(self, temp_config_file):
        """Test setting a nested config value."""
        config_manager = ConfigManager(temp_config_file)
        
        # Set a nested value
        config_manager.set('scanner.new_option', 'test_value')
        
        # Verify it was set
        assert config_manager.get('scanner.new_option') == 'test_value'

    def test_set_config_value_creates_nested(self, temp_config_file):
        """Test setting a deeply nested config value creates intermediate keys."""
        config_manager = ConfigManager(temp_config_file)
        
        # Set a deeply nested value
        config_manager.set('new_section.subsection.value', 'test')
        
        # Verify the structure was created
        assert config_manager.get('new_section.subsection.value') == 'test'

    def test_update_config(self, temp_config_file):
        """Test updating config with a dictionary."""
        config_manager = ConfigManager(temp_config_file)
        
        # Update with new values
        updates = {
            'logging.level': 'WARNING',
            'scanner.timeout': 60
        }
        config_manager.update(updates)
        
        # Verify the updates
        assert config_manager.get('logging.level') == 'WARNING'
        assert config_manager.get('scanner.timeout') == 60

    def test_reset_config(self, temp_config_file):
        """Test resetting config to defaults."""
        config_manager = ConfigManager(temp_config_file)
        
        # Change a value
        config_manager.set('logging.level', 'DEBUG')
        assert config_manager.get('logging.level') == 'DEBUG'
        
        # Reload from file to reset
        original_level = config_manager.get('logging.level')
        config_manager = ConfigManager(temp_config_file)  # Reinitialize
        new_level = config_manager.get('logging.level')
        
        # The value should be back to original
        assert new_level == original_level

    def test_config_validation(self, temp_config_file):
        """Test basic config validation."""
        config_manager = ConfigManager(temp_config_file)
        
        # Check that required sections exist
        assert 'logging' in config_manager.config
        assert 'scanner' in config_manager.config
        assert 'network' in config_manager.config
        assert 'firewall' in config_manager.config
        assert 'docker' in config_manager.config

    def test_config_get_with_dot_notation(self, temp_config_file):
        """Test getting config values with dot notation."""
        config_manager = ConfigManager(temp_config_file)
        
        # Test various levels of nesting
        level = config_manager.get('logging.level')
        assert level == 'INFO'
        
        ports = config_manager.get('network.ports_to_check')
        assert isinstance(ports, list)
        assert 22 in ports

    def test_config_set_with_dot_notation(self, temp_config_file):
        """Test setting config values with dot notation."""
        config_manager = ConfigManager(temp_config_file)
        
        # Set at various levels
        config_manager.set('logging.level', 'ERROR')
        assert config_manager.get('logging.level') == 'ERROR'
        
        config_manager.set('network.timeout', 10)
        assert config_manager.get('network.timeout') == 10

    def test_config_persistence(self, temp_config_file):
        """Test that config changes can be saved and loaded."""
        # Create a temporary file for this test
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            initial_config = {
                'logging': {'level': 'INFO'},
                'scanner': {'timeout': 30}
            }
            yaml.dump(initial_config, f)
            temp_path = f.name
        
        try:
            # Load, modify, and check
            config_manager = ConfigManager(temp_path)
            config_manager.set('logging.level', 'DEBUG')
            
            # Create new instance and check if changes persist
            # Note: In this implementation, we're not saving to file automatically
            # so the change won't persist unless explicitly saved
            new_config_manager = ConfigManager(temp_path)
            # The original value should still be there since we didn't save
            assert new_config_manager.get('logging.level') == 'INFO'
        finally:
            os.unlink(temp_path)

    def test_config_deep_get(self, temp_config_file):
        """Test getting deeply nested config values."""
        config_manager = ConfigManager(temp_config_file)
        
        # Add a deeply nested structure
        config_manager.set('a.b.c.d.e', 'deep_value')
        
        # Get the deeply nested value
        value = config_manager.get('a.b.c.d.e')
        assert value == 'deep_value'

    def test_config_special_characters(self, temp_config_file):
        """Test config with special characters in keys."""
        config_manager = ConfigManager(temp_config_file)
        
        # Set and get values with special characters in keys
        config_manager.set('test-key_with.special/chars', 'value')
        value = config_manager.get('test-key_with.special/chars')
        assert value == 'value'

    def test_config_none_values(self, temp_config_file):
        """Test config with None values."""
        config_manager = ConfigManager(temp_config_file)
        
        # Set a None value
        config_manager.set('test.none_value', None)
        value = config_manager.get('test.none_value')
        assert value is None

    def test_config_numeric_values(self, temp_config_file):
        """Test config with numeric values."""
        config_manager = ConfigManager(temp_config_file)
        
        # Test various numeric types
        config_manager.set('test.integer', 42)
        config_manager.set('test.float', 3.14)
        config_manager.set('test.zero', 0)
        
        assert config_manager.get('test.integer') == 42
        assert config_manager.get('test.float') == 3.14
        assert config_manager.get('test.zero') == 0