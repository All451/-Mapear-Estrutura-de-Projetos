"""
Basic test suite for the Cybersecurity Toolkit
This module provides unit tests for the cybersecurity tools.
"""
import unittest
import os
import tempfile
from cybersec_config import CybersecConfig
from cybersec_logging import CybersecLogger


class TestCybersecConfig(unittest.TestCase):
    """
    Test cases for the Cybersecurity Configuration system
    """
    
    def setUp(self):
        """
        Set up test fixtures before each test method.
        """
        self.test_config_file = "test_config.yaml"
    
    def tearDown(self):
        """
        Clean up after each test method.
        """
        if os.path.exists(self.test_config_file):
            os.remove(self.test_config_file)
    
    def test_default_config(self):
        """
        Test that default configuration is loaded when no config file exists
        """
        config = CybersecConfig(self.test_config_file)
        self.assertEqual(config.get('general.log_level'), 'INFO')
        self.assertEqual(config.get('security.scan_depth'), 2)
        self.assertTrue(config.get('security.check_permissions'))
    
    def test_custom_config(self):
        """
        Test loading custom configuration from file
        """
        # Create a sample config file
        sample_config = """
general:
  log_level: DEBUG
  output_format: json
security:
  scan_depth: 3
  include_hidden: True
"""
        with open(self.test_config_file, 'w') as f:
            f.write(sample_config)
        
        config = CybersecConfig(self.test_config_file)
        self.assertEqual(config.get('general.log_level'), 'DEBUG')
        self.assertEqual(config.get('general.output_format'), 'json')
        self.assertEqual(config.get('security.scan_depth'), 3)
        self.assertTrue(config.get('security.include_hidden'))
    
    def test_config_get_with_default(self):
        """
        Test getting configuration with default value
        """
        config = CybersecConfig(self.test_config_file)
        # Test existing key
        self.assertEqual(config.get('general.log_level'), 'INFO')
        # Test non-existing key with default
        self.assertEqual(config.get('non.existing.key', 'default'), 'default')
        # Test non-existing key without default
        self.assertIsNone(config.get('non.existing.key'))
    
    def test_config_set_and_get(self):
        """
        Test setting and getting configuration values
        """
        config = CybersecConfig(self.test_config_file)
        # Set a new value
        config.set('general.test_value', 'test')
        # Get the value back
        self.assertEqual(config.get('general.test_value'), 'test')
    
    def test_config_save(self):
        """
        Test saving configuration to file
        """
        config = CybersecConfig(self.test_config_file)
        config.set('general.test_save', 'value')
        result = config.save()
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.test_config_file))


class TestCybersecLogger(unittest.TestCase):
    """
    Test cases for the Cybersecurity Logging system
    """
    
    def setUp(self):
        """
        Set up test fixtures before each test method.
        """
        self.test_log_file = "./test_cybersec.log"
        # Clean up any existing test log file
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)
    
    def tearDown(self):
        """
        Clean up after each test method.
        """
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)
    
    def test_logger_initialization(self):
        """
        Test that logger is properly initialized
        """
        logger = CybersecLogger("test_logger", self.test_log_file, "DEBUG", force_new=True)
        self.assertIsNotNone(logger.get_logger())
        self.assertEqual(logger.get_logger().name, "test_logger")
    
    def test_log_security_event(self):
        """
        Test logging security events
        """
        logger = CybersecLogger("test_logger", self.test_log_file, "DEBUG", force_new=True)
        
        # Test basic security event logging
        logger.log_security_event("test_event", "This is a test event")
        
        # Verify log file was created
        self.assertTrue(os.path.exists(self.test_log_file))
    
    def test_log_scan_result(self):
        """
        Test logging scan results
        """
        logger = CybersecLogger("test_logger", self.test_log_file, "DEBUG", force_new=True)
        
        # Test with findings
        logger.log_scan_result("test", "target", ["finding1", "finding2"])
        
        # Test without findings
        logger.log_scan_result("test", "target")
        
        # Verify log file was created
        self.assertTrue(os.path.exists(self.test_log_file))
    
    def test_log_firewall_action(self):
        """
        Test logging firewall actions
        """
        logger = CybersecLogger("test_logger", self.test_log_file, "DEBUG", force_new=True)
        
        # Test firewall action logging
        logger.log_firewall_action("ban", "127.0.0.1", "test reason")
        
        # Verify log file was created
        self.assertTrue(os.path.exists(self.test_log_file))


class TestIntegration(unittest.TestCase):
    """
    Integration tests for the cybersecurity toolkit components
    """
    
    def test_config_and_logger_integration(self):
        """
        Test that config and logger can work together
        """
        # Create a config
        config = CybersecConfig()
        
        # Use config values to initialize logger
        log_level = config.get('general.log_level', 'INFO')
        log_file = "/tmp/integration_test.log"
        
        logger = CybersecLogger("integration_test", log_file, log_level)
        
        # Log something using the logger
        logger.log_security_event("integration", "Config and logger working together")
        
        # Verify the log was created
        self.assertTrue(os.path.exists(log_file))
        
        # Clean up
        if os.path.exists(log_file):
            os.remove(log_file)


def run_tests():
    """
    Run all tests in the suite
    """
    # Create a test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__name__)
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == '__main__':
    print("Running Cybersecurity Toolkit Test Suite...")
    run_tests()