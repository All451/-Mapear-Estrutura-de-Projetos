"""Main entry point for the Cybersecurity Toolkit CLI."""
import sys
import os
from typing import NoReturn

# Add the project root to the path to ensure imports work correctly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from cybersec.cli.parser import parse_args
from cybersec.cli.commands import CommandHandler
from cybersec.utils.logger import setup_logging


def main() -> NoReturn:
    """Main entry point for the CLI application."""
    try:
        # Parse command line arguments
        args = parse_args()
        
        # Setup logging
        logger = setup_logging()
        
        # Create command handler
        handler = CommandHandler()
        
        # Route to appropriate handler based on command
        if args.command == 'scan':
            exit_code = handler.handle_scan(args)
        elif args.command == 'firewall':
            exit_code = handler.handle_firewall(args)
        elif args.command == 'network':
            exit_code = handler.handle_network(args)
        elif args.command == 'docker':
            exit_code = handler.handle_docker(args)
        elif args.command == 'config':
            exit_code = handler.handle_config(args)
        elif args.command == 'report':
            exit_code = handler.handle_report(args)
        elif args.command is None:
            # No command specified, show help
            from cybersec.cli.parser import create_parser
            create_parser().print_help()
            exit_code = 0
        else:
            print(f"Unknown command: {args.command}")
            exit_code = 1
        
        sys.exit(exit_code)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()