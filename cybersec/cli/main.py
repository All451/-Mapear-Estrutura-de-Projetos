"""Main CLI module for the cybersecurity toolkit."""
import click

from cybersec.cli.commands import (
    scan_cmd, firewall_status, ban_cmd, unban_cmd, list_banned, 
    check_cmd, ports_cmd, check_port_cmd, docker_scan_cmd, 
    docker_report_cmd, config_show, report_generate
)


@click.group()
@click.version_option(version='3.0.0')
def cli():
    """Cybersecurity Toolkit - A comprehensive security scanning tool."""
    pass


# Add commands to the CLI
cli.add_command(scan_cmd, name='scan')
cli.add_command(firewall_status, name='firewall-status')
cli.add_command(ban_cmd, name='ban')
cli.add_command(unban_cmd, name='unban')
cli.add_command(list_banned, name='list-banned')
cli.add_command(check_cmd, name='check')
cli.add_command(ports_cmd, name='ports')
cli.add_command(check_port_cmd, name='check-port')
cli.add_command(docker_scan_cmd, name='docker-scan')
cli.add_command(docker_report_cmd, name='docker-report')
cli.add_command(config_show, name='config-show')
cli.add_command(report_generate, name='report-generate')


if __name__ == '__main__':
    cli()