#!/usr/bin/env python3
"""
SONiC Mgmt Metadata Validator with Enhanced OOP Architecture

This script validates the integrity and consistency of testbed configurations,
network topologies, and inventory data across the SONiC management infrastructure
using a flexible, configuration-driven approach.
"""

import sys
import argparse
import logging

from config_loader import create_sample_config_file
from validators import get_default_registry
from validator_runner import MetaValidator


def setup_logging(log_level=logging.INFO):
    """Setup logging configuration"""
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='SONiC Mgmt Metadata Validator')
    parser.add_argument(
        '--config', '-c',
        help='Path to validator configuration file (YAML or JSON)'
    )
    parser.add_argument(
        '--graph-groups', '-gg',
        default='ansible/files/graph_groups.yml',
        help='Path to graph groups file (default: ansible/files/graph_groups.yml)'
    )
    parser.add_argument(
        '--testbed-config', '-t',
        default='ansible/testbed.yaml',
        help='Path to testbed configuration file (default: ansible/testbed.yaml)'
    )
    parser.add_argument(
        '--testbed-nut-config', '-tn',
        default='ansible/testbed.nut.yaml',
        help='Path to NUT testbed configuration file (default: ansible/testbed.nut.yaml)'
    )
    parser.add_argument(
        '--fail-fast',
        action='store_true',
        help='Stop validation on the first error'
    )
    parser.add_argument(
        '--warnings-as-errors',
        action='store_true',
        help='Treat all warnings as errors'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--group', '-g',
        nargs='*',
        metavar='GROUP',
        help='Validate specific groups only (space-separated list)'
    )
    parser.add_argument(
        '--create-sample-config', '-s',
        metavar='FILE',
        help='Create a sample configuration file and exit'
    )
    parser.add_argument(
        '--list-validators', '-l',
        action='store_true',
        help='List available validators and exit'
    )
    parser.add_argument(
        '--report-level', '-r',
        choices=['summary', 'errors', 'full'],
        default='summary',
        help=('Output issue level: summary (only summary), errors (summary and all errors), '
              'full (summary, all errors and warnings) (default: summary)')
    )
    parser.add_argument(
        '--enable-validators', '-e',
        nargs='*',
        metavar='VALIDATOR',
        help='Enable only these validators (space-separated list)'
    )
    parser.add_argument(
        '--disable-validators', '-d',
        nargs='*',
        metavar='VALIDATOR',
        help='Disable these validators (space-separated list)'
    )
    parser.add_argument(
        '--output-format', '-o',
        choices=['text', 'json', 'yaml'],
        default='text',
        help='Output format for results (default: text)'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress logging output and only show the report'
    )

    return parser.parse_args()


def handle_special_commands(args):
    """Handle special commands that exit early"""
    if args.create_sample_config:
        create_sample_config_file(args.create_sample_config)
        return True

    if args.list_validators:
        registry = get_default_registry()
        print("Available validators:")
        for validator_name in registry.list_validators():
            info = registry.get_validator_info(validator_name)
            print(f"  {validator_name}: {info.get('description', 'No description')}")
        return True

    return False


def apply_validator_filters(config, enable_validators, disable_validators, logger):
    """
    Apply validator enable/disable filters to configuration

    Args:
        config: ValidationConfig object
        enable_validators: List of validators to enable (None means all enabled)
        disable_validators: List of validators to disable (None means none disabled)
        logger: Logger instance

    Returns:
        ValidationConfig: Updated configuration with filters applied
    """
    from config_loader import ValidationConfig

    # Get current validator configs
    validator_configs = config.get_validator_configs().copy()
    available_validators = [v['name'] for v in validator_configs]

    # Validate that specified validators exist
    if enable_validators is not None:
        invalid_validators = [v for v in enable_validators if v not in available_validators]
        if invalid_validators:
            logger.error(f"Invalid validators in --enable-validators: {', '.join(invalid_validators)}")
            logger.error(f"Available validators: {', '.join(available_validators)}")
            sys.exit(1)

    if disable_validators is not None:
        invalid_validators = [v for v in disable_validators if v not in available_validators]
        if invalid_validators:
            logger.error(f"Invalid validators in --disable-validators: {', '.join(invalid_validators)}")
            logger.error(f"Available validators: {', '.join(available_validators)}")
            sys.exit(1)

    # Apply filters
    if enable_validators is not None:
        # If enable list specified, disable all others
        for validator_config in validator_configs:
            validator_config['enabled'] = validator_config['name'] in enable_validators
        logger.info(f"Enabled validators: {', '.join(enable_validators)}")

    if disable_validators is not None:
        # Disable specified validators
        for validator_config in validator_configs:
            if validator_config['name'] in disable_validators:
                validator_config['enabled'] = False
        logger.info(f"Disabled validators: {', '.join(disable_validators)}")

    # Create new config with updated validators
    config_dict = config.config_dict.copy()
    config_dict['validators'] = validator_configs

    return ValidationConfig(config_dict)


def main():
    """Main validation function using OOP design"""
    args = parse_arguments()

    # Handle special commands that exit early
    if handle_special_commands(args):
        return

    # Setup logging (disable if quiet mode)
    if not args.quiet:
        log_level = logging.DEBUG if args.verbose else logging.INFO
        setup_logging(log_level)
        logger = logging.getLogger('meta_validator')
        logger.info("Starting SONiC Mgmt metadata validation")
    else:
        # In quiet mode, disable all logging
        setup_logging(logging.CRITICAL)
        logger = logging.getLogger('meta_validator')

    # Create MetaValidator instance
    validator = MetaValidator(logger)

    try:
        # Load configuration
        config = validator.load_configuration(args.config)

        # Apply validator enable/disable filters
        if args.enable_validators is not None or args.disable_validators is not None:
            config = apply_validator_filters(config, args.enable_validators, args.disable_validators, logger)
            # Reload validators with filtered config
            validator.config = config
            validator.validators = validator.config_manager.create_validators_from_config(config)

        # Load testbed data
        validator.load_testbed_data(
            testbed_config_path=args.testbed_config,
            testbed_nut_config_path=args.testbed_nut_config,
            graph_groups_path=args.graph_groups,
            specific_groups=args.group
        )

        # Run validation
        results = validator.run_validation(
            fail_fast=args.fail_fast,
            warnings_as_errors=args.warnings_as_errors
        )

        # Print results and exit
        validator.print_results(results, report_level=args.report_level, output_format=args.output_format)
        exit_code = 0 if results.overall_success else 1
        sys.exit(exit_code)

    except Exception as e:
        logger.error(f"Validation failed with error: {e}")
        if args.verbose:
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == '__main__':
    main()
