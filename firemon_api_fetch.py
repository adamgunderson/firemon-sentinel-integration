#!/usr/bin/env python3
# firemon_api_fetch.py
# This script fetches detailed information about FireMon changes and forwards it to Sentinel

import argparse
import json
import logging
import os
import requests
import sys
from datetime import datetime
import configparser
from urllib.parse import quote

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/firemon_api_fetch.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('firemon_api_fetch')

# Load configuration
config = configparser.ConfigParser()
config_file = '/etc/firemon/api_fetch.conf'
if os.path.exists(config_file):
    config.read(config_file)
else:
    logger.warning(f"Config file {config_file} not found, using default values")
    # Set default values
    config['api'] = {
        'username': 'admin',
        'password': 'passwd',
        'verify_ssl': 'false'
    }
    config['sentinel'] = {
        'enabled': 'true',
        'workspace_id': '',
        'shared_key': '',
        'log_type': 'FireMonChangeLog'
    }

# Configuration globals
API_USERNAME = config['api'].get('username', 'admin')
API_PASSWORD = config['api'].get('password', 'passwd')
VERIFY_SSL = config['api'].getboolean('verify_ssl', False)
SENTINEL_ENABLED = config['sentinel'].getboolean('enabled', True)

def parse_args():
    """Parse command line arguments from syslog-ng"""
    parser = argparse.ArgumentParser(description='Fetch FireMon change details')
    parser.add_argument('--device-name', required=True, help='Device name from syslog')
    parser.add_argument('--revision', required=True, help='Revision number from syslog')
    parser.add_argument('--user', required=True, help='Username from syslog')
    parser.add_argument('--timestamp', required=True, help='Timestamp from syslog')
    parser.add_argument('--server', required=True, help='FireMon server hostname')
    return parser.parse_args()

def get_auth_token(server):
    """Get authentication token from FireMon API"""
    url = f'https://{server}/securitymanager/api/authentication/login'
    headers = {'Content-Type': 'application/json', 'accept': 'application/json'}
    data = {"username": API_USERNAME, "password": API_PASSWORD}
    
    try:
        response = requests.post(url, headers=headers, json=data, verify=VERIFY_SSL)
        response.raise_for_status()
        result = response.json()
        logger.info("Successfully authenticated to FireMon API")
        return result.get('token')
    except Exception as e:
        logger.error(f"Error getting auth token: {str(e)}")
        return None

def get_changelog(server, token, device_id, revision, page=0, page_size=10):
    """Get changelog for a specific revision"""
    url = f'https://{server}/securitymanager/api/domain/1/device/{device_id}/rev/{revision}/changelog'
    headers = {'accept': 'application/json', 'Authorization': f'Bearer {token}'}
    params = {'page': page, 'pageSize': page_size}
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error getting changelog: {str(e)}")
        return None

def get_rules_with_failures(server, token, device_id, timestamp, page=0, page_size=10):
    """Get rules with control failures from the revision timestamp"""
    # Format timestamp for query - ensure it's in the right format
    try:
        # Remove trailing 'Z' if present and add timezone if not
        if timestamp.endswith('Z'):
            timestamp = timestamp[:-1] + '+00:00'
        elif '+' not in timestamp and '-' not in timestamp[-6:]:
            timestamp = timestamp + '+00:00'
            
        # Create datetime object and format for query
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime('%Y-%m-%dT%H:%M:%S%z')
    except Exception as e:
        logger.error(f"Error formatting timestamp {timestamp}: {str(e)}")
        # Fall back to using timestamp as is
        formatted_time = timestamp
    
    # Build and encode the query
    query = f"device {{ id = {device_id} }} AND rule {{ lastchanged > {formatted_time} }} AND control{{ status='FAIL' }}"
    encoded_query = quote(query)
    
    url = f'https://{server}/securitymanager/api/siql/secrule/paged-search'
    headers = {'accept': 'application/json', 'Authorization': f'Bearer {token}'}
    params = {'q': encoded_query, 'page': page, 'pageSize': page_size}
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error getting rules with failures: {str(e)}")
        return None

def get_control_failures(server, token, device_id, policy_uid, rule_uid, page=0, page_size=20):
    """Get control failures for a specific rule"""
    query = f"device {{ id = {device_id} }} AND policy {{ uid = '{policy_uid}' }} AND control {{ status = 'FAIL' }} AND rule {{ uid = '{rule_uid}' }}"
    encoded_query = quote(query)
    
    url = f'https://{server}/securitymanager/api/siql/control/paged-search'
    headers = {'accept': 'application/json', 'Authorization': f'Bearer {token}'}
    params = {
        'q': encoded_query, 
        'page': page, 
        'pageSize': page_size,
        'sortdir': 'asc',
        'sort': 'name'
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error getting control failures: {str(e)}")
        return None

def handle_pagination(func, *args, **kwargs):
    """Handle pagination for API calls"""
    all_results = []
    page = 0
    page_size = kwargs.get('page_size', 10)
    
    while True:
        kwargs['page'] = page
        data = func(*args, **kwargs)
        
        if not data or 'results' not in data or not data['results']:
            break
            
        all_results.extend(data['results'])
        logger.debug(f"Retrieved {len(data['results'])} results, total: {data['total']}")
        
        # Check if we've received all results
        if data['total'] <= (page + 1) * page_size:
            break
            
        page += 1
    
    return all_results

def send_to_sentinel(data):
    """Send collected data to Azure Sentinel"""
    if not SENTINEL_ENABLED:
        logger.info("Sentinel integration disabled, skipping data transmission")
        return True
        
    # Import the sentinel module
    try:
        from sentinel_integration import SentinelIntegration
        
        workspace_id = config['sentinel'].get('workspace_id')
        shared_key = config['sentinel'].get('shared_key')
        log_type = config['sentinel'].get('log_type', 'FireMonChangeLog')
        
        if not workspace_id or not shared_key:
            logger.error("Sentinel workspace ID or shared key not configured")
            return False
            
        sentinel = SentinelIntegration(workspace_id, shared_key, log_type)
        return sentinel.post_data(data)
    except ImportError:
        logger.error("sentinel_integration module not found")
        return False
    except Exception as e:
        logger.error(f"Error sending data to Sentinel: {str(e)}")
        return False

def main():
    args = parse_args()
    
    # Get auth token
    token = get_auth_token(args.server)
    if not token:
        logger.error("Failed to get auth token")
        return 1
    
    # First, we need to get device ID - start with placeholder
    placeholder_device_id = 1
    initial_changelog_data = get_changelog(args.server, token, placeholder_device_id, args.revision)
    
    # Extract actual device ID from changelog
    actual_device_id = None
    if initial_changelog_data and 'results' in initial_changelog_data and initial_changelog_data['results']:
        for entry in initial_changelog_data['results']:
            if 'deviceId' in entry:
                actual_device_id = entry['deviceId']
                break
    
    if not actual_device_id:
        logger.error("Failed to determine device ID from changelog")
        # Continue with placeholder ID as fallback
        actual_device_id = placeholder_device_id
    
    logger.info(f"Using device ID: {actual_device_id}")
    
    # Get all changelog entries for the revision with pagination
    all_changelog_entries = handle_pagination(
        get_changelog, args.server, token, actual_device_id, args.revision, page_size=10
    )
    
    if not all_changelog_entries:
        logger.warning(f"No changelog entries found for revision {args.revision}")
    else:
        logger.info(f"Retrieved {len(all_changelog_entries)} changelog entries")
    
    # Get rules with control failures 
    all_rules_with_failures = handle_pagination(
        get_rules_with_failures, args.server, token, actual_device_id, args.timestamp, page_size=10
    )
    
    if not all_rules_with_failures:
        logger.warning(f"No rules with control failures found for timestamp {args.timestamp}")
    else:
        logger.info(f"Retrieved {len(all_rules_with_failures)} rules with control failures")
    
    # Collect control failures for each rule
    all_control_failures = []
    for rule in all_rules_with_failures:
        policy_uid = rule.get('policy', {}).get('matchId')
        rule_uid = rule.get('matchId')
        
        if policy_uid and rule_uid:
            rule_failures = handle_pagination(
                get_control_failures, args.server, token, actual_device_id, 
                policy_uid, rule_uid, page_size=20
            )
            
            if rule_failures:
                all_control_failures.extend(rule_failures)
                logger.info(f"Found {len(rule_failures)} control failures for rule {rule.get('name', rule_uid)}")
    
    # Prepare data to send to Sentinel
    sentinel_data = {
        'device_name': args.device_name,
        'revision': args.revision,
        'user': args.user,
        'timestamp': args.timestamp,
        'server': args.server,
        'device_id': actual_device_id,
        'changelog': all_changelog_entries,
        'rules_with_failures': all_rules_with_failures,
        'control_failures': all_control_failures
    }
    
    # Save data locally for debugging (optional)
    with open(f'/var/log/firemon/revision_{args.revision}_data.json', 'w') as f:
        json.dump(sentinel_data, f, indent=2)
    
    # Send data to Sentinel
    if send_to_sentinel(sentinel_data):
        logger.info("Successfully sent data to Sentinel")
    else:
        logger.warning("Failed to send data to Sentinel")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logger.exception(f"Unhandled exception: {str(e)}")
        sys.exit(1)