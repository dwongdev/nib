#!/usr/bin/env python3
"""
NIB Omada Bouncer - Push CrowdSec decisions to TP-Link Omada Controller

This script syncs CrowdSec ban decisions to an Omada-managed network by:
1. Fetching active decisions from CrowdSec LAPI
2. Creating/updating an IP Group in Omada Controller
3. The IP Group can be referenced in Gateway ACL rules to block traffic

Requirements:
    pip install requests

Usage:
    # Discover mode - inspect API structure (run this first!)
    python omada-sync.py --discover

    # One-shot sync
    python omada-sync.py

    # Continuous sync (daemon mode)
    python omada-sync.py --daemon

    # Dry run (show what would be synced)
    python omada-sync.py --dry-run

Environment variables:
    CROWDSEC_LAPI_URL    - CrowdSec LAPI URL (default: http://localhost:8080)
    CROWDSEC_LAPI_KEY    - CrowdSec bouncer API key
    OMADA_URL            - Omada Controller URL (e.g., https://192.168.1.10:8043)
    OMADA_USER           - Omada admin username
    OMADA_PASS           - Omada admin password
    OMADA_SITE           - Omada site name (default: Default)
    OMADA_GROUP_NAME     - IP Group name for blocked IPs (default: nib-blocklist)
    SYNC_INTERVAL        - Seconds between syncs in daemon mode (default: 60)

IMPORTANT: Run with --discover first to verify API compatibility with your
Omada Controller version. This will show the exact API responses and help
identify the correct payload format for your setup.
"""

import os
import sys
import json
import time
import logging
import argparse
import requests
from datetime import datetime
from typing import Set, Optional, Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CrowdSecClient:
    """Simple CrowdSec LAPI client"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-Api-Key': api_key,
            'Content-Type': 'application/json'
        })
    
    def get_decisions(self) -> Optional[Set[str]]:
        """Fetch active ban decisions (IP addresses only).
        Returns None on LAPI errors to distinguish from 'no active bans' (empty set)."""
        try:
            response = self.session.get(
                f'{self.url}/v1/decisions',
                params={'type': 'ban'},
                timeout=10
            )
            response.raise_for_status()

            decisions = response.json()
            if not decisions:
                return set()

            # Extract unique IPs
            ips = set()
            for decision in decisions:
                value = decision.get('value', '')
                # Handle CIDR ranges - Omada IP Groups support both single IPs and ranges
                if value:
                    ips.add(value)

            return ips

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch CrowdSec decisions: {e}")
            return None


class OmadaClient:
    """
    TP-Link Omada Controller API client
    
    Based on ghaberek/omada-api patterns and official Omada API documentation.
    Tested with Omada Controller v5.x - API may differ in other versions.
    """
    
    def __init__(self, url: str, username: str, password: str, site: str = 'Default', verify_ssl: bool = False):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Disable SSL warnings if not verifying
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.token = None
        self.omadac_id = None
        self.site_id = None
        self.api_version = None
    
    def _timestamp(self) -> int:
        """Generate timestamp in milliseconds (required by Omada API)"""
        return int(datetime.utcnow().timestamp() * 1000)
    
    def _get_api_info(self) -> Dict[str, Any]:
        """Get API info including omadacId for v5+"""
        response = self.session.get(f'{self.url}/api/info', timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get('errorCode') != 0:
            raise Exception(f"API info failed: {data}")
        return data.get('result', {})
    
    def _build_url(self, path: str) -> str:
        """Build full API URL with omadacId prefix if needed"""
        if self.omadac_id:
            return f'{self.url}/{self.omadac_id}/api/v2{path}'
        return f'{self.url}/api/v2{path}'
    
    def login(self) -> bool:
        """Authenticate with Omada Controller"""
        try:
            # Get API info first (needed for v5+)
            api_info = self._get_api_info()
            self.omadac_id = api_info.get('omadacId', '')
            self.api_version = api_info.get('apiVer', 'unknown')
            
            logger.info(f"Omada API version: {self.api_version}, omadacId: {self.omadac_id or 'none'}")
            
            # Login
            response = self.session.post(
                self._build_url('/login'),
                json={'username': self.username, 'password': self.password},
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get('errorCode') != 0:
                logger.error(f"Login failed: {data.get('msg', 'Unknown error')} (errorCode: {data.get('errorCode')})")
                return False
            
            result = data.get('result', {})
            self.token = result.get('token')
            
            if not self.token:
                logger.error("Login succeeded but no token received")
                return False
            
            # Update session headers with CSRF token
            self.session.headers.update({'Csrf-Token': self.token})
            
            # Get site ID
            self._get_site_id()
            
            logger.info(f"Logged into Omada Controller (site: {self.site}, site_id: {self.site_id})")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to login to Omada: {e}")
            return False
    
    def _get_site_id(self):
        """Get the site key/ID for API calls"""
        response = self.session.get(
            self._build_url('/users/current'),
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get('errorCode') != 0:
            raise Exception(f"Failed to get current user: {data}")
        
        # Find site in privilege list
        result = data.get('result', {})
        sites = result.get('privilege', {}).get('sites', [])
        
        for site in sites:
            if site.get('name') == self.site:
                self.site_id = site.get('key')
                return
        
        # List available sites for debugging
        available = [s.get('name') for s in sites]
        raise Exception(f"Site '{self.site}' not found. Available sites: {available}")
    
    def _api_get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make authenticated GET request"""
        if params is None:
            params = {}
        
        response = self.session.get(
            self._build_url(path),
            params=params,
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get('errorCode') != 0:
            raise Exception(f"API GET {path} failed: {data}")
        
        return data.get('result', {})
    
    def _api_post(self, path: str, json_data: Dict) -> Dict[str, Any]:
        """Make authenticated POST request"""
        params = {
            '_': self._timestamp(),
            'token': self.token
        }
        
        response = self.session.post(
            self._build_url(path),
            params=params,
            json=json_data,
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get('errorCode') != 0:
            raise Exception(f"API POST {path} failed: {data}")
        
        return data.get('result', {})
    
    def _api_patch(self, path: str, json_data: Dict) -> Dict[str, Any]:
        """Make authenticated PATCH request"""
        params = {
            '_': self._timestamp(),
            'token': self.token
        }
        
        response = self.session.patch(
            self._build_url(path),
            params=params,
            json=json_data,
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get('errorCode') != 0:
            raise Exception(f"API PATCH {path} failed: {data}")
        
        return data.get('result', {})
    
    def get_ip_groups(self) -> List[Dict]:
        """
        Get all IP Groups for the site.
        
        IP Groups are type 0 in Omada API:
        - Type 0: IP Group
        - Type 1: IP-Port Group  
        - Type 2: MAC Group
        """
        try:
            # Try with type suffix first (documented approach)
            result = self._api_get(f'/sites/{self.site_id}/setting/profiles/groups/0')
            if isinstance(result, dict) and 'data' in result:
                return result['data']
            elif isinstance(result, list):
                return result
            return []
        except Exception as e:
            logger.warning(f"Failed with /groups/0, trying /groups: {e}")
            # Fallback to generic groups endpoint
            try:
                result = self._api_get(f'/sites/{self.site_id}/setting/profiles/groups')
                if isinstance(result, dict):
                    # Filter to IP groups only
                    all_groups = result.get('data', [])
                    return [g for g in all_groups if g.get('type') == 0]
                return []
            except Exception as e2:
                logger.error(f"Failed to get IP groups: {e2}")
                return []
    
    def find_ip_group(self, name: str) -> Optional[Dict]:
        """Find an IP Group by name"""
        groups = self.get_ip_groups()
        for group in groups:
            if group.get('name') == name:
                return group
        return None
    
    def create_ip_group(self, name: str, ips: Set[str]) -> Dict:
        """
        Create a new IP Group.
        
        Note: The exact payload format may vary by Omada Controller version.
        This uses the format observed in the Omada web UI.
        """
        # Format IPs - observed format from web UI network inspection
        ip_list = [{'ipEntry': ip} for ip in sorted(ips)]
        
        data = {
            'name': name,
            'type': 0,  # IP Group
            'ipList': ip_list
        }
        
        logger.debug(f"Creating IP Group with payload: {json.dumps(data, indent=2)}")
        return self._api_post(f'/sites/{self.site_id}/setting/profiles/groups', data)
    
    def update_ip_group(self, group_id: str, name: str, ips: Set[str]) -> Dict:
        """
        Update an existing IP Group.
        
        Note: The exact payload format may vary by Omada Controller version.
        """
        ip_list = [{'ipEntry': ip} for ip in sorted(ips)]
        
        data = {
            'name': name,
            'type': 0,
            'ipList': ip_list
        }
        
        logger.debug(f"Updating IP Group {group_id} with payload: {json.dumps(data, indent=2)}")
        return self._api_patch(f'/sites/{self.site_id}/setting/profiles/groups/{group_id}', data)
    
    def sync_blocklist(self, group_name: str, ips: Set[str]) -> bool:
        """Sync blocked IPs to an Omada IP Group"""
        try:
            existing = self.find_ip_group(group_name)
            
            if existing:
                # Get group ID - try different field names used by different versions
                group_id = existing.get('groupId') or existing.get('id') or existing.get('_id')
                if not group_id:
                    logger.error(f"Could not find group ID in existing group: {existing}")
                    return False
                
                self.update_ip_group(group_id, group_name, ips)
                logger.info(f"Updated IP Group '{group_name}' with {len(ips)} IPs")
            else:
                # Create new group
                self.create_ip_group(group_name, ips)
                logger.info(f"Created IP Group '{group_name}' with {len(ips)} IPs")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to sync blocklist: {e}")
            return False
    
    def discover(self) -> Dict[str, Any]:
        """
        Discover API structure and dump useful debugging info.
        Run this first to verify compatibility with your Omada Controller.
        """
        info = {
            'api_version': self.api_version,
            'omadac_id': self.omadac_id,
            'site': self.site,
            'site_id': self.site_id,
            'ip_groups': [],
            'endpoints_tested': {}
        }
        
        # Test IP groups endpoint
        try:
            groups = self.get_ip_groups()
            info['ip_groups'] = groups
            info['ip_group_count'] = len(groups)
            
            if groups:
                # Show structure of first group
                info['ip_group_example'] = groups[0]
                logger.info(f"Found {len(groups)} IP Group(s)")
                logger.info(f"Example IP Group structure:\n{json.dumps(groups[0], indent=2)}")
            else:
                logger.info("No existing IP Groups found")
                
        except Exception as e:
            info['ip_groups_error'] = str(e)
            logger.warning(f"Could not fetch IP Groups: {e}")
        
        # Test various endpoints to understand the API structure
        test_endpoints = [
            f'/sites/{self.site_id}/setting',
            f'/sites/{self.site_id}/setting/profiles/groups',
            f'/sites/{self.site_id}/setting/profiles/groups/0',
        ]
        
        for endpoint in test_endpoints:
            try:
                result = self._api_get(endpoint)
                info['endpoints_tested'][endpoint] = 'success'
                logger.debug(f"Endpoint {endpoint}: success")
            except Exception as e:
                info['endpoints_tested'][endpoint] = str(e)
                logger.debug(f"Endpoint {endpoint}: {e}")
        
        return info
    
    def logout(self):
        """Logout from Omada Controller"""
        try:
            params = {
                '_': self._timestamp(),
                'token': self.token
            }
            self.session.post(
                self._build_url('/logout'),
                params=params,
                timeout=5
            )
            logger.debug("Logged out of Omada Controller")
        except Exception as e:
            logger.debug(f"Logout error (non-fatal): {e}")


def discover_mode(omada: OmadaClient) -> bool:
    """Run discovery to inspect API structure"""
    logger.info("=" * 60)
    logger.info("OMADA API DISCOVERY MODE")
    logger.info("=" * 60)
    
    if not omada.login():
        logger.error("Failed to login - check credentials and URL")
        return False
    
    try:
        info = omada.discover()
        
        print("\n" + "=" * 60)
        print("DISCOVERY RESULTS")
        print("=" * 60)
        print(f"\nAPI Version: {info.get('api_version')}")
        print(f"OmadacId: {info.get('omadac_id') or 'none (pre-v5)'}")
        print(f"Site: {info.get('site')} (key: {info.get('site_id')})")
        print(f"\nIP Groups found: {info.get('ip_group_count', 0)}")
        
        if info.get('ip_groups'):
            print("\nExisting IP Groups:")
            for g in info['ip_groups']:
                name = g.get('name', 'unnamed')
                gid = g.get('groupId') or g.get('id') or g.get('_id', 'no-id')
                ip_count = len(g.get('ipList', []))
                print(f"  - {name} (id: {gid}, IPs: {ip_count})")
            
            print("\n" + "-" * 40)
            print("EXAMPLE IP GROUP STRUCTURE (for reference):")
            print("-" * 40)
            print(json.dumps(info['ip_groups'][0], indent=2))
        
        print("\n" + "-" * 40)
        print("ENDPOINT TEST RESULTS:")
        print("-" * 40)
        for endpoint, result in info.get('endpoints_tested', {}).items():
            status = "✓" if result == 'success' else "✗"
            print(f"  {status} {endpoint}")
            if result != 'success':
                print(f"      Error: {result}")
        
        print("\n" + "=" * 60)
        print("NEXT STEPS")
        print("=" * 60)
        print("""
1. If discovery succeeded with existing IP Groups, examine the
   'ipList' structure in the example above.

2. Create a test IP Group manually in Omada UI, then run
   discovery again to see its exact structure.

3. Once you understand the format, run:
   python omada-sync.py --dry-run

4. If dry-run looks good, run the actual sync:
   python omada-sync.py
""")
        
        return True
        
    finally:
        omada.logout()


def sync_once(crowdsec: CrowdSecClient, omada: OmadaClient, group_name: str, dry_run: bool = False) -> bool:
    """Perform one sync cycle"""
    # Get CrowdSec decisions
    blocked_ips = crowdsec.get_decisions()
    if blocked_ips is None:
        logger.warning("Skipping sync: CrowdSec LAPI unreachable (existing blocklist preserved)")
        return False
    logger.info(f"CrowdSec has {len(blocked_ips)} active bans")
    
    if dry_run:
        logger.info(f"[DRY RUN] Would sync {len(blocked_ips)} IPs to Omada group '{group_name}'")
        if blocked_ips:
            for ip in sorted(list(blocked_ips))[:10]:
                logger.info(f"  - {ip}")
            if len(blocked_ips) > 10:
                logger.info(f"  ... and {len(blocked_ips) - 10} more")
        return True
    
    # Login to Omada
    if not omada.login():
        return False
    
    try:
        # Sync to Omada IP Group
        success = omada.sync_blocklist(group_name, blocked_ips)
        return success
    finally:
        omada.logout()


def main():
    parser = argparse.ArgumentParser(
        description='Sync CrowdSec decisions to Omada Controller',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # First, run discovery to verify API compatibility:
  python omada-sync.py --discover

  # Then do a dry run:
  python omada-sync.py --dry-run

  # Finally, run the sync:
  python omada-sync.py

  # Or run as a daemon:
  python omada-sync.py --daemon --interval 60
        """
    )
    parser.add_argument('--discover', action='store_true', 
                        help='Discover API structure (run this first!)')
    parser.add_argument('--daemon', action='store_true', 
                        help='Run continuously')
    parser.add_argument('--dry-run', action='store_true', 
                        help='Show what would be synced')
    parser.add_argument('--interval', type=int, default=60, 
                        help='Sync interval in seconds (daemon mode)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration from environment
    crowdsec_url = os.environ.get('CROWDSEC_LAPI_URL', 'http://localhost:8080')
    crowdsec_key = os.environ.get('CROWDSEC_LAPI_KEY', '')
    
    omada_url = os.environ.get('OMADA_URL', '')
    omada_user = os.environ.get('OMADA_USER', '')
    omada_pass = os.environ.get('OMADA_PASS', '')
    omada_site = os.environ.get('OMADA_SITE', 'Default')
    omada_verify = os.environ.get('OMADA_VERIFY_SSL', 'false').lower() == 'true'
    
    group_name = os.environ.get('OMADA_GROUP_NAME', 'nib-blocklist')
    sync_interval = int(os.environ.get('SYNC_INTERVAL', args.interval))
    
    # Validate required config
    if not all([omada_url, omada_user, omada_pass]):
        logger.error("OMADA_URL, OMADA_USER, and OMADA_PASS are required")
        logger.error("Set these environment variables or create a .env file")
        sys.exit(1)
    
    # Initialize Omada client
    omada = OmadaClient(omada_url, omada_user, omada_pass, omada_site, omada_verify)
    
    # Discovery mode - just inspect API
    if args.discover:
        success = discover_mode(omada)
        sys.exit(0 if success else 1)
    
    # For sync modes, CrowdSec key is required
    if not crowdsec_key:
        logger.error("CROWDSEC_LAPI_KEY is required for sync mode")
        logger.error("Run with --discover first to test Omada connectivity")
        sys.exit(1)
    
    # Initialize CrowdSec client
    crowdsec = CrowdSecClient(crowdsec_url, crowdsec_key)
    
    if args.daemon:
        logger.info(f"Starting daemon mode (interval: {sync_interval}s)")
        while True:
            try:
                sync_once(crowdsec, omada, group_name, args.dry_run)
            except Exception as e:
                logger.error(f"Sync failed: {e}")
            time.sleep(sync_interval)
    else:
        success = sync_once(crowdsec, omada, group_name, args.dry_run)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
