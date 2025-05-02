import ipaddress
import requests
from typing import Dict
import logging

logger = logging.getLogger(__name__)

class GeoIPLookup:
    def __init__(self, cache_size: int = 5000):
        self.cache = {}
        self.cache_size = cache_size
        logger.info("Initialized GeoIP lookup service")

    def is_valid_public_ip(self, ip_address: str) -> bool:
        """Verify that the IP address is public and correct"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return not (ip.is_private or ip.is_loopback or
                       ip.is_link_local or ip.is_multicast or
                       ip.is_reserved or ip.is_unspecified)
        except ValueError:
            return False

    def get_country(self, ip_address: str) -> Dict[str, str]:
        """Find IP Address Country"""
        if not ip_address or ip_address == 'unknown':
            return {"code": "XX", "name": "Unknown"}

        if not self.is_valid_public_ip(ip_address):
            return {"code": "LO", "name": "Local"}

        if ip_address in self.cache:
            return self.cache[ip_address]

        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}?fields=status,countryCode,country',
                timeout=2
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        "code": data.get('countryCode', 'XX'),
                        "name": data.get('country', 'Unknown')
                    }
                    self._add_to_cache(ip_address, result)
                    return result

            return {"code": "XX", "name": "Unknown"}
        except Exception as e:
            logger.debug(f"GeoIP lookup error for {ip_address}: {str(e)[:100]}")
            return {"code": "XX", "name": "Unknown"}

    def _add_to_cache(self, ip: str, data: Dict[str, str]):
        """Add result to cache"""
        if len(self.cache) >= self.cache_size:
            self.cache.clear()
        self.cache[ip] = data
