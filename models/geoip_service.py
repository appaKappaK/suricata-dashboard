import os

class GeoIPService:
    """GeoIP lookup service with caching and error handling"""
    
    def __init__(self, app_logger=None):
        self.reader = None
        self.cache = {}  
        self.cache_max_size = 1000
        self.app_logger = app_logger
        
        geoip_paths = [
            os.getenv('GEOIP_DATABASE', '/usr/share/GeoIP/GeoLite2-City.mmdb'),
            '/var/lib/GeoIP/GeoLite2-City.mmdb',
            '/usr/local/share/GeoIP/GeoLite2-City.mmdb',
            './GeoLite2-City.mmdb'
        ]
        
        for geoip_path in geoip_paths:
            if os.path.exists(geoip_path):
                try:
                    import geoip2.database
                    import geoip2.errors
                    self.reader = geoip2.database.Reader(geoip_path)
                    if self.app_logger:
                        self.app_logger.info(f"GeoIP database loaded: {geoip_path}")
                    break
                except ImportError:
                    if self.app_logger:
                        self.app_logger.warning("geoip2 library not installed. Run: pip install geoip2")
                    break
                except Exception as e:
                    if self.app_logger:
                        self.app_logger.warning(f"Failed to load GeoIP database {geoip_path}: {e}")
                    continue
        
        if not self.reader and self.app_logger:
            self.app_logger.info("No GeoIP database found - geographic lookups disabled")
    
    def get_location(self, ip_address):
        """Get geographic location for IP address with caching"""
        if not self.reader or not ip_address or ip_address in ('Unknown', '0.0.0.0', '127.0.0.1'):
            return None
        
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        try:
            import geoip2.errors
            response = self.reader.city(ip_address)
            
            location_data = {
                'country': response.country.name or 'Unknown',
                'country_code': response.country.iso_code or '',
                'city': response.city.name or 'Unknown',
                'latitude': float(response.location.latitude) if response.location.latitude else None,
                'longitude': float(response.location.longitude) if response.location.longitude else None,
                'org': response.traits.organization or ''
            }
            
            if len(self.cache) >= self.cache_max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
            
            self.cache[ip_address] = location_data
            return location_data
            
        except geoip2.errors.AddressNotFoundError:
            self.cache[ip_address] = None
            return None
        except Exception as e:
            if self.app_logger:
                self.app_logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return None
    
    def get_distance(self, ip1, ip2):
        """Calculate distance between two IP addresses"""
        loc1 = self.get_location(ip1)
        loc2 = self.get_location(ip2)
        
        if not loc1 or not loc2 or not all([loc1.get('latitude'), loc1.get('longitude'), 
                                           loc2.get('latitude'), loc2.get('longitude')]):
            return None
        
        import math
        
        lat1, lon1 = math.radians(loc1['latitude']), math.radians(loc1['longitude'])
        lat2, lon2 = math.radians(loc2['latitude']), math.radians(loc2['longitude'])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return 6371 * c