def validate_ip_address(ip):
    """Validate IP address format"""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def sanitize_input(text, max_length=500):
    """Sanitize user input"""
    if not isinstance(text, str):
        return ""
    return text.strip()[:max_length]