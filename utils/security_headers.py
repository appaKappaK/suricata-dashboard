def add_security_headers(response):
    """
    Enhanced security headers for Flask responses
    
    Args:
        response: Flask response object
        
    Returns:
        Flask response object with security headers added
    """
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval' cdnjs.cloudflare.com;",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response


def get_security_headers():
    """
    Get security headers as a dictionary
    
    Returns:
        dict: Security headers configuration
    """
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval' cdnjs.cloudflare.com;",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }