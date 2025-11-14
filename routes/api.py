from flask import Blueprint, jsonify, request, current_app
from flask_limiter import Limiter
import os
import time
import sys
from datetime import datetime, timedelta

api_bp = Blueprint('api', __name__)

@api_bp.route('/health')
def health_check():
    """Enhanced health check with detailed metrics"""
    config = current_app.config['app_config']
    dashboard_state = current_app.config['dashboard_state']
    performance_monitor = current_app.config['performance_monitor']
    db_manager = current_app.config['db_manager']  
    
    log_exists = os.path.exists(config.LOG_FILE)
    log_size = os.path.getsize(config.LOG_FILE) if log_exists else 0
    
    uptime = time.time() - performance_monitor.start_time
    
    db_stats = {}
    db_health = {'status': 'disabled'}
    if db_manager and db_manager.enabled:
        try:
            db_health = db_manager.health_check()
            db_stats = db_manager.get_alert_stats(hours=24)
        except Exception as e:
            current_app.logger.warning(f"Failed to get database stats: {e}")
            db_health = {'status': 'error', 'error': str(e)}

    health_data = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'uptime_seconds': int(uptime),
        'uptime_human': str(timedelta(seconds=int(uptime))),
        'alerts_loaded': len(dashboard_state.alerts),
        'performance': performance_monitor.metrics,
        'database': {  
            'enabled': db_manager.enabled if db_manager else False,
            'path': db_manager.db_path if db_manager and db_manager.enabled else None,
            'health': db_health,
            'stats': db_stats if db_manager and db_manager.enabled else {}
        },
        'log_file': {
            'exists': log_exists,
            'path': config.LOG_FILE,
            'size_bytes': log_size,
            'size_mb': round(log_size / (1024 * 1024), 2) if log_exists else 0
        },
        'config': {
            'max_lines_to_read': config.MAX_LINES_TO_READ,
            'refresh_interval': config.REFRESH_INTERVAL,
            'high_priority_threshold': config.HIGH_PRIORITY_THRESHOLD,
            'persistence_enabled': config.ENABLE_PERSISTENCE,  
            'environment': config.ENVIRONMENT  
        }
    }
    
    warnings = []
    errors = []
    
    if performance_monitor.metrics['memory_usage_mb'] > config.MAX_MEMORY_MB * 1.2:
        warnings.append('High memory usage')
    
    if performance_monitor.metrics['file_read_errors'] > 5:
        errors.append('Multiple file read errors')
    
    if db_manager and db_manager.enabled:
        if db_health.get('status') == 'unhealthy':
            errors.append('Database connection unhealthy')
        elif db_health.get('status') == 'error':
            warnings.append('Database stats temporarily unavailable')
        
        total_db_alerts = db_stats.get('total_alerts', 0)
        total_memory_alerts = len(dashboard_state.alerts)
        if total_db_alerts > 0 and total_memory_alerts == 0:
            warnings.append('Database has alerts but memory is empty - possible sync issue')
    
    if health_data['log_file']['size_mb'] > 1000:  
        warnings.append('Large log file detected')
    
    if warnings:
        health_data['warnings'] = warnings
        health_data['status'] = 'warning'
    
    if errors:
        health_data['errors'] = errors
        health_data['status'] = 'critical'
    
    status_code = 200
    if health_data['status'] == 'warning':
        status_code = 200  
    elif health_data['status'] == 'critical':
        status_code = 503  
    
    return jsonify(health_data), status_code
    
@api_bp.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts with pagination - newest first"""
    dashboard_state = current_app.config['dashboard_state']
    performance_monitor = current_app.config['performance_monitor']
    
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        per_page = max(1, min(per_page, 200))  
    except ValueError:
        return jsonify({'error': 'Invalid pagination parameters'}), 400

    try:
        all_alerts = sorted(
            dashboard_state.alerts,
            key=lambda a: a['timestamp'],
            reverse=True
        )
    except KeyError:
        return jsonify({'error': 'Alerts missing timestamp field'}), 500

    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_alerts = all_alerts[start_idx:end_idx]

    response = {
        'alerts': paginated_alerts,
        'stats': dashboard_state.stats.copy(),
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': len(all_alerts),
            'pages': (len(all_alerts) + per_page - 1) // per_page
        },
        'performance': performance_monitor.metrics
    }

    return jsonify(response)

@api_bp.route('/api/alerts/search')
def search_alerts():
    """Enhanced search with better validation and caching"""
    try:
        dashboard_state = current_app.config['dashboard_state']
        
        query_params = {
            'q': request.args.get('q', '').strip(),
            'priority': request.args.get('priority', '').strip().lower(),
            'category': request.args.get('category', '').strip(),
            'ip': request.args.get('ip', '').strip(),
            'protocol': request.args.get('protocol', '').strip().upper(),
            'port': request.args.get('port', '').strip()
        }
        
        if not any(query_params.values()):
            return jsonify({
                'error': 'At least one search parameter is required',
                'available_filters': ['q', 'priority', 'category', 'ip', 'protocol', 'port']
            }), 400
        
        limit = min(int(request.args.get('limit', 100)), 500)
        start_time = time.time()
        
        results = dashboard_state.search_alerts(query_params)
        results = results[:limit]
        
        search_time = (time.time() - start_time) * 1000
        
        return jsonify({
            'query_params': query_params,
            'results': results,
            'total_found': len(results),
            'search_time_ms': round(search_time, 2),
            'timestamp': datetime.now().isoformat()
        })
        
    except ValueError as e:
        return jsonify({'error': f'Invalid parameter: {e}'}), 400
    except Exception as e:
        current_app.logger.error(f"Search error: {e}")
        return jsonify({'error': 'Internal search error'}), 500

@api_bp.route('/api/stats')
def api_stats():
    """Enhanced statistics endpoint"""
    dashboard_state = current_app.config['dashboard_state']
    performance_monitor = current_app.config['performance_monitor']
    
    return jsonify({
        'dashboard_stats': dashboard_state.stats.copy(),
        'performance_metrics': performance_monitor.metrics,
        'system_info': {
            'python_version': sys.version.split()[0],
            'platform': sys.platform,
            'process_id': os.getpid()
        },
        'alert_summary': {
            'total_in_memory': len(dashboard_state.alerts),
            'history_size': len(dashboard_state.alert_history),
            'recent_trend': performance_monitor.get_alert_trend()
        }
    })

@api_bp.route('/api/alerts/export')
def export_alerts():
    """Enhanced export with format options and compression"""
    try:
        dashboard_state = current_app.config['dashboard_state']
        
        format_type = request.args.get('format', 'json').lower()
        limit = min(int(request.args.get('limit', 1000)), 5000)
        include_history = request.args.get('history', 'false').lower() == 'true'
        
        if include_history:
            export_data = list(dashboard_state.alert_history)[-limit:]
        else:
            export_data = dashboard_state.get_recent_alerts(limit)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format_type == 'csv':
            import csv
            from io import StringIO
            
            output = StringIO()
            writer = csv.writer(output)
            
            writer.writerow([
                'Timestamp', 'Signature', 'Priority', 'Category',
                'Source IP', 'Source Port', 'Dest IP', 'Dest Port',
                'Protocol', 'Event Type'
            ])
            
            for alert in export_data:
                writer.writerow([
                    alert.get('timestamp', ''),
                    alert.get('signature', ''),
                    alert.get('priority', ''),
                    alert.get('category', ''),
                    alert.get('src_ip', ''),
                    alert.get('src_port', ''),
                    alert.get('dest_ip', ''),
                    alert.get('dest_port', ''),
                    alert.get('proto', ''),
                    alert.get('event_type', '')
                ])
            
            response_data = output.getvalue()
            headers = {
                'Content-Type': 'text/csv',
                'Content-Disposition': f'attachment; filename=suricata_alerts_{timestamp}.csv'
            }
            
            return response_data, 200, headers
            
        else:  
            export_package = {
                'metadata': {
                    'exported_at': datetime.now().isoformat(),
                    'total_alerts': len(export_data),
                    'format': 'json',
                    'dashboard_version': '2.1',
                    'include_history': include_history
                },
                'statistics': dashboard_state.stats.copy(),
                'alerts': export_data
            }
            
            return jsonify(export_package)
            
    except Exception as e:
        current_app.logger.error(f"Export error: {e}")
        return jsonify({'error': 'Export failed'}), 500

@api_bp.route('/api/geoip/<ip>')
def api_geoip(ip):
    """API endpoint for GeoIP lookups"""
    try:
        alert_processor = current_app.config['alert_processor']
        
        import ipaddress
        ipaddress.ip_address(ip)
        
        location = alert_processor.geoip.get_location(ip)
        
        if location:
            return jsonify({
                'ip': ip,
                'location': location,
                'status': 'success'
            })
        else:
            return jsonify({
                'ip': ip,
                'location': None,
                'status': 'not_found',
                'message': 'Location data not available for this IP'
            }), 404
            
    except ValueError:
        return jsonify({
            'error': 'Invalid IP address format',
            'ip': ip
        }), 400
    except Exception as e:
        current_app.logger.error(f"GeoIP API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/api/stats/geo')
def api_geo_stats():
    """Geographic distribution statistics"""
    try:
        dashboard_state = current_app.config['dashboard_state']
        
        geo_stats = {
            'countries': {},
            'cities': {},
            'total_geolocated': 0,
            'total_alerts': len(dashboard_state.alerts)
        }
        
        for alert in dashboard_state.alerts:
            if alert.get('src_geo') and alert['src_geo'].get('country'):
                country = alert['src_geo']['country']
                geo_stats['countries'][country] = geo_stats['countries'].get(country, 0) + 1
                geo_stats['total_geolocated'] += 1
            
            if alert.get('src_geo') and alert['src_geo'].get('city'):
                city = f"{alert['src_geo']['city']}, {alert['src_geo'].get('country', 'Unknown')}"
                geo_stats['cities'][city] = geo_stats['cities'].get(city, 0) + 1
        
        geo_stats['top_countries'] = dict(sorted(geo_stats['countries'].items(), 
                                               key=lambda x: x[1], reverse=True)[:10])
        geo_stats['top_cities'] = dict(sorted(geo_stats['cities'].items(), 
                                            key=lambda x: x[1], reverse=True)[:10])
        
        return jsonify(geo_stats)
        
    except Exception as e:
        current_app.logger.error(f"Geo stats error: {e}")
        return jsonify({'error': 'Failed to generate geographic statistics'}), 500