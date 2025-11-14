from flask import Blueprint, render_template, current_app

views_bp = Blueprint('views', __name__)

@views_bp.route('/')
def dashboard():
    """Main dashboard"""
    dashboard_state = current_app.config['dashboard_state']
    recent_alerts = dashboard_state.get_recent_alerts(30)
    
    return render_template('dashboard.html', 
        alerts=recent_alerts,
        stats=dashboard_state.stats.copy(),
        config=current_app.config['app_config'].__dict__
    )