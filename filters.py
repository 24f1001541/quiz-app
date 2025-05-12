from datetime import datetime

def time_ago(dt):
    """
    Convert a datetime object to a relative time string (e.g., "2 hours ago").
    
    Args:
        dt (datetime): The datetime to convert
        
    Returns:
        str: Human-readable relative time string
    
    Examples:
        >>> time_ago(datetime.utcnow() - timedelta(minutes=5))
        '5 minutes ago'
        >>> time_ago(datetime.utcnow() - timedelta(days=3))
        '3 days ago'
        >>> time_ago(datetime(2020, 1, 1))
        '2020-01-01'
    """
    if not isinstance(dt, datetime):
        raise TypeError("Expected datetime object")
        
    now = datetime.utcnow()
    
    # Handle future dates
    if dt > now:
        return dt.strftime('%Y-%m-%d')
    
    diff = now - dt
    
    seconds = diff.total_seconds()
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    weeks = days / 7
    months = days / 30
    years = days / 365

    if years >= 1:
        return dt.strftime('%Y-%m-%d')
    elif months >= 1:
        return f"{int(months)} month{'s' if months >= 2 else ''} ago"
    elif weeks >= 1:
        return f"{int(weeks)} week{'s' if weeks >= 2 else ''} ago"
    elif days >= 1:
        return f"{int(days)} day{'s' if days >= 2 else ''} ago"
    elif hours >= 1:
        return f"{int(hours)} hour{'s' if hours >= 2 else ''} ago"
    elif minutes >= 1:
        return f"{int(minutes)} minute{'s' if minutes >= 2 else ''} ago"
    else:
        return "just now"
        