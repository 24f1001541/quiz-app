from datetime import datetime

def time_ago(dt):
    now = datetime.utcnow()
    diff = now - dt
    
    seconds = diff.total_seconds()
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24

    if days > 7:
        return dt.strftime('%Y-%m-%d')
    elif days > 0:
        return f"{int(days)} days ago"
    elif hours > 0:
        return f"{int(hours)} hours ago"
    elif minutes > 0:
        return f"{int(minutes)} minutes ago"
    else:
        return "just now"
        
    