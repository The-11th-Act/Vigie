from datetime import datetime, timedelta
from typing import Optional

def calculate_remediation_deadline(severity: str, detection_time: Optional[datetime] = None) -> datetime:
    if detection_time is None:
        detection_time = datetime.utcnow()
        
    sla_days = {
        "Critical": 14,
        "High": 30,
        "Medium": 90,
        "Low": 180
    }
    days = sla_days.get(severity, 90)
    return detection_time + timedelta(days=days)
