from datetime import datetime, timezone


class Signal:
    VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def __init__(
        self,
        ip,
        attack_type,
        severity,
        confidence,
        timestamp=None,
        reason=None,
        payload=None,
        endpoint=None,
    ):
        self.ip = ip
        self.attack_type = attack_type

        if severity not in self.VALID_SEVERITIES:
            severity = "LOW"
        self.severity = severity

        self.confidence = max(0.0, min(float(confidence), 1.0))

        # If no timestamp provided, auto-generate one
        self.timestamp = timestamp or datetime.now(timezone.utc)

        self.reason = reason
        self.payload = payload
        self.endpoint = endpoint

    def to_dict(self):
        return {
            "ip": self.ip,
            "attack": self.attack_type,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "payload": self.payload,
            "endpoint": self.endpoint,
        }
