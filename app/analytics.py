from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import FeatureVector, SecurityEvent


SUSPICIOUS_SIGNALS = {
    "risky_signin",
    "impossible_travel",
    "mfa_reset",
    "mass_download",
    "encoded_powershell",
    "credential_access",
    "remote_service",
    "lateral_logon",
    "c2_connection",
    "oauth_consent",
    "high_privilege_grant",
    "app_only_signin",
    "mailbox_access",
}


def build_features(events: Iterable[SecurityEvent]) -> FeatureVector:
    materialized = list(events)
    event_types = Counter(event.event_type for event in materialized)
    sources = {event.source for event in materialized}
    users = {event.user for event in materialized if event.user}
    devices = {event.device for event in materialized if event.device}
    ips = {event.src_ip for event in materialized if event.src_ip}
    suspicious = sum(event_types[event_type] for event_type in SUSPICIOUS_SIGNALS)

    # Transparent bounded score: suspicious density plus cross-source correlation.
    density = suspicious / max(1, len(materialized))
    source_bonus = min(0.25, max(0, len(sources) - 1) * 0.08)
    entity_bonus = min(0.15, (len(users) + len(devices) + len(ips)) * 0.02)
    anomaly_score = round(min(1.0, 0.70 * density + source_bonus + entity_bonus), 4)

    return FeatureVector(
        event_count=len(materialized),
        source_count=len(sources),
        unique_users=len(users),
        unique_devices=len(devices),
        unique_ips=len(ips),
        suspicious_signal_count=suspicious,
        anomaly_score=anomaly_score,
        event_type_counts=dict(sorted(event_types.items())),
    )

