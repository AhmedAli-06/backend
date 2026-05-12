"""
Ghost Access Detector - Detects impossible access patterns

Detects:
  1. Simultaneous sessions - same user active on multiple assets/IPs
  2. Impossible travel - same badge used at different locations with physically impossible speed
  3. Credential sharing - same credential used by different users
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from math import asin, cos, radians, sin, sqrt
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.access import AccessEvent, AccessSession
from app.models.asset import Asset
from app.models.tenant import TenantConfig
from app.models.user import Credential

# =============================================================================
# Configuration
# =============================================================================

# Default threshold for impossible travel detection (km/h)
# Ground travel is typically < 200 km/h, but we use 500 km/h for flights
DEFAULT_IMPOSSIBLE_TRAVEL_SPEED_KMH = 500.0

# Default time window for impossible travel detection (minutes)
DEFAULT_TRAVEL_WINDOW_MINUTES = 60

# Default simultaneous session threshold (concurrent sessions)
DEFAULT_CONCURRENT_SESSION_THRESHOLD = 1


@dataclass
class GhostAccessConfig:
    """Configurable thresholds for ghost access detection."""
    impossible_travel_speed_kmh: float = DEFAULT_IMPOSSIBLE_TRAVEL_SPEED_KMH
    travel_window_minutes: int = DEFAULT_TRAVEL_WINDOW_MINUTES
    concurrent_session_threshold: int = DEFAULT_CONCURRENT_SESSION_THRESHOLD


@dataclass
class ImpossibleTravelResult:
    """Detailed result of impossible travel detection."""
    ghost_detected: bool
    reason: str | None = None
    detail: str | None = None
    penalty: float = 0.0
    # Detailed tracking data
    previous_location: str | None = None
    current_location: str | None = None
    distance_km: float | None = None
    time_gap_minutes: float | None = None
    calculated_speed_kmh: float | None = None
    previous_timestamp: datetime | None = None
    current_timestamp: datetime | None = None


@dataclass
class SimultaneousSessionResult:
    """Detailed result of simultaneous session detection."""
    ghost_detected: bool
    reason: str | None = None
    detail: str | None = None
    penalty: float = 0.0
    # Detailed tracking data
    active_sessions: list[dict] = field(default_factory=list)
    suspicious_ips: list[str] = field(default_factory=list)
    session_count: int = 0


async def get_ghost_config(db: AsyncSession, tenant_id: UUID) -> GhostAccessConfig:
    """
    Load ghost access configuration for a tenant.
    Falls back to defaults if no config exists.
    """
    result = await db.execute(
        select(TenantConfig).where(TenantConfig.tenant_id == tenant_id)
    )
    config = result.scalar_one_or_none()

    if config:
        # Check for ghost-specific config fields, use defaults if not present
        return GhostAccessConfig(
            impossible_travel_speed_kmh=getattr(config, 'impossible_travel_speed_kmh', DEFAULT_IMPOSSIBLE_TRAVEL_SPEED_KMH),
            travel_window_minutes=getattr(config, 'travel_window_minutes', DEFAULT_TRAVEL_WINDOW_MINUTES),
            concurrent_session_threshold=getattr(config, 'concurrent_session_threshold', DEFAULT_CONCURRENT_SESSION_THRESHOLD)
        )

    return GhostAccessConfig()


# =============================================================================
# Haversine Distance Calculation
# =============================================================================

def haversine_distance(
    lat1: float, lon1: float,
    lat2: float, lon2: float
) -> float:
    """
    Calculate the great-circle distance between two points on Earth using Haversine formula.

    Args:
        lat1: Latitude of first point in degrees
        lon1: Longitude of first point in degrees
        lat2: Latitude of second point in degrees
        lon2: Longitude of second point in degrees

    Returns:
        float: Distance in kilometers
    """
    # Earth's radius in kilometers
    EARTH_RADIUS_KM = 6371.0

    # Convert to radians
    lat1_rad = radians(lat1)
    lat2_rad = radians(lat2)
    delta_lat = radians(lat2 - lat1)
    delta_lon = radians(lon2 - lon1)

    # Haversine formula
    a = sin(delta_lat / 2) ** 2 + cos(lat1_rad) * cos(lat2_rad) * sin(delta_lon / 2) ** 2
    c = 2 * asin(sqrt(a))

    return EARTH_RADIUS_KM * c


# =============================================================================
# Location Parsing
# =============================================================================

# Known city coordinates for common locations (in production, use a geocoding API)
KNOWN_LOCATIONS = {
    "new york": (40.7128, -74.0060),
    "nyc": (40.7128, -74.0060),
    "los angeles": (34.0522, -118.2437),
    "la": (34.0522, -118.2437),
    "chicago": (41.8781, -87.6298),
    "houston": (29.7604, -95.3698),
    "phoenix": (33.4484, -112.0740),
    "philadelphia": (39.9526, -75.1652),
    "san antonio": (29.4241, -98.4936),
    "san diego": (32.7157, -117.1611),
    "dallas": (32.7767, -96.7970),
    "san jose": (37.3382, -121.8863),
    "austin": (30.2672, -97.7431),
    "jacksonville": (30.3322, -81.6557),
    "fort worth": (32.7555, -97.3308),
    "columbus": (39.9612, -82.9988),
    "charlotte": (35.2271, -80.8431),
    "indianapolis": (39.7684, -86.1581),
    "seattle": (47.6062, -122.3321),
    "denver": (39.7392, -104.9903),
    "boston": (42.3601, -71.0589),
    "atlanta": (33.7490, -84.3880),
    "miami": (25.7617, -80.1918),
    "london": (51.5074, -0.1278),
    "paris": (48.8566, 2.3522),
    "berlin": (52.5200, 13.4050),
    "tokyo": (35.6762, 139.6503),
    "sydney": (-33.8688, 151.2093),
}


def parse_location_to_coords(location: str | None) -> tuple[float, float] | None:
    """
    Parse a location string to coordinates.

    Args:
        location: Location string (city name, "lat,lon" format, or None)

    Returns:
        tuple of (latitude, longitude) or None if unparseable
    """
    if not location:
        return None

    location_lower = location.lower().strip()

    # Check known locations
    if location_lower in KNOWN_LOCATIONS:
        return KNOWN_LOCATIONS[location_lower]

    # Try "lat,lon" format
    try:
        parts = location.split(",")
        if len(parts) == 2:
            lat = float(parts[0].strip())
            lon = float(parts[1].strip())
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return (lat, lon)
    except (ValueError, IndexError):
        pass

    return None


# =============================================================================
# Main Ghost Access Check
# =============================================================================

async def check_ghost_access(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID,
    credential_value: str | None = None,
    tenant_id: UUID | None = None
) -> dict:
    """
    Check for ghost access patterns.

    Detects:
      - User has another active session on different asset/IP
      - Same badge used at another location with physically impossible speed
      - Same credential used by different users (credential sharing)

    Args:
        db: Database session
        user_id: The user attempting access
        asset_id: The asset being accessed
        credential_value: The credential value (badge ID)
        tenant_id: Optional tenant ID for loading config

    Returns:
        dict with:
          - ghost_detected: bool
          - reason: str ("simultaneous_session", "impossible_travel", "credential_sharing", or None)
          - detail: str with details
          - penalty: float (0.0-1.0, trust score penalty)
          - detection_data: dict with detailed tracking info
    """
    # Load configuration
    if tenant_id:
        config = await get_ghost_config(db, tenant_id)
    else:
        config = GhostAccessConfig()

    # Check 1: Simultaneous active sessions (enhanced with IP check)
    simultaneous = await check_simultaneous_sessions(
        db, user_id, asset_id, config
    )
    if simultaneous.get("ghost_detected"):
        return simultaneous

    # Check 2: Impossible travel (enhanced with Haversine + configurable threshold)
    if credential_value:
        impossible_travel = await check_impossible_travel(
            db, user_id, asset_id, credential_value, config
        )
        if impossible_travel.get("ghost_detected"):
            return impossible_travel

    # Check 3: Credential sharing (same badge used by different users)
    if credential_value:
        sharing = await check_credential_sharing(db, user_id, credential_value)
        if sharing.get("ghost_detected"):
            return sharing

    return {
        "ghost_detected": False,
        "reason": None,
        "detail": None,
        "penalty": 0.0,
        "detection_data": {}
    }


async def check_simultaneous_sessions(
    db: AsyncSession,
    user_id: UUID,
    current_asset_id: UUID,
    config: GhostAccessConfig | None = None
) -> dict:
    """
    Check if user has multiple active sessions from different IPs/locations.

    Enhancement over v0.2.0:
    - Uses configurable threshold (default: 1 = 2+ sessions = suspicious)
    - Tracks all active sessions for detailed alert data
    - Same IP from different browsers = OK, different IPs = suspicious

    Args:
        db: Database session
        user_id: The user ID
        current_asset_id: The current asset being accessed
        config: Optional ghost access configuration

    Returns:
        dict with ghost_detected, reason, detail, penalty, and session details
    """
    if config is None:
        config = GhostAccessConfig()

    result = await db.execute(
        select(AccessSession)
        .where(
            AccessSession.user_id == user_id,
            AccessSession.status == "active",
            AccessSession.asset_id != current_asset_id
        )
    )
    other_sessions = result.scalars().all()

    # Get current session's IP for comparison
    current_session_result = await db.execute(
        select(AccessSession)
        .where(
            AccessSession.user_id == user_id,
            AccessSession.status == "active",
            AccessSession.asset_id == current_asset_id
        )
        .order_by(AccessSession.started_at.desc())
        .limit(1)
    )
    current_session = current_session_result.scalar_one_or_none()
    current_ip = getattr(current_session, 'ip_address', None) if current_session else None

    # Build session details list
    session_details = []
    suspicious_ips = []

    for s in other_sessions:
        session_ip = getattr(s, 'ip_address', None)
        session_asset_result = await db.execute(
            select(Asset).where(Asset.id == s.asset_id)
        )
        asset = session_asset_result.scalar_one_or_none()
        asset_name = asset.name if asset else "Unknown"

        session_info = {
            "session_id": str(s.id),
            "asset_id": str(s.asset_id),
            "asset_name": asset_name,
            "asset_location": asset.location if asset else None,
            "ip_address": session_ip,
            "started_at": s.started_at.isoformat() if s.started_at else None
        }
        session_details.append(session_info)

        # Same IP from different browsers/devices = OK
        # Different IP = suspicious
        if session_ip and current_ip and session_ip != current_ip:
            suspicious_ips.append(session_ip)

    session_count = len(other_sessions)

    # Check threshold
    if session_count >= config.concurrent_session_threshold:
        # Determine if it's suspicious based on IP addresses
        if suspicious_ips:
            detail = (
                f"User has {session_count + 1} active sessions from {len(suspicious_ips) + 1} different IPs "
                f"(threshold: {config.concurrent_session_threshold + 1}+ concurrent)"
            )
            penalty = 0.8
        else:
            detail = (
                f"User has {session_count + 1} active sessions but same IP addresses "
                f"(likely multi-browser, threshold: {config.concurrent_session_threshold + 1}+)"
            )
            # Same IP = less suspicious
            penalty = 0.3

        return {
            "ghost_detected": True,
            "reason": "simultaneous_session",
            "detail": detail,
            "penalty": penalty,
            "detection_data": {
                "active_sessions": session_details,
                "suspicious_ips": suspicious_ips,
                "session_count": session_count,
                "threshold": config.concurrent_session_threshold
            }
        }

    return {
        "ghost_detected": False,
        "reason": None,
        "detail": None,
        "penalty": 0.0,
        "detection_data": {}
    }


async def check_impossible_travel(
    db: AsyncSession,
    user_id: UUID,
    current_asset_id: UUID,
    credential_value: str,
    config: GhostAccessConfig | None = None
) -> dict:
    """
    Check if same credential was used at a different location with physically impossible speed.

    Enhancement over v0.2.0:
    - Uses Haversine formula for accurate distance calculation
    - Configurable speed threshold (default: 500 km/h for flights)
    - Configurable time window (default: 60 minutes)
    - Returns detailed tracking: locations, timestamps, speed

    Args:
        db: Database session
        user_id: The user ID
        current_asset_id: The current asset being accessed
        credential_value: The badge ID
        config: Optional ghost access configuration

    Returns:
        dict with ghost_detected, reason, detail, penalty, and travel details
    """
    if config is None:
        config = GhostAccessConfig()

    # Get current asset location
    current_asset_result = await db.execute(
        select(Asset).where(Asset.id == current_asset_id)
    )
    current_asset = current_asset_result.scalar_one_or_none()
    current_location = current_asset.location if current_asset else None
    current_coords = parse_location_to_coords(current_location)

    # Look back within the configurable time window
    window_start = datetime.now(UTC) - timedelta(minutes=config.travel_window_minutes)

    result = await db.execute(
        select(AccessEvent)
        .join(Credential, AccessEvent.credential_id == Credential.id)
        .where(
            Credential.credential_value == credential_value,
            AccessEvent.asset_id != current_asset_id,
            AccessEvent.occurred_at >= window_start
        )
        .order_by(AccessEvent.occurred_at.desc())
    )
    recent_events = result.scalars().all()

    if not recent_events:
        return {
            "ghost_detected": False,
            "reason": None,
            "detail": None,
            "penalty": 0.0,
            "detection_data": {}
        }

    # Check most recent event
    last_event = recent_events[0]

    # Get previous asset location
    prev_asset_result = await db.execute(
        select(Asset).where(Asset.id == last_event.asset_id)
    )
    prev_asset = prev_asset_result.scalar_one_or_none()
    prev_location = prev_asset.location if prev_asset else None
    prev_coords = parse_location_to_coords(prev_location)

    # Calculate time gap
    current_time = datetime.now(UTC)
    time_gap = (current_time - last_event.occurred_at).total_seconds() / 60.0  # minutes

    # Calculate distance and speed
    if current_coords and prev_coords:
        distance_km = haversine_distance(
            prev_coords[0], prev_coords[1],
            current_coords[0], current_coords[1]
        )
        speed_kmh = (distance_km / time_gap) * 60.0 if time_gap > 0 else float('inf')

        # Check if speed exceeds threshold
        if speed_kmh > config.impossible_travel_speed_kmh:
            detail = (
                f"Impossible travel detected: {distance_km:.1f}km in {time_gap:.1f}min "
                f"(speed: {speed_kmh:.1f} km/h, threshold: {config.impossible_travel_speed_kmh} km/h). "
                f"Previous: {prev_location or 'Unknown'}, Current: {current_location or 'Unknown'}"
            )
            return {
                "ghost_detected": True,
                "reason": "impossible_travel",
                "detail": detail,
                "penalty": 0.7,
                "detection_data": {
                    "previous_location": prev_location,
                    "current_location": current_location,
                    "distance_km": round(distance_km, 2),
                    "time_gap_minutes": round(time_gap, 2),
                    "calculated_speed_kmh": round(speed_kmh, 2),
                    "speed_threshold_kmh": config.impossible_travel_speed_kmh,
                    "previous_timestamp": last_event.occurred_at.isoformat(),
                    "current_timestamp": current_time.isoformat(),
                    "previous_asset_id": str(last_event.asset_id),
                    "current_asset_id": str(current_asset_id)
                }
            }
    else:
        # Fallback to time-only check if locations can't be parsed
        # 100km in 30 minutes = 200 km/h (physically possible but suspicious)
        if time_gap < 30:
            detail = (
                f"Rapid badge reuse: same badge at different location within {time_gap:.1f} minutes. "
                f"Previous: {prev_location or 'Unknown'}, Current: {current_location or 'Unknown'}. "
                f"Locations could not be geocoded - using time-only heuristic."
            )
            return {
                "ghost_detected": True,
                "reason": "impossible_travel",
                "detail": detail,
                "penalty": 0.6,
                "detection_data": {
                    "previous_location": prev_location,
                    "current_location": current_location,
                    "time_gap_minutes": round(time_gap, 2),
                    "calculated_speed_kmh": None,
                    "previous_timestamp": last_event.occurred_at.isoformat(),
                    "current_timestamp": current_time.isoformat(),
                    "fallback_heuristic": True
                }
            }

    return {
        "ghost_detected": False,
        "reason": None,
        "detail": None,
        "penalty": 0.0,
        "detection_data": {}
    }


async def check_credential_sharing(
    db: AsyncSession,
    current_user_id: UUID,
    credential_value: str
) -> dict:
    """
    Check if the same credential is assigned to multiple users.

    Returns detailed information about shared credentials.
    """
    result = await db.execute(
        select(Credential)
        .where(
            Credential.credential_value == credential_value,
            Credential.user_id != current_user_id,
            Credential.is_active is True
        )
    )
    sharing_credentials = result.scalars().all()

    if sharing_credentials:
        shared_users = []
        for cred in sharing_credentials:
            from app.models.user import User
            user_result = await db.execute(
                select(User).where(User.id == cred.user_id)
            )
            user = user_result.scalar_one_or_none()
            if user:
                shared_users.append({
                    "user_id": str(user.id),
                    "full_name": user.full_name,
                    "email": getattr(user, 'email', None)
                })

        return {
            "ghost_detected": True,
            "reason": "credential_sharing",
            "detail": f"Badge assigned to {len(sharing_credentials)} other user(s): {[u['full_name'] for u in shared_users]}",
            "penalty": 0.9,
            "detection_data": {
                "shared_users": shared_users,
                "credential_value": credential_value[:8] + "..."  # Masked for logging
            }
        }

    return {
        "ghost_detected": False,
        "reason": None,
        "detail": None,
        "penalty": 0.0,
        "detection_data": {}
    }


async def get_active_sessions_for_user(
    db: AsyncSession,
    user_id: UUID
) -> list[AccessSession]:
    """
    Get all active sessions for a user.
    """
    result = await db.execute(
        select(AccessSession)
        .where(
            AccessSession.user_id == user_id,
            AccessSession.status == "active"
        )
    )
    return result.scalars().all()


async def revoke_ghost_sessions(
    db: AsyncSession,
    user_id: UUID,
    except_asset_id: UUID | None = None
) -> int:
    """
    Revoke all active sessions for a user except optionally one asset.
    Returns number of sessions revoked.
    """
    query = select(AccessSession).where(
        AccessSession.user_id == user_id,
        AccessSession.status == "active"
    )

    if except_asset_id:
        query = query.where(AccessSession.asset_id != except_asset_id)

    result = await db.execute(query)
    sessions = result.scalars().all()

    now = datetime.now(UTC)
    for session in sessions:
        session.status = "revoked"
        session.ended_at = now
        session.revocation_reason = "Ghost access detected - automated revocation"

    return len(sessions)


# =============================================================================
# Convenience API (per plan acceptance criteria)
# =============================================================================

async def detect_ghost_access(
    user_id: UUID,
    access_location: str | None,
    access_time: datetime,
    db: AsyncSession,
    credential_value: str | None = None,
    tenant_id: UUID | None = None,
    current_asset_id: UUID | None = None
) -> dict:
    """
    Unified function for ghost access detection.

    Per plan acceptance criteria:
    - Function: `detect_ghost_access(user_id, access_location, access_time)`
    - Detects: impossible travel, simultaneous sessions

    Args:
        user_id: The user ID to check
        access_location: Current access location string
        access_time: Current access timestamp
        db: Database session
        credential_value: Optional badge ID
        tenant_id: Optional tenant ID for config
        current_asset_id: Optional asset being accessed

    Returns:
        dict with ghost_detected, reason, detail, penalty, and detection_data
    """
    if current_asset_id:
        return await check_ghost_access(
            db=db,
            user_id=user_id,
            asset_id=current_asset_id,
            credential_value=credential_value,
            tenant_id=tenant_id
        )

    # If no asset_id, still check for simultaneous sessions and credential sharing
    # (impossible travel requires asset context)
    config = await get_ghost_config(db, tenant_id) if tenant_id else GhostAccessConfig()

    # Check simultaneous sessions
    session_result = await check_simultaneous_sessions(
        db, user_id, UUID("00000000-0000-0000-0000-000000000000"), config
    )
    if session_result.get("ghost_detected"):
        return session_result

    # Check credential sharing
    if credential_value:
        sharing_result = await check_credential_sharing(db, user_id, credential_value)
        if sharing_result.get("ghost_detected"):
            return sharing_result

    return {
        "ghost_detected": False,
        "reason": None,
        "detail": None,
        "penalty": 0.0,
        "detection_data": {}
    }


def create_ghost_alert(
    db: AsyncSession,
    tenant_id: UUID,
    user_id: UUID | None,
    asset_id: UUID,
    ghost_result: dict,
    session_id: UUID | None = None,
    trust_score: float = 0.0
) -> dict:
    """
    Create an alert for ghost access detection.

    Args:
        db: Database session
        tenant_id: Tenant UUID
        user_id: User UUID
        asset_id: Asset UUID
        ghost_result: Result from check_ghost_access
        session_id: Optional session ID
        trust_score: Trust score at detection time

    Returns:
        dict with alert creation status
    """
    if not ghost_result.get("ghost_detected"):
        return {"alert_created": False, "reason": "No ghost detected"}

    from app.services.alert_service import create_alert

    reason = ghost_result.get("reason", "unknown")
    detail = ghost_result.get("detail", "Ghost access pattern detected")
    detection_data = ghost_result.get("detection_data", {})

    # Determine severity based on penalty
    penalty = ghost_result.get("penalty", 0.5)
    if penalty >= 0.8:
        severity = "critical"
    elif penalty >= 0.5:
        severity = "warning"
    else:
        severity = "info"

    # Build title
    reason_labels = {
        "simultaneous_session": "Simultaneous Sessions Detected",
        "impossible_travel": "Impossible Travel Detected",
        "credential_sharing": "Credential Sharing Detected"
    }
    title = reason_labels.get(reason, "Ghost Access Detected")

    # Create alert
    alert = create_alert(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        asset_id=asset_id,
        session_id=session_id,
        severity=severity,
        alert_type=f"ghost_access_{reason}",
        title=title,
        description=detail,
        trust_score=trust_score,
        top_features=detection_data
    )

    return {
        "alert_created": True,
        "alert_id": str(alert.id),
        "severity": severity,
        "reason": reason
    }
