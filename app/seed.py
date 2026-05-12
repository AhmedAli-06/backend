"""
Seed script — populates the database with pilot data for demo.
Run: python -m app.seed
"""
import asyncio
import random
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.database import AsyncSessionLocal, Base, engine
from app.models.access import AccessEvent
from app.models.alert import Alert
from app.models.asset import Asset, AssetProject, AssetZone, Project, ProjectMember
from app.models.auth import AuthUser, Role, UserRole
from app.models.tenant import Tenant, TenantConfig
from app.models.user import Credential, User
from app.security import hash_password
from app.services.trust_engine import TrustScoreEngine

TENANT_ID = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
DEPARTMENTS = ["Engineering", "Security", "Operations", "Management", "Maintenance"]
ASSET_TYPES = [
    ("CNC Lathe A1", "cnc_machine", "critical"),
    ("CNC Mill B2", "cnc_machine", "critical"),
    ("Welding Station C1", "welding_station", "high"),
    ("Assembly Line D1", "assembly_line", "high"),
    ("Paint Booth E1", "paint_booth", "medium"),
    ("Forklift F1", "forklift", "medium"),
    ("3D Printer G1", "3d_printer", "medium"),
    ("Hydraulic Press H1", "press", "critical"),
    ("Robot Arm J1", "robot_arm", "critical"),
    ("Test Chamber K1", "test_chamber", "high"),
    ("Compressor L1", "compressor", "low"),
    ("Server Rack M1", "server", "critical"),
]
NAMES = [
    "Arjun Mehta", "Priya Sharma", "Vikram Singh", "Ananya Patel", "Rahul Kumar",
    "Sneha Reddy", "Amit Verma", "Kavita Iyer", "Rajesh Nair", "Deepika Gupta",
    "Suresh Rao", "Lakshmi Das", "Manoj Pillai", "Divya Menon", "Kiran Joshi",
    "Neha Agarwal", "Sanjay Desai", "Pooja Bhat", "Arun Chopra", "Meera Tiwari",
]


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Check if already seeded
        existing = await db.execute(select(Tenant).where(Tenant.id == TENANT_ID))
        if existing.scalar_one_or_none():
            print("[OK] Database already seeded.")
            return

        # --- Tenant ---
        tenant = Tenant(
            id=TENANT_ID, name="Meridian Manufacturing",
            slug="meridian-mfg", industry="manufacturing",
            subscription_tier="pilot", onboarding_status="active",
        )
        db.add(tenant)
        config = TenantConfig(tenant_id=TENANT_ID)
        db.add(config)
        await db.flush()

        # --- Roles ---
        roles = {}
        for rname in ["admin", "security_officer", "supervisor", "operator", "viewer"]:
            r = Role(tenant_id=TENANT_ID, name=rname, is_system=True)
            db.add(r)
            roles[rname] = r

        # --- Auth user (admin login) ---
        admin = AuthUser(
            tenant_id=TENANT_ID, email="admin@meridian-mfg.com",
            password_hash=hash_password("ContextShield2025!"),
            full_name="System Admin", is_superuser=True,
        )
        db.add(admin)
        await db.flush()
        db.add(UserRole(auth_user_id=admin.id, role_id=roles["admin"].id))

        # --- Zone ---
        zone = AssetZone(tenant_id=TENANT_ID, name="Main Factory Floor", location="Building A")
        db.add(zone)
        await db.flush()

        # --- Users (physical workers) ---
        users = []
        for i, name in enumerate(NAMES):
            dept = DEPARTMENTS[i % len(DEPARTMENTS)]
            u = User(
                tenant_id=TENANT_ID, full_name=name,
                email=f"{name.lower().replace(' ', '.')}@meridian-mfg.com",
                department=dept, employee_code=f"MFG-{1001 + i}",
                job_title=f"Senior {dept} Specialist" if i < 5 else f"{dept} Technician",
            )
            db.add(u)
            users.append(u)
        await db.flush()

        # --- Credentials ---
        for u in users:
            db.add(Credential(
                tenant_id=TENANT_ID, user_id=u.id,
                credential_type="rfid_badge",
                credential_value=f"RFID-{uuid.uuid4().hex[:12].upper()}",
            ))

        # --- Assets ---
        assets = []
        for name, atype, crit in ASSET_TYPES:
            a = Asset(
                tenant_id=TENANT_ID, name=name, asset_type=atype,
                category="production", location="Building A",
                zone_id=zone.id, criticality=crit,
            )
            db.add(a)
            assets.append(a)
        await db.flush()

        # --- Project ---
        project = Project(
            tenant_id=TENANT_ID, name="Q2 Production Run",
            status="active", description="Main production for Q2 2025",
        )
        db.add(project)
        await db.flush()

        for u in users[:12]:
            db.add(ProjectMember(project_id=project.id, user_id=u.id, role="operator"))
        for a in assets[:8]:
            db.add(AssetProject(asset_id=a.id, project_id=project.id))

        # --- Simulated Access Events ---
        engine_ts = TrustScoreEngine()
        now = datetime.now(UTC)
        events_created = 0

        for day_offset in range(7, -1, -1):
            base_time = now - timedelta(days=day_offset)
            num_events = random.randint(40, 80) if day_offset == 0 else random.randint(30, 60)

            for _ in range(num_events):
                user = random.choice(users)
                asset = random.choice(assets)
                hour = random.choices(
                    range(24),
                    weights=[1]*6 + [8]*12 + [3]*4 + [1]*2,
                    k=1
                )[0]
                event_time = base_time.replace(hour=hour, minute=random.randint(0, 59))

                is_on_project = random.random() > 0.15
                result = engine_ts.evaluate(
                    occurred_at=event_time,
                    user_on_project=is_on_project,
                    asset_on_project=is_on_project,
                    baseline_exists=False,
                )

                event = AccessEvent(
                    tenant_id=TENANT_ID, user_id=user.id, asset_id=asset.id,
                    event_type=random.choice(["access_granted", "access_attempt"]),
                    event_source="rfid_reader",
                    occurred_at=event_time,
                    trust_score=result.trust_score,
                    identity_score=result.identity_score,
                    temporal_score=result.temporal_score,
                    project_score=result.project_score,
                    role_score=result.role_score,
                    anomaly_score=result.anomaly_score,
                    decision=result.decision,
                    decision_reason=result.decision_reason,
                    processing_ms=result.processing_ms,
                    feature_vector=result.feature_vector,
                )
                db.add(event)
                events_created += 1

                # Generate alerts for low-trust events
                if result.decision in ("alert", "revoke"):
                    db.add(Alert(
                        tenant_id=TENANT_ID, user_id=user.id, asset_id=asset.id,
                        severity="critical" if result.decision == "revoke" else "warning",
                        alert_type="low_trust_score",
                        title=f"Low trust score ({result.trust_score}) for {user.full_name} on {asset.name}",
                        description=result.decision_reason,
                        trust_score_at_trigger=result.trust_score,
                        anomaly_score_at_trigger=result.anomaly_score,
                        triggered_at=event_time,
                    ))

        await db.commit()
        print(f"[OK] Seeded: 1 tenant, {len(users)} users, {len(assets)} assets, {events_created} events")
        print("  Admin login: admin@meridian-mfg.com / ContextShield2025!")


if __name__ == "__main__":
    asyncio.run(seed())
