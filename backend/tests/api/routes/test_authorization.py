from fastapi.testclient import TestClient
from sqlmodel import Session

from app import crud
from app.core.config import settings
from app.models import UserRole
from tests.utils.user import authentication_token_from_email, create_random_user
from tests.utils.utils import random_email, random_lower_string

PRIVILEGES_ERROR = {"detail": "The user doesn't have enough privileges"}


def _token_headers(
    *, client: TestClient, db: Session, role: UserRole
) -> dict[str, str]:
    return authentication_token_from_email(
        client=client, email=random_email(), db=db, role=role
    )


def test_list_users_allows_manager_and_denies_member(
    client: TestClient, db: Session
) -> None:
    member_headers = _token_headers(client=client, db=db, role=UserRole.member)
    manager_headers = _token_headers(client=client, db=db, role=UserRole.manager)

    denied = client.get(f"{settings.API_V1_STR}/users/", headers=member_headers)
    assert denied.status_code == 403
    assert denied.json() == PRIVILEGES_ERROR

    allowed = client.get(f"{settings.API_V1_STR}/users/", headers=manager_headers)
    assert allowed.status_code == 200
    assert "data" in allowed.json()
    assert "count" in allowed.json()


def test_create_user_allows_admin_and_denies_manager(
    client: TestClient, db: Session
) -> None:
    admin_headers = _token_headers(client=client, db=db, role=UserRole.admin)
    manager_headers = _token_headers(client=client, db=db, role=UserRole.manager)
    password = random_lower_string()

    denied = client.post(
        f"{settings.API_V1_STR}/users/",
        headers=manager_headers,
        json={"email": random_email(), "password": password},
    )
    assert denied.status_code == 403
    assert denied.json() == PRIVILEGES_ERROR

    member_email = random_email()
    created = client.post(
        f"{settings.API_V1_STR}/users/",
        headers=admin_headers,
        json={"email": member_email, "password": password},
    )
    assert created.status_code == 200
    assert created.json()["role"] == UserRole.member
    stored_member = crud.get_user_by_email(session=db, email=member_email)
    assert stored_member
    assert stored_member.role == UserRole.member

    manager_email = random_email()
    created_manager = client.post(
        f"{settings.API_V1_STR}/users/",
        headers=admin_headers,
        json={"email": manager_email, "password": password, "role": "manager"},
    )
    assert created_manager.status_code == 200
    assert created_manager.json()["role"] == UserRole.manager


def test_metrics_allows_manager_and_denies_member(
    client: TestClient, db: Session
) -> None:
    member_headers = _token_headers(client=client, db=db, role=UserRole.member)
    manager_headers = _token_headers(client=client, db=db, role=UserRole.manager)

    denied = client.get(f"{settings.API_V1_STR}/metrics/", headers=member_headers)
    assert denied.status_code == 403
    assert denied.json() == PRIVILEGES_ERROR

    allowed = client.get(f"{settings.API_V1_STR}/metrics/", headers=manager_headers)
    assert allowed.status_code == 200
    body = allowed.json()
    assert isinstance(body["user_count"], int)
    assert isinstance(body["item_count"], int)


def test_member_can_update_self_but_not_another_user(
    client: TestClient, db: Session
) -> None:
    member_headers = _token_headers(client=client, db=db, role=UserRole.member)
    other_user = create_random_user(db)

    updated = client.patch(
        f"{settings.API_V1_STR}/users/me",
        headers=member_headers,
        json={"full_name": "Updated Member"},
    )
    assert updated.status_code == 200
    assert updated.json()["full_name"] == "Updated Member"

    denied = client.patch(
        f"{settings.API_V1_STR}/users/{other_user.id}",
        headers=member_headers,
        json={"full_name": "Taken Over"},
    )
    assert denied.status_code == 403
    assert denied.json() == PRIVILEGES_ERROR


def test_signup_creates_member_and_profile_update_cannot_change_role(
    client: TestClient, db: Session
) -> None:
    email = random_email()
    password = random_lower_string()
    created = client.post(
        f"{settings.API_V1_STR}/users/signup",
        json={
            "email": email,
            "password": password,
            "role": "admin",
            "is_superuser": True,
        },
    )
    assert created.status_code == 200
    assert created.json()["role"] == UserRole.member
    assert created.json()["is_superuser"] is False

    stored = crud.get_user_by_email(session=db, email=email)
    assert stored
    assert stored.role == UserRole.member
    assert stored.is_superuser is False

    headers = authentication_token_from_email(client=client, email=email, db=db)
    updated = client.patch(
        f"{settings.API_V1_STR}/users/me",
        headers=headers,
        json={"full_name": "Still Member", "role": "admin"},
    )
    assert updated.status_code == 200
    assert updated.json()["full_name"] == "Still Member"
    assert updated.json()["role"] == UserRole.member

    db.refresh(stored)
    assert stored.role == UserRole.member
