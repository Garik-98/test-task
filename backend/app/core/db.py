from sqlmodel import Session, create_engine, select

from app import crud
from app.core.config import settings
from app.models import User, UserCreate, UserRole

SEEDED_MANAGER_EMAIL = "manager@example.com"
SEEDED_MEMBER_EMAIL = "member@example.com"

engine = create_engine(str(settings.DATABASE_URL), pool_pre_ping=True)


def init_db(session: Session) -> None:
    _ensure_user(
        session,
        email=settings.FIRST_SUPERUSER,
        password=settings.FIRST_SUPERUSER_PASSWORD,
        role=UserRole.admin,
    )
    _ensure_user(
        session,
        email=SEEDED_MANAGER_EMAIL,
        password=settings.FIRST_SUPERUSER_PASSWORD,
        role=UserRole.manager,
    )
    _ensure_user(
        session,
        email=SEEDED_MEMBER_EMAIL,
        password=settings.FIRST_SUPERUSER_PASSWORD,
        role=UserRole.member,
    )


def _ensure_user(
    session: Session, *, email: str, password: str, role: UserRole
) -> None:
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        return
    crud.create_user(
        session=session,
        user_create=UserCreate(email=email, password=password, role=role),
    )
