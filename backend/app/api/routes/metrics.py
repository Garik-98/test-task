from fastapi import APIRouter, Depends
from sqlmodel import func, select

from app.api.deps import SessionDep, require_role
from app.models import Item, MetricsPublic, User, UserRole

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get(
    "/",
    dependencies=[Depends(require_role(UserRole.admin, UserRole.manager))],
    response_model=MetricsPublic,
)
def read_metrics(session: SessionDep) -> MetricsPublic:
    user_count = session.exec(select(func.count()).select_from(User)).one()
    item_count = session.exec(select(func.count()).select_from(Item)).one()
    return MetricsPublic(user_count=user_count, item_count=item_count)
