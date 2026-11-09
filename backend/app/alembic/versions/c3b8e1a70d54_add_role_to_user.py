import sqlalchemy as sa
from alembic import op

revision = "c3b8e1a70d54"
down_revision = "fe56fa70289e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sa.Enum("admin", "manager", "member", name="userrole").create(
        op.get_bind(), checkfirst=True
    )
    op.add_column(
        "user",
        sa.Column(
            "role",
            sa.Enum(
                "admin",
                "manager",
                "member",
                name="userrole",
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'member'::userrole"),
        ),
    )
    op.execute("UPDATE \"user\" SET role = 'admin' WHERE is_superuser IS TRUE")
    op.create_check_constraint(
        "ck_user_role_matches_superuser",
        "user",
        "(role = 'admin' AND is_superuser IS TRUE) OR (role <> 'admin' AND is_superuser IS FALSE)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_user_role_matches_superuser", "user", type_="check")
    op.drop_column("user", "role")
    sa.Enum(name="userrole").drop(op.get_bind(), checkfirst=True)
