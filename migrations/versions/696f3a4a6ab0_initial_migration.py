"""Initial migration

Revision ID: 696f3a4a6ab0
Revises: 5161db879c4d
Create Date: 2024-06-01 00:16:07.774791

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '696f3a4a6ab0'
down_revision = '5161db879c4d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('roles_permissions',
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.Column('permission_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['permission.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )
    op.create_table('user_roles',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    with op.batch_alter_table('permission', schema=None) as batch_op:
        batch_op.alter_column('permission_name',
               existing_type=mysql.VARCHAR(length=100),
               type_=sa.String(length=64),
               nullable=True)

    with op.batch_alter_table('role', schema=None) as batch_op:
        batch_op.alter_column('role_name',
               existing_type=mysql.VARCHAR(length=50),
               type_=sa.String(length=64),
               nullable=True)

    with op.batch_alter_table('role_permission', schema=None) as batch_op:
        batch_op.add_column(sa.Column('id', sa.Integer(), nullable=False))
        batch_op.alter_column('role_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=True)
        batch_op.alter_column('permission_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=True)

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('username',
               existing_type=mysql.VARCHAR(length=150),
               type_=sa.String(length=64),
               existing_nullable=False)
        batch_op.alter_column('password_hash',
               existing_type=mysql.VARCHAR(length=128),
               nullable=True)
        batch_op.drop_constraint('user_ibfk_1', type_='foreignkey')
        batch_op.drop_column('role_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False))
        batch_op.create_foreign_key('user_ibfk_1', 'role', ['role_id'], ['id'])
        batch_op.alter_column('password_hash',
               existing_type=mysql.VARCHAR(length=128),
               nullable=False)
        batch_op.alter_column('username',
               existing_type=sa.String(length=64),
               type_=mysql.VARCHAR(length=150),
               existing_nullable=False)

    with op.batch_alter_table('role_permission', schema=None) as batch_op:
        batch_op.alter_column('permission_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=False)
        batch_op.alter_column('role_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=False)
        batch_op.drop_column('id')

    with op.batch_alter_table('role', schema=None) as batch_op:
        batch_op.alter_column('role_name',
               existing_type=sa.String(length=64),
               type_=mysql.VARCHAR(length=50),
               nullable=False)

    with op.batch_alter_table('permission', schema=None) as batch_op:
        batch_op.alter_column('permission_name',
               existing_type=sa.String(length=64),
               type_=mysql.VARCHAR(length=100),
               nullable=False)

    op.drop_table('user_roles')
    op.drop_table('roles_permissions')
    # ### end Alembic commands ###