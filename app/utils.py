from app.models import User, Role, Permission, RolePermission

def is_superadmin(user):
    return user.role.role_name == 'Superadmin'

def is_admin(user):
    return user.role.role_name == 'Admin'

def is_user(user):
    return user.role.role_name == 'User'

def has_permission(user, permission_name):
    permission = Permission.query.filter_by(permission_name=permission_name).first()
    if not permission:
        return False
    role_permission = RolePermission.query.filter_by(role_id=user.role_id, permission_id=permission.id).first()
    return role_permission is not None
