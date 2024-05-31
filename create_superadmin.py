from app import app, db
from app.models import Role, User, Permission

# Create the application context
with app.app_context():
    # Create roles if they don't exist
    roles = ['Superadmin', 'Admin', 'User']
    for role_name in roles:
        role = Role.query.filter_by(role_name=role_name).first()
        if not role:
            role = Role(role_name=role_name)
            db.session.add(role)

    # Create permissions
    permissions = ['create_user', 'delete_user', 'edit_user', 'view_user', 'manage_permissions', 'moderate_content']
    for perm_name in permissions:
        permission = Permission.query.filter_by(permission_name=perm_name).first()
        if not permission:
            permission = Permission(permission_name=perm_name)
            db.session.add(permission)
    
    db.session.commit()

    # Assign all permissions to Superadmin
    superadmin_role = Role.query.filter_by(role_name='Superadmin').first()
    if not superadmin_role.permissions:
        all_permissions = Permission.query.all()
        superadmin_role.permissions.extend(all_permissions)
        db.session.commit()

    # Create Superadmin user
    superadmin_user = User.query.filter_by(username='superadmin').first()
    if not superadmin_user:
        superadmin_user = User(username='superadmin', email='superadmin@example.com', role=superadmin_role)
        superadmin_user.set_password('superadminpassword')
        db.session.add(superadmin_user)
        db.session.commit()

    print("Superadmin role and user created successfully!")
