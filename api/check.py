from superadmin.models import User

def checkUser():
    pendingUsers = User.objects.filter(is_verified=False, user_type='USER').count()