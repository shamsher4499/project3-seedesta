from superadmin.models import *
from datetime import date

def removeUser():
    users = []
    all_users = GoalPoll.objects.filter(due_date=date.today(), remove_self=1)
    for i in all_users:
        users.append(i.leave_user_id)
        i.delete()
    GoalMember.objects.filter(members_id__in=users).delete()
    RequestGoal.objects.filter(member__in=users).delete()
    GoalGroupAdmin.objects.filter(user_id__in=users).delete()
    GoalLeaveRequest.objects.filter(user_id__in=users).delete()


def cancelUserSubscription():
    pass