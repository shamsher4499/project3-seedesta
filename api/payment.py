import stripe
from django.conf import settings
from django.http import JsonResponse
from django.views import View
from superadmin.models import UserGoal, GoalMember, GoalGroupAdmin, User, GoalPayment
from django.shortcuts import redirect

stripe.api_key = settings.STRIPE_SECRET_KEY

# class PaymentView(View):
def goalAmountCalculation(user, goal):
    if user:
        user_data = User.objects.get(email=user)
        user_member = GoalMember.objects.get(goal_id=goal.id, members_id=user_data.id, approve=1)
        amount = GoalPayment.objects.filter(user_id = user, goal_id = goal)
        # goal_data = UserGoal.objects.get(id = goal)
        total_paid = 0
        for i in amount:
            total_paid = int(i.payment_paid)
    pass