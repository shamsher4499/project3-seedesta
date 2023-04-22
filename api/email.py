from django.conf import settings
from django.core.mail import send_mail, EmailMessage
import random
from superadmin.models import GoalMember, User, EmailTemplate
import re
import threading
from datetime import datetime
from threading import Thread

class EmailThread(threading.Thread):
    def __init__(self, subject, html_content, recipient_list):
        self.subject = subject
        self.recipient_list = recipient_list
        self.html_content = html_content
        threading.Thread.__init__(self)

    def run (self):
        msg = EmailMessage(self.subject, self.html_content, settings.EMAIL_HOST_USER, self.recipient_list)
        msg.send()

def sendOTP(user):
    email = EmailTemplate.objects.get(name='Verify Email OTP')
    otp = random.randint(1000, 9999)
    subject = email.name
    data = email.editor
    replace_data = data.format(first_name=user.first_name, otp=otp)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    EmailThread(subject, message, [user.email]).start()
    user.otp = otp
    user.save()

def sendConfirmationMail(receipt_url, goal_id, user_email, amount):
    subject = 'Payment confirmation'
    message = f'We have successfully recieved your payment.\n\nGoal Name = {goal_id.goal_name}\nAmount: ${amount}\n\nYou can find invoice here: {receipt_url}\n\nThanks & Regards\nSeedesta Team'
    EmailThread(subject, message, [user_email]).start()
    # send_mail( subject, message, email_from, [user.email], fail_silently=False)

def sendSubscriptionMail(billing_date, plan_name, user_email, amount):
    subject = 'Your Subscription payment date'
    message = f'Your Subscription Plan Successfully Activated.\n\nPlan Name = {plan_name}\nAmount: ${amount}\n\nNext Payment Date: {billing_date}\n\nThanks & Regards\nSeedesta Team'
    EmailThread(subject, message, user_email).start()

def sendGoalCompleteMail(user_goal, user):
    subject = 'Your Goal Subscription successfully completed.'
    message = f'Your Goal Successfully completed.\n\nGoal Name = {user_goal.goal_name}\nAmount: ${user_goal.goal_amount}\n\nThanks & Regards\nSeedesta Team'
    EmailThread(subject, message, user.email).start()

def sendProductGoalCompleteMail(user_goal, user):
    subject = 'Your Order successfully completed.'
    message = f'Your Order Successfully completed.\n\Order Name = {user.name}\nAmount: ${user.price}\nStart Date: {user_goal.start_date}\nCompleted date: {datetime.now()}\n\nThanks & Regards\nSeedesta Team'
    EmailThread(subject, message, user.email).start()