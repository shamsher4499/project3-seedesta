from django.conf import settings
from django.core.mail import send_mail
import random
from superadmin.models import User, EmailTemplate
import re
from django.core.mail import send_mail, EmailMessage
import threading
from datetime import datetime
 


class EmailThread(threading.Thread):
    def __init__(self, subject, html_content, recipient_list):
        self.subject = subject
        self.recipient_list = recipient_list
        self.html_content = html_content
        threading.Thread.__init__(self)

    def run (self):
        msg = EmailMessage(self.subject, self.html_content, settings.EMAIL_HOST_USER, self.recipient_list)
        msg.send()

def sendForgetPassOTPUser(user):
    email = EmailTemplate.objects.get(name='Forget Password')
    otp = random.randint(1000, 9999)
    subject = email.name
    data = email.editor
    replace_data = data.format(otp=otp)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False )
    user.otp = otp
    user.save()


def sendWelcomeMailVendor(user):
    email = EmailTemplate.objects.get(name='Registration Successfully')
    subject = email.name
    data = email.editor
    replace_data = data.format(company_username=user.company_username, email=user.email)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False )

def sendWelcomeMailUser(user):
    email = EmailTemplate.objects.get(name='Registration Confirmation Email')
    subject = email.name
    data = email.editor
    replace_data = data.format(first_name=user.first_name, email=user.email)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False )


def sendContactUsMail(user):
    email = EmailTemplate.objects.get(name='Thanking for Contact us')
    subject = email.name
    data = email.editor
    replace_data = data.format(name=user.name, email=user.email)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False )


def sendSubscriptionMail(billing_date, plan_name, user_email, amount):
    subject = 'Your Subscription payment date'
    message = f'Your Subscription Plan Successfully Activated.\n\nPlan Name = {plan_name}\nAmount: ${amount}\n\nNext Payment Date: {billing_date}\n\nThanks & Regards\nSeedesta Team'
    EmailThread(subject, message, user_email).start()
