from django.conf import settings
from django.core.mail import send_mail
from django.core.mail import send_mail, EmailMessage
import random
from .models import User, EmailTemplate
import re
import threading

class EmailThread(threading.Thread):
    def __init__(self, subject, html_content, recipient_list):
        self.subject = subject
        self.recipient_list = recipient_list
        self.html_content = html_content
        threading.Thread.__init__(self)

    def run (self):
        msg = EmailMessage(self.subject, self.html_content, settings.EMAIL_HOST_USER, self.recipient_list)
        msg.send()

# def sendOTP(user):
#     subject = 'Email Verification Code'
#     otp = random.randint(100000, 999999)
#     message = f'Hii \nYour OTP is {user.otp} for email verification'
#     email_from = settings.EMAIL_HOST_USER
#     send_mail( subject, message, email_from, [user.email] )
#     user.otp = otp
#     user.save()


def resendOTP(user):
    email = EmailTemplate.objects.get(name='Resend Verify Email OTP')
    otp = random.randint(1000, 9999)
    subject = email.name
    data = email.editor
    replace_data = data.format(first_name=user.first_name, otp=otp)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False )
    user.otp = otp
    user.save()

def sendOTP(user):
    email = EmailTemplate.objects.get(name='Verify Email OTP')
    otp = random.randint(1000, 9999)
    subject = email.name
    data = email.editor
    if user.first_name :
        replace_data = data.format(first_name=user.first_name, otp=otp)
    else:
        replace_data = data.format(first_name=user.company_name, otp=otp)    
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False )
    user.otp = otp
    user.save()
    


def sendUserInfo(user):
    subject = "Seedesta Login Credentials"
    message = f"Hii {user.first_name}\nYour Email address is {user.email}\nYour Password is {user.password}.\nPlease Login and Reset password first.\nThanks"
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email] )

def sendWelcomeMail(user):
    email = EmailTemplate.objects.get(name='Welcome Mail')
    subject = email.name
    data = email.editor
    replace_data = data.format(first_name=user.first_name, email=user.email, password=user.password)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False )

def sendForgetPassOTP(user):
    email = EmailTemplate.objects.get(name='Forget Password')
    otp = random.randint(100000, 999999)
    subject = email.name
    data = email.editor
    replace_data = data.format(otp=otp)
    clear = re.compile('<.*?>') 
    message = re.sub(clear, '', replace_data)
    email_from = settings.EMAIL_HOST_USER
    send_mail( subject, message, email_from, [user.email], fail_silently=False)
    user.otp = otp
    user.save()

def accountApproved(vendor):
    email = EmailTemplate.objects.get(name='Account Approved')
    subject = email.name
    data = email.editor
    message = data.format(company_username=vendor.company_username)
    EmailThread(subject, message, [vendor.email]).start()