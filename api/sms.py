import os
from twilio.rest import Client
import random
from django.conf import settings


client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

def sendSms(user):
    otp = random.randint(1000, 9999)
    message = client.messages.create(
        body=f"Your OTP is: {otp}",
        from_='+18573747732',
        to=f'+91{user.mobile}'
    )
    message.sid
    user.otp = otp
    user.save()