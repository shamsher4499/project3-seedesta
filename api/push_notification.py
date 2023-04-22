from pyfcm import FCMNotification
from django.conf import settings

def webpush_notification(fcm_token,message_title,message_body,payload):
    push_service = FCMNotification(api_key=settings.API_KEY)
    push_service.notify_multiple_devices(registration_ids=[fcm_token], message_title=message_title, message_body=message_body, data_message=payload)