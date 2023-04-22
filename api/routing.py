from django.urls import path,re_path
from api.consumers import ChatConsumer, GroupChatConsumer

websocket_urlpatterns = [
    re_path('ws/chat/(?P<room_name>\w+)/$',ChatConsumer.as_asgi()),
    re_path('ws/groupchat/(?P<room_id>\w+)/$',GroupChatConsumer.as_asgi()),
]