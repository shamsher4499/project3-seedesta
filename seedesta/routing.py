from django.urls import path, re_path
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from api.consumers import ChatConsumer, GroupChatConsumer
from app.consumers import WebChatConsumer, WebGroupChatConsumer

application = ProtocolTypeRouter({
    "websocket": AuthMiddlewareStack(
        URLRouter([
            re_path('ws/chat/(?P<room_name>\w+)/$', ChatConsumer.as_asgi()),
            re_path('ws/groupchat/(?P<room_id>\w+)/$',GroupChatConsumer.as_asgi()),
            re_path('ws/web_chat/(?P<room_name>\w+)/$', WebChatConsumer.as_asgi()),
            re_path('ws/web_groupchat/(?P<room_id>\w+)/$',WebGroupChatConsumer.as_asgi()),
            
            
        ]),
    ),
})