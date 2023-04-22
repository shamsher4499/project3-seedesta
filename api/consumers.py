from time import sleep
from channels.consumer import AsyncConsumer
from time import sleep
import asyncio
import json
from superadmin.models import *
from asgiref.sync import sync_to_async, async_to_sync
from channels.generic.websocket import AsyncWebsocketConsumer
from django.db.models import Q

class ChatConsumer(AsyncWebsocketConsumer):
  async def connect(self):   
    self.room_name = self.scope['url_route']['kwargs']['room_name']
    self.room_group_name = 'chat_%s' % self.room_name
    # Join room group
    await self.channel_layer.group_add(
      self.room_group_name,
      self.channel_name
    )
    await self.accept()

  async def disconnect(self, close_code):
    # Leave room group
    await self.channel_layer.group_discard(
      self.room_group_name,
      self.channel_name
  )

  async def receive(self, text_data):
    data = json.loads(text_data)
    sender=data['sender']
    receiver=data['receiver']
    message=data['message']
    # image=data['image'] 
    room=self.room_name
    await self.save_message(room, message, sender, receiver)
    

  # Send message to room group
    await self.channel_layer.group_send(
      self.room_group_name,
      {
        'type': 'chat_message',
        # 'image': image,
        'message': message,
        'sender':sender,
        'receiver':receiver,
        'room':room
      }
    )
   
# # Receive message from room group
  async def chat_message(self, event):
    # image = event['image']
    message = event['message']
    sender=event['sender']
    receiver=event['receiver']
    room=event['room']

  # Send message to WebSocket
    await self.send(text_data=json.dumps({
        # 'image': image,
        'message': message,
        'sender':sender,
        'receiver':receiver,
        'room':room
     }))
    
  @sync_to_async
  def save_message(self, room, message, sender, receiver):
    room1 = room.split('_')
    room_id = f'{room1[0]}' + '_room_' + f'{room1[-1]}'
    room_id1 = f'{room1[-1]}' + '_room_' + f'{room1[0]}'
    try:
        room = Room.objects.get(Q(room=room_id) | Q(room=room_id1))
    except:
        room = None
    msg=message.strip()
    if msg:
      chat, created = Chat.objects.get_or_create(room_id_id=room.id, message=message, sender_id=sender, receiver_id=receiver)
      chat.save()
    else:
      pass


#group chat function where more then 2 persons can chat in the real time.
class GroupChatConsumer(AsyncWebsocketConsumer):
  async def connect(self):   
    self.room_name = self.scope['url_route']['kwargs']['room_id']
    self.room_group_name = 'chat_%s' % self.room_name
    # Join room group
    await self.channel_layer.group_add(
      self.room_group_name,
      self.channel_name
    )
    await self.accept()

  async def disconnect(self, close_code):
    # Leave room group
    await self.channel_layer.group_discard(
      self.room_group_name,
      self.channel_name
  )

  async def receive(self, text_data):
    data = json.loads(text_data)
    chat_massage = data['message']
    sender=data['sender']
    receiver_id=data['receiver_id']
    room_id=self.room_name
    await self.save_message(room_id, chat_massage, sender, receiver_id)

  # Send message to room group
    await self.channel_layer.group_send(
      self.room_group_name,
      {
        'type': 'chat_message',
        'chat_massage': chat_massage,
        'sender':sender,
        'receiver_id':receiver_id,
        'room_id':room_id
      }
    )
   
# # Receive message from room group
  async def chat_message(self, event):
    chat_massage = event['chat_massage']
    sender=event['sender']
    receiver_id=event['receiver_id']
    room_id=event['room_id']

  # Send message to WebSocket
    await self.send(text_data=json.dumps({
        'chat_massage': chat_massage,
        'sender':sender,
        'receiver_id':receiver_id,
        'room_id':room_id
     }))
    
  @sync_to_async
  def save_message(self, room_id, chat_massage, receiver_id, sender):
    # user1 = room[0] + room[1]
    # user2 = room[-2] + room[-1]
    # room_id = f'{user1}' + '_room_' + f'{user2}'
    # room_id1 = f'{user2}' + '_room_' + f'{user1}'
    try:
        room = ChatGroup.objects.get(room_id = room_id)
    except:
        room = None
    msg=chat_massage.strip()
    if msg:
      chat, created = GroupMassage.objects.get_or_create(group_id=room.id, chat_massage=chat_massage, receiver=receiver_id, sender=sender)
      chat.save()
    else:
      pass