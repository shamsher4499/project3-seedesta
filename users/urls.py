from unicodedata import name
from django.urls import path

from superadmin import views
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),

]