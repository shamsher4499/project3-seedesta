# from django.db import models
# from django.contrib.auth.models import AbstractUser
# from .manager import *
# from .choices import *
# # Create your models here.
# class User(AbstractUser):
#     username = None
#     email = models.EmailField( unique=True)
#     password = models.CharField(max_length=255, null=True, blank=True)
#     user_type = models.CharField(max_length=10, choices=USER_TYPE)
#     first_name = models.CharField(max_length=255, null=True, blank=True)
#     last_name = models.CharField(max_length=255, null=True, blank=True)
#     mobile = models.CharField(max_length=255, null=True, blank=True)

#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = []

#     objects = UserManager()
        
#     def __str__(self):
#         return self.email

#     class Meta:
#         verbose_name_plural = "User"