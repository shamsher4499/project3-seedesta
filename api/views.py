import json
from logging import raiseExceptions
import datetime
import requests
import base64
from django.views.decorators.csrf import csrf_exempt
from operator import sub
from django.db.models import Q, Sum
from rest_framework.pagination import PageNumberPagination
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, SAFE_METHODS, BasePermission
from rest_framework.generics import ListAPIView
from rest_framework.filters import SearchFilter
from superadmin.views import vendor
from .pagination import HelpPagination
from django.http import HttpResponse, JsonResponse
from itertools import chain
from superadmin.models import *
from .serializers import *
from .email import *
from .check import *
from .payment import *
from .sms import *
from currency_converter import CurrencyConverter
from .utils import *
from .push_notification import webpush_notification
import stripe
import jwt
from random import randint
from datetime import timedelta, datetime
from datetime import date
# Create your views here.

def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

def payment_success(request):
    payment_checkout = stripe.checkout.Session.retrieve(
        'cs_test_a1JsXvXlp81YeuWapMaykBtJPCaPfUe4ZLv8LDySx92OxWUXmjHgzalWMm'
    )
    return HttpResponse('Payment Received successfully!')

def payment_failed(request):
    return HttpResponse('Payment failed. Please try again!')

class ReadOnly(BasePermission):
    def has_permission(self, request, view):
        return request.method in SAFE_METHODS

jwt_options = {
        'verify_signature': False,
        'verify_exp': True,
        'verify_nbf': False,
        'verify_iat': True,
        'verify_aud': False
        }

class PaymentView(APIView):
    def get(self, request):
        data = settings.STRIPE_PUBLIC_KEY
        return Response({
            'status': True,
            'payload': data,
            'message': 'You have already registerd',
        })
    
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        # goal_id = self.request.GET['goal_id']
        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            goal = UserGoal.objects.get(id = data['goal_id'])
            goal_member = GoalMember.objects.get(goal_id = data['goal_id'], members_id = user_data.id, approve=1)
        except:
            goal = None
            goal_member = None
        if goal and goal_member:
            goalAmountCalculation(user_data, goal)
            amount = data['amount']
            goal_name = goal.goal_name
            # client_reference_id = user_data
            session = stripe.checkout.Session.create(
                line_items=[{
                    'name': goal_name,
                    'amount': int(amount)*100,
                    'currency': 'usd',
                    'quantity': 1,
                }],
                # email = user_data.email,
                mode='payment',
                success_url = '%s/?session_id={CHECKOUT_SESSION_ID}' % settings.SUCCESS_URL,
                cancel_url = '%s' % settings.CANCEL_URL,
                )
            return Response({
                'status': True,
                'sessionId': session,
                'message': 'Payment Request successfully created. Please find payment URL.',
                })
        else:
            return Response({
                'status': False,
                'message': 'You are not associated with current goal.',
                })

class CheckPaymentStatusView(APIView):
    def get(self, request):
        data = settings.STRIPE_PUBLIC_KEY
        return Response({
            'status': True,
            'payload': data,
            'message': 'You have already registerd',
        })
    
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            goal = UserGoal.objects.get(id = data['goal_id'])
            goal_member = GoalMember.objects.get(goal_id = data['goal_id'], members_id = user_data.id, approve=1)
        except:
            goal = None
            goal_member = None
        if goal and goal_member:
            payment_status1 = GoalPayment(payment_paid = data['amount'], transaction_id=data['id'], payment_status=data['payment_status'],
            goal_id = data['goal_id'], user_id=user_data.id)
            payment_status1.save()
            return Response({
                'status': True,
                'message': 'Payment Details successfully created.',
                })
        else:
            return Response({
                'status': False,
                'message': 'You are not associated with current goal.',
                })

def homepage(request):
    template_name = 'index.html'
    return render(request, template_name)

class RegisterUser(APIView):
    def post(self, request):
        data = request.data
        try:
            user = User.objects.get(email = data['email'])
            verified_user = User.objects.filter(email = data['email'], is_verified=False)
            user_status = User.objects.get(email=user)
        except:
            user = None
            verified_user = None
        serializer = RegitserSerializer(data=data) 
        if not user:
            if serializer.is_valid(raise_exception=False):
                user = serializer.save()
                user.set_password(data['password'])
                sendOTP(user)
                if user.user_type == 'USER':
                    customer_data = stripe.Customer.create(
                        name=user.first_name +' '+user.last_name,
                        email=user.email,
                        phone=user.mobile,
                        )
                    user.customer_id = customer_data['id']
                    user.save()
                    return Response({
                        'status': True,
                        'message': 'Verification code sent on the mail address. Please check'
                    })
                else:
                        if get_size(data['company_document']):
                            customer_data = stripe.Customer.create(
                                name=user.company_username,
                                email=user.email,
                                phone=user.mobile,
                                )
                            user.customer_id = customer_data['id']
                            user.save()
                            return Response({
                                'status': True,
                                'message': 'Verification code sent on the mail address. Please check'
                            })
                        else:
                            return Response({
                                'status': False,
                                'message': 'Document size must be less than or equal 1 MB.',
                            })
            else:
                return Response({
                'status': False,
                'message': serializer.errors,
            })
        elif verified_user:
            return Response({
                'status': False,
                'message': 'You have already registerd',
            })
        else:
            return Response({
                'status': False,
                'message': 'Email Address already registerd.',
                'email_status': user_status.is_verified
            })      

class CheckSocialUser(APIView):
    def post(self, request):
        try:
            data = request.data
            try:
                user = User.objects.get(provider_id = data['provider_id'])
            except:
                user = None 
            if not user:
                serializer = CheckSocialLoginSerializer(data = data, context={'request':request})
                if not serializer.is_valid():
                    return Response({
                        'status': False, 
                        'payload': serializer.errors, 
                        'message': 'Please input valid data.'
                        })
                else:
                    return Response({
                        'status': True, 
                        'message': 'No user found.'
                        })
            else:
                user.fcm_token = data['fcm_token']
                user.save()
                user_view = UserViewSerializer(user)
                vendor_view = VendorViewSerializer(user)
                refresh = RefreshToken.for_user(user)
                if user.user_type == 'USER':
                    if user.is_verified and user.is_active:
                        return Response({
                            'status': True, 
                            'token': str(refresh.access_token),
                            'payload': user_view.data,
                            'message': 'Login Successfully.'
                            })
                    else:
                        return Response({
                            'status': True, 
                            'message': 'Your email is not verified.'
                            })
                if user.user_type == 'VENDOR':
                    if user.is_verified and user.is_active:
                        return Response({
                            'status': True, 
                            'token': str(refresh.access_token),
                            'payload': vendor_view.data,
                            'message': 'Login Successfully.'
                            })
                    else:
                        return Response({
                            'status': False, 
                            'message': 'Your account not active yet. Please wait for admin approval.'
                            })
        except:
            return Response({
                'status': False, 
                'message': 'Something went wrong.'
                })

class RegisterSocialUser(APIView):
    def post(self, request):
        try:
            data = request.data
            try:
                user = User.objects.get(email = data['email'])
            except:
                user = None 
            if user:
                if data['user_type'] == 'USER':
                    serializer = RegisterUserSocialSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'status': False, 
                            'payload': serializer.errors, 
                            'message': 'Please input valid data.'
                            })
                    else:
                        if not User.objects.filter(provider_id=data['provider_id']).exists():
                            user.provider_id = data['provider_id']
                            user.provider_name = data['provider_name']
                            user.fcm_token = data['fcm_token']
                            user.save()
                            user_view = RegitserSerializer(user)
                            refresh = RefreshToken.for_user(user)
                            return Response({
                                'status': True, 
                                'token': str(refresh.access_token),
                                'payload': user_view.data,
                                'message': 'Login Successfully.'
                                })
                        else:
                            return Response({
                                'status': False, 
                                'message': 'You have already registered with this provider.'
                                })
                if data['user_type'] == 'VENDOR':
                    serializer = RegisterVendorSocialSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'status': False, 
                            'payload': serializer.errors, 
                            'message': 'Please input valid data.'
                            })
                    else:
                        if not User.objects.filter(provider_id=data['provider_id']).exists():
                            user.provider_id = data['provider_id']
                            user.provider_name = data['provider_name']
                            user.fcm_token = data['fcm_token']
                            user.save()
                            user_view = RegitserSerializer(user)
                            refresh = RefreshToken.for_user(user)
                            return Response({
                                'status': True, 
                                'token': str(refresh.access_token),
                                'payload': user_view.data,
                                'message': 'Login Successfully.'
                                })
                        else:
                            return Response({
                                'status': False, 
                                'message': 'You have already registered with this provider.'
                                })
            else:
                if data['user_type'] == 'USER':
                    serializer = RegisterUserSocialSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'status': False, 
                            'payload': serializer.errors, 
                            'message': 'Please input valid data.'
                            })
                    else:
                        if not User.objects.filter(provider_id=data['provider_id']).exists():
                            new_user = User.objects.create(first_name=data['first_name'], last_name=data['last_name'], email=data['email'],
                            mobile=data['mobile'], user_type='USER', provider_id=data['provider_id'], provider_name=data['provider_name'],
                            fcm_token=data['fcm_token'], is_active=True, is_verified=True)
                            new_user.save()
                            user = User.objects.get(id = new_user.id)
                            user_view = RegitserSerializer(user)
                            refresh = RefreshToken.for_user(user)
                            return Response({
                                'status': True, 
                                'token': str(refresh.access_token),
                                'payload': user_view.data,
                                'message': 'You have Successfully Registered with this provider.'
                                })
                        else:
                            return Response({
                                'status': False, 
                                'message': 'You have already registered with this provider.'
                                })
                if data['user_type'] == 'VENDOR':
                    serializer = RegisterVendorSocialSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'status': False, 
                            'payload': serializer.errors, 
                            'message': 'Please input valid data.'
                            })
                    else:
                        if not User.objects.filter(provider_id=data['provider_id']).exists():
                            new_vendor = User.objects.create(company_username=data['company_username'], company_name=data['company_name'], email=data['email'], company_regisration_number=data['company_regisration_number'], company_document=data['company_document'],
                            mobile=data['mobile'], user_type='VENDOR', provider_id=data['provider_id'], provider_name=data['provider_name'],
                            fcm_token=data['fcm_token'], is_verified=True)
                            new_vendor.save()
                            return Response({
                                'status': True, 
                                'message': 'You have successfully registered with this provider. Please wait for admin approval.'
                                })
                        else:
                            return Response({
                                'status': False, 
                                'message': 'You have already registered with this provider.'
                                })
        except:
            return Response({
                'status': False, 
                'message': 'Something went wrong.'
                })

class ResendOTPView(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = ResendOTPSerializer(data = data)
            if serializer.is_valid():
                email = request.data['email']
                filter_email = email.lower()
                try:
                    user = User.objects.get(email=filter_email)
                except:
                    user : None
                if user:
                    if not user.is_verified:
                        sendOTP(user)
                        return Response({
                            'status': True,
                            'message': 'Verification code sent on the mail address. Please check',
                            'email_status': user.is_verified
                        })
                    else:
                        return Response({
                            'status': False,
                            'message': 'You have already verify this email address',
                            'email_status': user.is_verified
                        })
                else:
                    return Response({
                        'status': False,
                        'message': 'This Email Address not found in our system.',
                    })
            else:
                return Response({
                            'status': False,
                            'errors': serializer.errors
                        })
        except:
            return Response({
                        'status': False,
                        'message': 'Email Address not found.',
                    })

class VerifyOTP(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = VerifyOTPSerializer(data = data)
            if serializer.is_valid():
                email = request.data['email']
                otp = request.data['otp']
                filter_email = email.lower()
                user = User.objects.filter(email=filter_email).first()
                if user is None:
                    return Response({
                                'status': True,
                                'message': "This Email address not found in our system.",
                            })
                if user.otp != otp:
                    return Response({
                                'status': False,
                                'message': "OTP does not match. Please try again."
                            })
                else:
                    if not user.is_verified:
                        user.is_verified = True
                        user.save()
                        user_view = UserViewSerializer(user)
                        vendor_view = VendorViewSerializer(user)
                        user = User.objects.get(email = serializer.data['email'])
                        user.fcm_token = data['fcm_token']
                        user.save()
                        refresh = RefreshToken.for_user(user)
                        if user.user_type == 'USER':
                            user.is_verified = True
                            user.is_active = True
                            user.save()
                            return Response({
                                    'status': True,
                                    'token': str(refresh.access_token),
                                    'payload': user_view.data,
                                    'message': "You have successfully verified Email."
                                })
                        if user.user_type == 'VENDOR':
                            user.is_verified = True
                            user.save()
                            return Response({
                                    'status': True,
                                    'token': str(refresh.access_token),
                                    'payload': vendor_view.data,
                                    'message': "Your account is under verification by the admin."
                                })
                    else:
                        return Response({
                                'status': False,
                                'message': "You have already verified Email."
                            })
            return Response({
                        'status': False,
                        'message': 'Please Input validate data!',  
                    })
        except:
            return Response({
                'status': False,
                'message': 'Email not found our system.',   
            })

class LoginUser(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = LoginSerializer(data = data)
            if serializer.is_valid():
                email = request.data['email']
                password = request.data['password'] 
                filter_email = email.lower()
                user = User.objects.filter(email=filter_email).first()
                user_data = User.objects.get(email=user)
                user_view = UserViewSerializer(user_data, context={'request':request})
                if not user:
                    return Response({
                        'status': False,
                        'message': 'This Email address not found in our system.'
                        })
                if not user.check_password(password):
                    return Response({
                            'status': False,
                            'message': 'Incorrect Password. Please try again!'
                        })
                if not user.is_active == True:
                    return Response({
                            'status': False,
                            'message': 'Your Account is Inactive. Please contact the Admin.'
                        })
                else:
                    if user.is_verified:
                        user = User.objects.get(email = filter_email)
                        if not User.objects.filter(fcm_token=data['fcm_token']).exists():
                            fcm_user = User.objects.filter(fcm_token=data['fcm_token'])
                            for i in fcm_user:
                                i.fcm_token = None
                                i.save()
                        user.fcm_token = data['fcm_token']
                        user.save()
                        user_view = UserViewSerializer(user)
                        vendor_view = VendorViewSerializer(user)
                        refresh = RefreshToken.for_user(user)
                        if user.user_type == 'USER':
                            return Response({
                                'status': True,
                                'token': str(refresh.access_token),
                                'payload': user_view.data,
                                'message': "You have successfully verified Email."
                            })
                        if user.user_type == 'VENDOR':
                            return Response({
                                'status': True,
                                'token': str(refresh.access_token),
                                'payload': vendor_view.data,
                                'message': "You have successfully login."
                            })
                    else:
                        sendOTP(user)
                        return Response({
                            'status': True,
                            'message': 'Verification code sent on the mail address. Please check',
                            'email_status': user.is_verified
                        })
            return Response({
                'status': False,
                'message': 'Please Input validate data...',
            })
        except:
            return Response({
                'status': False,
                'message': 'This Email address not found in our system.',
            })

class LogoutUser(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER':
                if user_data.fcm_token:
                    user_data.fcm_token = None
                    user_data.save()
                    return Response({
                        'status': True, 
                        'message': "Logout Successfully."
                        })
                return Response({
                    'status': True, 
                    'message': "Logout Successfully."
                    })
            if user_data.user_type == 'VENDOR':
                if user_data.fcm_token:
                    user_data.fcm_token = None
                    user_data.save()
                    return Response({
                        'status': True, 
                        'message': "Logout Successfully."
                        })
                return Response({
                    'status': True, 
                    'message': "Logout Successfully."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticate User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class MobileLoginUser(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = MobileLoginSerializer(data = data)  
            if serializer.is_valid():
                mobile = request.data['mobile']
                user = User.objects.filter(mobile=mobile).first()
                mobile_data = mobile[6:10]
                if user is None:
                    return Response({
                            'status': False,
                            'message': 'This Mobile Number not found in our system.'
                        })
                if not user.is_active == True:
                    return Response({
                            'status': False,
                            'message': 'Your Account is Inactive. Please contact the Admin.'
                        })
                else:
                    if user.is_verified:
                        if user.user_type == 'USER':
                            sendSms(user)
                            return Response({
                                'status': True,
                                'message': f"OTP send successfully on ***{mobile_data}"
                                })
                        if user.user_type == 'VENDOR':
                            sendSms(user)
                            return Response({
                                'status': True,
                                'message': f"OTP send successfully on ***{mobile_data}"
                                })
                    else:
                        sendOTP(user)
                        return Response({
                            'status': True,
                            'message': 'Verification code sent on the mail address. Please check',
                            'email_status': user.is_verified
                        })
            return Response({
                        'status': False,
                        'message': 'Please Input validate data...',
                    })
        except:
            return Response({
                    'status': False,
                    'message': 'Mobile Number not found.',
                })

class VerifMobileyOTP(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = MobileVerifyOTPSerializer(data=data)
            if serializer.is_valid():
                mobile = request.data['mobile']
                otp = request.data['otp']
                user = User.objects.filter(mobile=mobile).first()
                if user is None:
                    return Response({
                        'status': True,
                        'message': "This Mobile number not found in our system.",
                    })
                if otp != user.otp:
                    return Response({
                        'status': False,
                        'message': "OTP does not match. Please try again."
                    })
                if not user.is_verified:
                    return Response({
                        'status': False,
                        'message': "Please Verify Email First."
                    })
                if user.is_verified and user.is_active:
                    user_view = UserViewSerializer(user)
                    vendor_view = VendorViewSerializer(user)
                    user = User.objects.get(mobile = serializer.data['mobile'])
                    user.fcm_token = data['fcm_token']
                    user.save()
                    refresh = RefreshToken.for_user(user)
                    if user.user_type == 'USER':
                        return Response({
                                'status': True,
                                'token': str(refresh.access_token),
                                'payload': user_view.data,
                                'message': "Login successfully."
                            })
                    if user.user_type == 'VENDOR':
                        return Response({
                                'status': True,
                                'token': str(refresh.access_token),
                                'payload': vendor_view.data,
                                'message': "Login successfully."
                            })
                else:
                    return Response({
                        'status': False,
                        'message': 'Your account is not active. Please contact with Admin.',  
                    })
            else:
                return Response({
                        'status': False,
                        'message': 'Please Input validate data!',  
                    })
        except:
            return Response({
                'status': False,
                'message': 'Something Went Wrong.',   
            })

class ChangePasswordSendMobileOTP(APIView):
    def post(self, request):
        data = request.data
        serializer = MobileLoginSerializer(data = data)
        if serializer.is_valid():
            try:
                mobile = data['mobile']
                user_mobile = mobile[6:10]
                user = User.objects.get(mobile = mobile, is_superuser=False)
                if user:
                    if user.is_verified:
                        # sendOTP(user)
                        return Response({'status': True, 'message': f'OTP has been send on last  ****{user_mobile}.'})
                    else:
                        return Response({'status': False, 'message': 'You have not verifed email address yet.'})
                else:
                    return Response({'status': False, 'message': 'Mobile Number Not Found.'})
            except:
                return Response({'status': False, 'message': 'This Mobile Number does not Exists.'})
        else:
            return Response({'status': False, 'message': 'Please input Valid Mobile Number.'})

class ChangePasswordSendMail(APIView):
    def post(self, request):
        data = request.data
        serializer = UserChangePasswordMailSerializer(data = data)
        if serializer.is_valid():
            try:
                email = data['email']
                filter_email = email.lower()
                user = User.objects.get(email = filter_email, is_superuser=False)
                if user:
                    if user.is_verified:
                        sendOTP(user)
                        return Response({'status': True, 'message': 'OTP has been send on email address. Please check Email Address.'})
                    else:
                        return Response({'status': False, 'message': 'You have not verifed email address yet.'})
                else:
                    return Response({'status': False, 'message': 'Email Not Found.'})
            except:
                return Response({'status': False, 'message': 'This email address does not Exists.'})
        else:
            return Response({'status': False, 'message': 'Please input Valid mail Address.'})

class ChangePasswordVerifyOTP(APIView):
    def post(self, request):
        data = request.data
        serializer = UserChangePasswordVerifyOTPSerializer(data = data)
        if serializer.is_valid():
            try:
                email = data['email']
                filter_email = email.lower()
                user = User.objects.get(email = filter_email, is_superuser=False)
                if user:
                    if user.otp != serializer.data['otp']:
                        return Response({'status': False, 'message': 'OTP not matched.'})
                    else:
                        return Response({'status': True, 'message': 'OTP successfully matched'})
                else:
                    return Response({'status': False, 'message': 'This email address does not Exists.'})
            except:
                return Response({'status': False, 'message': 'This email address does not Exists!'})
        else:
            return Response({'status': False, 'message': 'Please Input validate data...'})

class ChangePasswordVerifyMobileOTP(APIView):
    def post(self, request):
        data = request.data
        serializer = MobileVerifyOTPSerializer(data = data)
        if serializer.is_valid():
            try:
                mobile = data['mobile']
                otp = data['otp']
                user = User.objects.get(mobile = mobile, is_superuser=False)
                if user:
                    if '1234' != otp:
                        return Response({'status': False, 'message': 'OTP not matched.'})
                    else:
                        return Response({'status': True, 'message': 'OTP successfully matched'})
                else:
                    return Response({'status': False, 'message': 'This mobile number does not Exists.'})
            except:
                return Response({'status': False, 'message': 'This mobile number does not Exists!'})
        else:
            return Response({'status': False, 'message': 'Please Input validate data...'})

class ChangePassword(APIView):
    def put(self, request):
        data = request.data
        serializer = UserChangePasswordSerializer(data = data)
        try:
            email = data['email']
            filter_email = email.lower()
            user = User.objects.get(email = filter_email)
        except:
            user = None
        if serializer.is_valid():
            if user:
                if serializer.data['new_password'] == serializer.data['confirm_password']:
                    user.set_password(serializer.data['confirm_password'])
                    user.save()
                    return Response({'status': True, 'message': 'Your Password Successfully set.'})
                else:
                    return Response({'status': False, 'message': 'Password does not matched!'})
            else:
                return Response({'status': False, 'message': 'Email Address not found.'})
        else:
            return Response({'status': False, 'message': 'Please Input validate data...'})

class ChangePasswordMobile(APIView):
    def put(self, request):
        data = request.data
        serializer = UserChangePasswordMobileSerializer(data = data)
        try:
            mobile = data['mobile']
            user = User.objects.get(mobile = mobile)
        except:
            user = None
        if serializer.is_valid():
            if user:
                if serializer.data['new_password'] == serializer.data['confirm_password']:
                    user.set_password(serializer.data['confirm_password'])
                    user.save()
                    return Response({'status': True, 'message': 'Your Password Successfully set.'})
                else:
                    return Response({'status': False, 'message': 'Password does not matched!'})
            else:
                return Response({'status': False, 'message': 'Mobile Number not found.'})
        else:
            return Response({'status': False, 'message': 'Please Input validate data...'})

class UserDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER':
                user_details = User.objects.get(email=user_data)
                serializer = UserDetailsSerializer(user_details, context={'request':request})  
                return Response({
                    'status': True, 
                    'payload': serializer.data ,
                    'message': "All products are successfully fetched."
                    })
            else:
                return Response({
                        'status': False, 
                        'message': "You have not permission to see user profile. Please contact to Admin."
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated|ReadOnly]
    def patch(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        data = request.data
        try:
            user_profile = User.objects.get(email=user_data)
        except:
            user_profile = None
        if user_profile:
            serializer = VendorViewSerializer(user_profile, data = data, partial=True)
            if not serializer.is_valid():
                return Response({
                    'success': False, 
                    'payload': serializer.errors, 
                    'message': 'Something went wrong'
                    })
            serializer.save()
            return Response({
                'success': True, 
                'payload': serializer.data, 
                'message': 'You have successfully updated profile.'
                })
        else:
            return Response({
                    'success': False, 
                    'payload': serializer.errors, 
                    'message': 'Something went wrong'
                    })

class AppSliderView(APIView):
    def get(self, request):
        try: 
            slider = AppSlider.objects.all()
            slider_serializer = AppSliderSerializer(slider, many=True)
            return Response({
                'status': True, 
                'payload': slider_serializer.data,
                'message': "All slides are successfully fetched."
                })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class ResetPassword(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            serializer = UserResetPasswordSerializer(data = data)
            try:
                user = User.objects.get(email = user_data)
            except:
                user = None
            if serializer.is_valid():
                if user:
                    if not user.check_password(serializer.data['old_password']):
                        return Response({'status': False, 'message': 'Old Password does not matched!'})
                    user.set_password(serializer.data['new_password'])
                    user.save()
                    return Response({'status': True, 'message': 'Your Password Successfully set.'})
                else:
                    return Response({'status': False, 'message': 'Email Address not found.'})
            else:
                return Response({'status': False, 'message': 'Please Input validate data...'})
        except:
            return Response({'status': False, 'message': 'Email Address not found.'})

class UserProfilePic(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        data = request.data
        try:
            user_profile = User.objects.get(email=user_data)
        except:
            user_profile = None
        if user_profile:
            serializer = UsreProfilePicSerializer(user_profile, data = data, partial=True)
            if not serializer.is_valid():
                return Response({
                    'success': False, 
                    'payload': serializer.errors, 
                    'message': 'Something went wrong'
                    })
            serializer.save()
            user = User.objects.get(email = user_data)
            user_view = UserViewSerializer(user)
            vendor_view = VendorViewSerializer(user)
            if user_data.user_type == 'USER':
                return Response({
                        'status': True,
                        'payload': user_view.data,
                        'message': "You have successfully updated profile."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                        'status': True,
                        'payload': vendor_view.data,
                        'message': "You have successfully updated profile."
                    })
        else:
            return Response({
                    'success': False, 
                    'payload': serializer.errors, 
                    'message': 'Something went wrong'
                    })

    def patch(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        data = request.data
        try:
            user_profile = User.objects.get(email=user_data)
        except:
            user_profile = None
        if user_profile:
            serializer = UsreProfilePicSerializer(user_profile, data = data, partial=True)
            if not serializer.is_valid():
                return Response({
                    'success': False, 
                    'payload': serializer.errors, 
                    'message': 'Something went wrong'
                    })
            serializer.save()
            user = User.objects.get(email = user_data)
            user_view = UserViewSerializer(user)
            vendor_view = VendorViewSerializer(user)
            if user_data.user_type == 'USER':
                return Response({
                        'status': True,
                        'payload': user_view.data,
                        'message': "You have successfully updated profile."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                        'status': True,
                        'payload': vendor_view.data,
                        'message': "You have successfully updated profile."
                    })
        else:
            return Response({
                    'success': False, 
                    'payload': serializer.errors, 
                    'message': 'Something went wrong'
                    })

class ContactUsView(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = ContactUsSerializer(data = data, partial=True)
            if not serializer.is_valid():
                return Response({
                    'success': False, 
                    'payload': serializer.errors, 
                    'message': 'Something went wrong'
                    })
            contact , created = ContactUs.objects.get_or_create(name = data['name'], email=data['email'], subject=data['subject'], message=data['message'], status='PENDING')
            contact.save()
            return Response({
                    'status': True,
                    'message': "We have Received your Request. We response soon."
                })
        except:
            return Response({
                    'success': False, 
                    'message': 'Something went wrong'
                    })

class AboutUsView(APIView):
    def get(self, request):
        try: 
            about = AboutUsApp.objects.all()
            about_serializer = AboutUsSerializer(about, many=True)
            return Response({
                'status': True, 
                'payload': about_serializer.data ,
                'message': "About Us page are successfully fetched."
                })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class TermsConditionView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            if user_data:
                queryset = Product.objects.get(id=id)
                serializer = ProductSerializer(queryset, context={'request':request})  
                return Response({
                    'status': True, 
                    'payload': serializer.data ,
                    'message': "All products are successfully fetched."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "No product found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class PrivacyPolicyView(APIView):
    def get(self, request):
        try: 
            privacy = PrivacyPolicy.objects.all()
            privacy_serializer = PrivacyPolicySerializer(privacy, many=True)
            return Response({
                'status': True, 
                'payload': privacy_serializer.data ,
                'message': "Privacy Policy page are successfully fetched."
                })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class HelpView(ListAPIView):
    queryset = Help.objects.all()
    serializer_class = HelpSerializer
    filter_backends = [SearchFilter]
    search_fields = ['question', 'answer']
    queryset = Help.objects.all()
    serializer_class = HelpSerializer
    pagination_class = HelpPagination

class NotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            try:
                notification = User.objects.get(email=user_data)
            except:
                notification = None
            if notification:
                serializer = NotificationSettingsSerializer(notification, data = data, partial=True)
                if not serializer.is_valid():
                    return Response({
                        'success': False, 
                        'payload': serializer.errors, 
                        'message': 'Something went wrong'
                        })
                serializer.save()
                user = User.objects.get(email = user_data)
                user_view = UserViewSerializer(user)
                vendor_view = VendorViewSerializer(user)
                if user_data.user_type == 'USER':
                    return Response({
                            'status': True,
                            'payload': user_view.data,
                            'message': "Notification Update Successfully."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                            'status': True,
                            'payload': vendor_view.data,
                            'message': "Notification Update Successfully."
                        })
            else:
                return Response({
                        'success': False, 
                        'payload': serializer.errors, 
                        'message': 'Something went wrong'
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Email Address not found.'
                })

class LocationView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            try:
                location = User.objects.get(email=user_data)
            except:
                location = None
            if location:
                serializer = LocationSerializer(location, data = data, partial=True)
                if not serializer.is_valid():
                    return Response({
                        'success': False, 
                        'payload': serializer.errors, 
                        'message': 'Something went wrong'
                        })
                serializer.save()
                user = User.objects.get(email = user_data)
                user_view = UserViewSerializer(user)
                vendor_view = VendorViewSerializer(user)
                if user_data.user_type == 'USER':
                    return Response({
                            'status': True,
                            'payload': user_view.data,
                            'message': "Location Update Successfully."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                            'status': True,
                            'payload': vendor_view.data,
                            'message': "Location Update Successfully."
                        })
            else:
                return Response({
                        'success': False, 
                        'payload': serializer.errors, 
                        'message': 'Something went wrong'
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong.'
                })

class LocationUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER':
                    serializer = LocationUpdateSerializer(data = data)
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        user = User.objects.get(id=user_data.id)
                        user.latitude = data['latitude']
                        user.longitude = data['longitude']
                        user.save()
                        return Response({
                            'success': True, 
                            'message': 'Your Location successfully updated.'
                            })
                if user_data.user_type == 'VENDOR':
                    serializer = LocationUpdateSerializer(data = data)
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        user = User.objects.get(id=user_data.id)
                        user.latitude = data['latitude']
                        user.longitude = data['longitude']
                        user.save()
                        return Response({
                            'success': True, 
                            'message': 'Your Location successfully updated.'
                            })
                else:
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to add location. Please contact with Admin.'
                            })
            else:
                return Response({
                        'success': False, 
                        'message': 'Unauthenticated User.'
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class TicketView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            ticket = Ticket.objects.all()
            ticket_serializer = TicketSerializer(ticket, many=True)
            return Response({
                'status': True, 
                'payload': ticket_serializer.data ,
                'message': "All Tickets page are successfully fetched."
                })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            try:
                questions = Ticket.objects.get(id = data['id'])
            except:
                # user = None
                questions = None
            if user_data:
                if questions:
                    ticket_id = random_with_N_digits(12)
                    ticket , created = RaiseTicket.objects.get_or_create(user = user_data.email, question=questions.question, ticket_num=ticket_id, desc=data['desc'], status='PENDING')
                    ticket.save()
                    return Response({
                    'success': True,
                    'ticket_id': ticket_id,
                    'message': 'Your Ticket successfully created.'
                    })

                ticket_id = random_with_N_digits(12)
                ticket , created = RaiseTicket.objects.get_or_create(user = user_data.email, question=data['question'], ticket_num=random_with_N_digits(12), desc=data['desc'], status='PENDING')
                ticket.save()
                raise_ticket = RaiseTicket.objects.get(ticket_num=ticket.ticket_num)
                serializer = RaiseTicketSerializer(raise_ticket)
                return Response({
                'success': True, 
                'ticket_id': ticket_id,
                'message': 'Your Ticket successfully created.'
                })
            else:
                return Response({
                        'success': False, 
                        'message': 'Unauthenticated User!'
                        })

class ProductView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            search_params = self.request.query_params.get('search')
            product_type_params = self.request.query_params.get('product_type')
            product_payment_params = self.request.query_params.get('payment_plan')
            product_amount_params = self.request.query_params.get('amount')
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            if user_data.user_type == 'USER':
                if search_params:
                    queryset = Product.objects.all().filter(Q(name__contains=search_params)).order_by('-id')
                    result_obj = paginat.paginate_queryset(queryset, request)
                    serializer = ProductSerializer(result_obj, many=True, context={'request':request})  
                    pagination_data = serializer.data
                    page = paginat.get_paginated_response(pagination_data)
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All products are successfully fetched."
                        })
                if product_type_params and not product_payment_params:
                    products = Product.objects.filter(category=product_type_params).order_by('-id')
                    result_obj = paginat.paginate_queryset(products, request)
                    serializer = ProductSerializer(result_obj, many=True, context={'request':request})  
                    pagination_data = serializer.data
                    page = paginat.get_paginated_response(pagination_data)
                    if user_data.user_type == 'USER':
                        return Response({
                            'status': True, 
                            'payload': page.data ,
                            'message': "All Goals are successfully fetched."
                            })
                    if user_data.user_type == 'VENDOR':
                        return Response({
                            'status': False, 
                            'message': "You have no permission to see Goals. Please contact with Admin."
                            })
                if product_payment_params and not product_type_params:
                    products = Product.objects.filter(category=product_type_params).order_by('-id')
                    result_obj = paginat.paginate_queryset(products, request)
                    serializer = ProductSerializer(result_obj, many=True, context={'request':request})  
                    pagination_data = serializer.data
                    page = paginat.get_paginated_response(pagination_data)
                    if user_data.user_type == 'USER':
                        return Response({
                            'status': True, 
                            'payload': page.data ,
                            'message': "All Goals are successfully fetched."
                            })
                    if user_data.user_type == 'VENDOR':
                        return Response({
                            'status': False, 
                            'message': "You have no permission to see Goals. Please contact with Admin."
                            })
                if product_amount_params == 'high':
                    queryset = Product.objects.all().order_by('-price')
                    result_obj = paginat.paginate_queryset(queryset, request)
                    serializer = ProductSerializer(result_obj, many=True, context={'request':request})  
                    pagination_data = serializer.data
                    page = paginat.get_paginated_response(pagination_data)
                    if user_data.user_type == 'USER':
                        return Response({
                            'status': True, 
                            'payload': page.data ,
                            'message': "All high price products are successfully fetched."
                            })
                    if user_data.user_type == 'VENDOR':
                        return Response({
                            'status': False, 
                            'message': "You have no permission to see Goals. Please contact with Admin."
                            })
                if product_amount_params == 'low':
                    queryset = Product.objects.all().order_by('price')
                    result_obj = paginat.paginate_queryset(queryset, request)
                    serializer = ProductSerializer(result_obj, many=True, context={'request':request})  
                    pagination_data = serializer.data
                    page = paginat.get_paginated_response(pagination_data)
                    if user_data.user_type == 'USER':
                        return Response({
                            'status': True, 
                            'payload': page.data ,
                            'message': "All high price products are successfully fetched."
                            })
                    if user_data.user_type == 'VENDOR':
                        return Response({
                            'status': False, 
                            'message': "You have no permission to see Goals. Please contact with Admin."
                            })
                queryset = Product.objects.all().order_by('-id')
                result_obj = paginat.paginate_queryset(queryset, request)
                serializer = ProductSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = serializer.data
                page = paginat.get_paginated_response(pagination_data)
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All products are successfully fetched."
                    })
            elif user_data.user_type == 'VENDOR':
                queryset = Product.objects.filter(user = user_data.email).order_by('-id')
                result_obj = paginat.paginate_queryset(queryset, request)
                serializer = ProductSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if queryset:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All products are successfully fetched."
                        })
                else:
                    return Response({
                        'status': True, 
                        'payload': serializer.data,
                        'message': "No product found."
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            images1 = request.FILES.getlist('image')
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                    serializer = ProductSerializer(data = data)
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if VendorSubscription.objects.filter(customer_id=user_data.customer_id).exists():
                            vendor_plan = VendorSubscription.objects.get(vendor_id=user_data.id)
                            vendor_product = Product.objects.filter(user=user_data.email).count()
                            if  vendor_product < int(vendor_plan.plan.product_count):
                                serializer.save(user = user_data.email)
                                product = Product.objects.get(id = serializer.data['id'])
                                for image in images1:
                                    images , created = ProductImages.objects.get_or_create(product = product, image=image)
                                    images.save()
                                return Response({
                                    'success': True, 
                                    'message': 'Your Product successfully created.'
                                    })
                            else:
                                return Response({
                                    'success': False, 
                                    'message': 'You have already reached your product limit. Please upgrade your plan.'
                                    })
                        else:
                            return Response({
                                'success': False, 
                                'message': 'You have no subscription plan for create Product.'
                                })
                if user_data.user_type != 'VENDOR':
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to add products. Please contact with Admin.'
                            })
                else:
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to add products. Please contact with Admin.'
                            })
            else:
                return Response({
                        'success': False, 
                        'message': 'You are not a Vendor type.'
                        })
        except:
            return Response({
                    'success': False, 
                    'message': 'Something went wrong!'
                    })

    permission_classes = [IsAuthenticated]
    def put(self, request):
        try:
            data = request.data
            images1 = request.FILES.getlist('image')
            delete_imge=request.data['delete_img']
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
    
            try:
                product = Product.objects.get(id = data['id'])
            except:
                product = None
            if user_data:
                if user_data.user_type == 'VENDOR':
                    if product:
                        serializer = ProductSerializer(instance=product, data = data, partial=True)
                        if not serializer.is_valid():
                            return Response({
                                'success': False, 
                                'payload': serializer.errors, 
                                'message': 'Something went wrong'
                                }) 
                        else:
                            serializer.save()
                            if images1:
                                for i in images1:
                                    obj=ProductImages.objects.create(image=i,product=product)
                                    obj.save()    
                            if delete_imge:
                                image_obj=ProductImages.objects.filter(product=product)
                                l=list()
                                for i in image_obj:
                                    l.append(i.id)
                                x=delete_imge.split(',')
                                for i in x:      
                                    if int(i) in l:
                                        obj=ProductImages.objects.get(id=int(i))
                                        obj.delete()
                                    else:
                                        pass
                            return Response({
                                    'success': True, 
                                    'message': 'Your Product successfully updated.'
                                    })
                    else:
                        return Response({
                                'success': False, 
                                'message': 'Product id does not exists in our database.'
                                })
                if user_data.user_type != 'VENDOR':
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to update products. Please contact with Admin.'
                            })
                else:
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to update products. Please contact with Admin.'
                            })
            else:
                return Response({
                        'success': False, 
                        'message': 'You are not a Vendor type.'
                        })
        except:
            return Response({
                    'success': False, 
                    'message': 'Something went wrong!'
                    })

    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            try:
                product = Product.objects.get(id = id)
            except:
                product = None
            if user_data:
                if user_data.user_type == 'VENDOR':
                    if product:
                        if not UserGoal.objects.filter(product_id=product.id).exists():
                            product.delete()
                            return Response({
                                'success': True, 
                                'message': 'Product Successfully Deleted.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': "Product can't be deleted. Customers are bind this product."
                                })
                    else:
                        return Response({
                                'success': False, 
                                'message': 'Product id not found in our database.'
                                })
                else:
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to Delete products. Please contact with Admin.'
                            })
            else:
                return Response({
                        'success': False, 
                        'message': 'You have no permission to Delete products. Please contact with Admin.'
                        })
        except:
            return Response({
                    'success': False, 
                    'message': 'Something went wrong!'
                    })
 
class MembersViewListing(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            user_type_params = self.request.query_params.get('user_type')
            user_rating_params = self.request.query_params.get('rating')
            search_params = self.request.query_params.get('search')
            paginat=PageNumberPagination()
            paginat.page_size=10
            paginat.page_size_query_param='page_size'
            if user_type_params:
                queryset = User.objects.filter(user_type='USER', user_category=user_type_params).exclude(id=user_data.id)
                result_obj = paginat.paginate_queryset(queryset, request)
                serializer = MembersSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = serializer.data
                page = paginat.get_paginated_response(pagination_data)
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Members are successfully fetched."
                    })
            if user_rating_params == 'high':
                queryset = User.objects.filter(user_type='USER', is_active=True, is_verified=True).exclude(id=user_data.id).order_by('-avg_rating')
                result_obj = paginat.paginate_queryset(queryset, request)
                serializer = MembersSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = serializer.data
                page = paginat.get_paginated_response(pagination_data)
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Members are successfully fetched."
                    })
            if user_rating_params == 'low':
                queryset = User.objects.filter(user_type='USER', is_active=True, is_verified=True).exclude(id=user_data.id).order_by('avg_rating')
                result_obj = paginat.paginate_queryset(queryset, request)
                serializer = MembersSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = serializer.data
                page = paginat.get_paginated_response(pagination_data)
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Members are successfully fetched."
                    })
            if search_params:
                queryset = User.objects.filter(user_type='USER').exclude(id=user_data.id).filter(Q(first_name__contains=search_params) | Q(last_name__contains=search_params))
                result_obj = paginat.paginate_queryset(queryset, request)
                serializer = MembersSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = serializer.data
                page = paginat.get_paginated_response(pagination_data)
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Members are successfully fetched."
                    })
            queryset = User.objects.filter(user_type='USER').exclude(id=user_data.id).order_by('-id')
            result_obj = paginat.paginate_queryset(queryset, request)
            serializer = MembersSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = serializer.data
            page = paginat.get_paginated_response(pagination_data)
            return Response({
                'status': True, 
                'payload': page.data ,
                'message': "All Members are successfully fetched."
                })
        except:
            return Response({
                'status': False, 
                'message': "Something went wrong."
                })

class MembersListing(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        paginat=PageNumberPagination()
        paginat.page_size=10
        paginat.page_size_query_param='page_size'
        queryset = GoalMember.objects.all()
        result_obj = paginat.paginate_queryset(queryset, request)
        serializer = MemberSerializer(result_obj, many=True, context={'request':request})  
        pagination_data = serializer.data
        page = paginat.get_paginated_response(pagination_data)
        return Response({
            'status': True, 
            'payload': page.data ,
            'message': "All Members are successfully fetched."
            })

class GoalMemberRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            queryset = GoalMember.objects.filter(members_id=user_data.id, approve=0, request=1)
            serializer = GoalMemberRequestSerializer(queryset, many=True, context={'request':request})  
            return Response({
                'status': True, 
                'payload': serializer.data ,
                'message': "All Members are successfully fetched."
                })
        except:
            return Response({
                'status': False, 
                'message': "Something went wrong."
                })
    
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = GoalMemberRequestSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if data['approve'] == "0":
                            if GoalMember.objects.filter(goal_id = data['goal_id'], members_id = user_data.id).exists():
                                goal_request = GoalMember.objects.get(goal_id = data['goal_id'], members_id = user_data.id)
                                goal_request.delete()
                            else:
                                return Response({
                                    'success': False, 
                                    'message': 'No request found with this goal.'
                                    }) 
                            if GoalGroupAdmin.objects.filter(group_goal_id=data['goal_id'], user_id=user_data.id).exists():
                                goal_admin = GoalGroupAdmin.objects.get(group_goal_id=data['goal_id'], user_id=user_data.id)
                                goal_admin.delete()
                            else:
                                pass
                            return Response({
                                'success': True, 
                                'message': 'You have successfully decline goal request.'
                                }) 
                        if data['approve'] == "1":
                            if GoalMember.objects.filter(goal_id = data['goal_id'], members_id = user_data.id).exists():
                                goal_request_approve = GoalMember.objects.get(goal_id = data['goal_id'], members_id = user_data.id)
                                goal_request_approve.approve = 1
                                goal_request_approve.request = 0
                                goal_request_approve.save()
                            else:
                                return Response({
                                    'success': False, 
                                    'message': 'No request found with this goal.'
                                    }) 
                            if GoalGroupAdmin.objects.filter(group_goal_id=data['goal_id'], user_id=user_data.id).exists():
                                goal_admin = GoalGroupAdmin.objects.get(group_goal_id=data['goal_id'], user_id=user_data.id)
                                goal_admin.approve = 1
                                goal_admin.save()
                            else:
                                pass
                            goal_admin = GoalMember.objects.get(goal_id=data['goal_id'], members_id=user_data.id)
                            goal_details = UserGoal.objects.get(id=data['goal_id'])
                            UserNotification.objects.create(sender_id=user_data.id, receiver_id=goal_admin.owner_id, notification_type='REQUEST', notification=f'{user_data.first_name} has accepted {goal_details.goal_name} request.', notification_id=data['goal_id'])
                            return Response({
                                'success': True, 
                                'message': f'You have successfully Accepted goal request.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Something Went Wrong'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "No Goals are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalMemberListingView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal = UserGoal.objects.filter(user_id = user_data.id, goal_type = 'GROUP')
            x_list=[]
            for i in goal:
                queryset = GoalMember.objects.filter(goal_id = i, approve=1)
                x_list.append(queryset)
            x=x_list[0]
            for i in range(1,len(x_list)):
                j=x_list[i]
                x = x|x_list[i]
            serializer = GoalMemberListingSerializer(x, many=True, context={'request':request})  
            return Response({
                'status': True, 
                'payload': serializer.data ,
                'message': "All Members are successfully fetched."
                })
        except:
            return Response({
                'status': False, 
                'message': "Something went wrong."
                })
    
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = GoalMemberRequestSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if GoalMember.objects.filter(goal_id = data['goal_id']).exists() and data['approve'] == "0" and data['request'] == "0":
                            try:
                                goal_request = GoalMember.objects.get(goal_id = data['goal_id'], members_id = user_data.id)
                            except:
                                goal_request = None
                            goal = UserGoal.objects.get(id = data['goal_id'])
                            goal_request.delete()
                            return Response({
                                'success': True, 
                                'message': f'You have successfully decline {goal.goal_name} goal request.'
                                }) 
                        if data['approve'] == "1":
                            goal_request_approve = GoalMember.objects.get(goal_id = data['goal_id'], members_id = user_data.id)
                            goal_request_approve.approve = 1
                            goal_request_approve.save()
                            return Response({
                                'success': True, 
                                'message': f'You have successfully Accepted goal request.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Something Went Wrong'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "No Goals are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class PaymentPlanView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            plans = PaymentPlan.objects.all()
            plans_serializer = PaymentSerializer(plans, many=True)
            return Response({
                'status': True, 
                'payload': plans_serializer.data ,
                'message': "All Plans are successfully fetched."
                })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class ProductDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            if user_data:
                queryset = Product.objects.get(id=id)
                serializer = ProductSerializer(queryset, context={'request':request})  
                return Response({
                    'status': True, 
                    'payload': serializer.data ,
                    'message': "All products are successfully fetched."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "No product found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalView(APIView):
    permission_classes = [IsAuthenticated]  
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_type_params = self.request.query_params.get('goal_type')
            goal_payment_params = self.request.query_params.get('payment_plan')
            goal_amount_params = self.request.query_params.get('amount')
            search_params = self.request.query_params.get('search')
            popular_params = self.request.query_params.get('popular')
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            if popular_params:
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC").order_by('-total_members')
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id).order_by('-total_members')
                goals = public_goals.order_by('-created') | private_goals.order_by('-created')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
            if search_params:
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC").filter(Q(goal_name__contains=search_params))
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id).filter(Q(goal_name__contains=search_params))
                goals = public_goals.order_by('-created') | private_goals.order_by('-created')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
            if goal_type_params and not goal_payment_params:
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC", goal_as=goal_type_params)
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id, goal_as=goal_type_params)
                goals = public_goals.order_by('-created') | private_goals.order_by('-created')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
            if goal_payment_params and not goal_type_params:
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC", payment_plan_id=goal_payment_params)
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id, payment_plan_id=goal_payment_params)
                goals = public_goals.order_by('-created') | private_goals.order_by('-created')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
            if goal_type_params and goal_payment_params:
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC", goal_as=goal_type_params, payment_plan_id=goal_payment_params)
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id,  goal_as=goal_type_params,payment_plan_id=goal_payment_params)
                goals = public_goals.order_by('-created') | private_goals.order_by('-created')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
            if goal_amount_params == 'high':
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC")
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id)
                goals = public_goals.order_by('-goal_amount') | private_goals.order_by('-goal_amount')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
            if goal_amount_params == 'low':
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC")
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id)
                goals = public_goals.order_by('goal_amount') | private_goals.order_by('goal_amount')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
            else:
                public_goals = UserGoal.objects.filter(goal_priority="PUBLIC")
                private_goals = UserGoal.objects.filter(goal_priority="PRIVATE", user_id=user_data.id)
                goals = public_goals.order_by('-created') | private_goals.order_by('-created')
                result_obj = paginat.paginate_queryset(goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        members = data['members[]']
        sub_goals = data['sub_goals[]']
        questions = data['question[]']
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        if user_data:
            if user_data.user_type == 'USER' and user_data.is_active == True:
                serializer = GoalSerializer(data = data)
                if not serializer.is_valid():
                    return Response({
                        'success': False, 
                        'payload': serializer.errors, 
                        'message': 'Something went wrong'
                        }) 
                else:
                    payment = PaymentPlan.objects.get(id = data['payment_plan'])
                    try:
                        product = Product.objects.get(id = data['product_id'])
                    except:
                        product = None
                    if data['goal_as'] == 'CUSTOM':
                        if data['goal_type'] == 'GROUP':
                                goal , created = UserGoal.objects.get_or_create(goal_name = data['goal_name'], goal_as=data['goal_as'],
                                goal_amount=data['goal_amount'], goal_priority=data['goal_priority'], goal_type=data['goal_type'],
                                payment_plan=payment, start_date=data['start_date'], user=user_data, goal_desc=data['goal_desc'])
                                goal.save()
                                if sub_goals:
                                    for sub_goal in sub_goals:
                                        name=sub_goal['sub_goal_name']
                                        date=sub_goal['sub_start_date']
                                        amount=sub_goal['sub_goal_amount']
                                        sub_goals_table , created = SubGoal.objects.get_or_create(sub_goal_id=goal.id, sub_goal_name=name,
                                        sub_start_date=date, sub_goal_amount=amount)
                                        sub_goals_table.save()
                                else:
                                    pass
                                for member in members:
                                    member_table, created = GoalMember.objects.get_or_create(members_id=member, goal_id = goal.id, request=1, owner=user_data)
                                    member_table.save()
                                    if member != user_data.id:
                                        UserNotification.objects.create(sender_id=user_data.id, receiver_id=member, notification_type='INVITATION', notification=f'{user_data.first_name} request you to join a Goal.',
                                        notification_id=goal.id)
                                popular_goal = UserGoal.objects.get(id=goal.id)
                                popular_goal.total_members = len(members)
                                popular_goal.save()
                                group_member_user = GoalMember.objects.get(goal_id=goal.id, members_id=user_data.id)
                                group_member_user.approve = 1
                                group_member_user.request = 0
                                group_member_user.save()
                                if questions:
                                    for ques in questions:
                                        question=ques['question']
                                        answer=ques['answer']
                                        questions_table, created = GroupQuestion.objects.get_or_create(questions=question, answer=answer, 
                                        group_id=goal.id)
                                        questions_table.save()
                                else:
                                    pass
                                if data['admin[]']:
                                    for i in data['admin[]']:
                                        group_admin , created = GoalGroupAdmin.objects.get_or_create(group_goal_id=goal.id, user_id=i, approve=0)
                                        group_admin.save()
                                    group_admin_user = GoalGroupAdmin.objects.get(group_goal_id=goal.id, user_id=user_data.id)
                                    group_admin_user.approve = 1
                                    group_admin_user.save()
                                group_admin , created = GoalGroupAdmin.objects.get_or_create(group_goal_id=goal.id, user_id=user_data.id, approve=1)
                                group_admin.save()
                                goal_admin = GoalMember.objects.get(members_id=user_data.id, goal_id=goal.id)
                                goal_admin.approve = 1
                                goal_admin.request = 0
                                goal_admin.save()
                                group , created = ChatGroup.objects.get_or_create(group_name=goal.goal_name, goal_id=goal.id, members=members,  owner=user_data.id, room_id=random_with_N_digits(12))
                                group.save()
                                if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                    follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                    for i in follow_user:
                                        UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id, notification_type='GOAL', notification=f'{user_data.first_name} create a new Goal.',
                                        notification_id=goal.id)
                                        if i.user_email.notification_settings == 1:
                                            message_title = "New Goal"
                                            message_body =  f'{user_data.first_name} create a new Goal.'
                                            payload = {
                                                'id': goal.id,
                                                'push_type': "GOAL",
                                            }
                                            if i.user_email.fcm_token:
                                                webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                            else:
                                                pass
                                        else:
                                            pass
                                return Response({
                                    'success': True, 
                                    'message': 'Your Goal successfully created.'
                                    })
                        goal , created = UserGoal.objects.get_or_create(goal_name = data['goal_name'], goal_as=data['goal_as'],
                        goal_amount=data['goal_amount'], goal_priority=data['goal_priority'], goal_type=data['goal_type'],
                        payment_plan=payment, start_date=data['start_date'], user=user_data, goal_desc=data['goal_desc'])
                        goal.save()
                        group_admin , created = GoalGroupAdmin.objects.get_or_create(group_goal_id = goal.id, user_id=user_data.id, approve=1)
                        group_admin.save()
                        member_table, created = GoalMember.objects.get_or_create(members_id=user_data.id, goal_id = goal.id, request=1, owner=user_data)
                        member_table.save()
                        goal_admin = GoalMember.objects.get(members_id=user_data.id, goal_id = goal.id)
                        goal_admin.approve = 1
                        goal_admin.request = 0
                        goal_admin.save()
                        if sub_goals:
                            for sub_goal in sub_goals:
                                name=sub_goal['sub_goal_name']
                                date=sub_goal['sub_start_date']
                                amount=sub_goal['sub_goal_amount']
                                sub_goals_table , created = SubGoal.objects.get_or_create(sub_goal_id=goal.id, sub_goal_name=name,
                                sub_start_date=date, sub_goal_amount=amount)
                                sub_goals_table.save()
                        else:
                            pass
                        if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                            follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                            for i in follow_user:
                                UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id,
                                notification_type='GOAL', notification=f'{user_data.first_name} create a new Goal.',
                                notification_id=goal.id)
                                if i.user_email.notification_settings == 1:
                                    message_title = "New Goal"
                                    message_body =  f'{user_data.first_name} create a new Goal.'
                                    payload = {
                                        'id': goal.id,
                                        'push_type': "GOAL",
                                    }
                                    if i.user_email.fcm_token:
                                        webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                    else:
                                        pass
                                else:
                                    pass
                        return Response({
                            'success': True, 
                            'message': 'Your Goal successfully created.'
                            })
                    if data['goal_as'] == 'PRODUCT':
                        if data['goal_type'] == 'GROUP':
                            goal , created = UserGoal.objects.get_or_create(goal_name = data['goal_name'], goal_as=data['goal_as'],
                            goal_amount=data['goal_amount'], goal_priority=data['goal_priority'], goal_type=data['goal_type'],
                            payment_plan=payment, start_date=data['start_date'], user=user_data, goal_desc=data['goal_desc'], product=product)
                            goal.save()
                            if sub_goals:
                                for sub_goal in sub_goals:
                                    name=sub_goal['sub_goal_name']
                                    date=sub_goal['sub_start_date']
                                    amount=sub_goal['sub_goal_amount']
                                    sub_goals_table , created = SubGoal.objects.get_or_create(sub_goal_id=goal.id, sub_goal_name=name,
                                    sub_start_date=date, sub_goal_amount=amount)
                                    sub_goals_table.save()
                            else:
                                pass
                            for member in members:
                                member_table, created = GoalMember.objects.get_or_create(members_id=member, goal_id = goal.id, request=1, owner=user_data)
                                member_table.save()
                                if member != user_data.id:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=member, notification_type='INVITATION', notification=f'{user_data.first_name} request you to join a Goal.',
                                    notification_id=goal.id)
                            group_member_user = GoalMember.objects.get(goal_id=goal.id, members_id=user_data.id)
                            group_member_user.approve = 1
                            group_member_user.request = 0
                            group_member_user.save()
                            if questions:
                                for ques in questions:
                                    question=ques['question']
                                    answer=ques['answer']
                                    questions_table, created = GroupQuestion.objects.get_or_create(questions=question, answer=answer, 
                                    group_id=goal.id)
                                    questions_table.save()
                            else:
                                pass
                            if data['admin[]']:
                                for i in data['admin[]']:
                                    group_admin , created = GoalGroupAdmin.objects.get_or_create(group_goal_id=goal.id, user_id=i, approve=0)
                                    group_admin.save()
                                group_admin_user = GoalGroupAdmin.objects.get(group_goal_id=goal.id, user_id=user_data.id)
                                group_admin_user.approve = 1
                                group_admin_user.save()
                            group_admin , created = GoalGroupAdmin.objects.get_or_create(group_goal_id = goal.id, user_id=user_data.id, approve=1)
                            group_admin.save()
                            goal_admin = GoalMember.objects.get(members_id=user_data.id, goal_id = goal.id)
                            goal_admin.approve = 1
                            goal_admin.request = 0
                            goal_admin.save()
                            try:
                                goal_order = GoalOrder.objects.all()
                            except:
                                goal_order = None
                            if goal_order:
                                order_id_previous = GoalOrder.objects.latest('id')
                                generate_order_id = int(order_id_previous.order_id)+1
                                goal_order = GoalOrder.objects.create(goal_id=goal.id, user_id=user_data.id, product_id=product.id,
                                status='PENDING', order_id=generate_order_id)
                                goal_order.save()
                            else:
                                goal_order = GoalOrder.objects.create(goal_id=goal.id, user_id=user_data.id, product_id=product.id,
                                status='PENDING', order_id=1000)
                                goal_order.save()
                            group , created = ChatGroup.objects.get_or_create(group_name=goal.goal_name, goal_id=goal.id, members=members,  owner=user_data.id, room_id=random_with_N_digits(12))
                            group.save()
                            if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                for i in follow_user:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id,
                                    notification_type='GOAL', notification=f'{user_data.first_name} create a new Goal.',
                                    notification_id=goal.id)
                                    if i.user_email.notification_settings == 1:
                                        message_title = "New Goal"
                                        message_body =  f'{user_data.first_name} create a new Goal.'
                                        payload = {
                                            'id': goal.id,
                                            'push_type': "GOAL",
                                        }
                                        if i.user_email.fcm_token:
                                            webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                        else:
                                            pass
                                    else:
                                        pass
                            return Response({
                                'success': True, 
                                'message': 'Your Goal successfully created.'
                                })
                        goal , created = UserGoal.objects.get_or_create(goal_name = data['goal_name'], goal_as=data['goal_as'],
                        goal_amount=data['goal_amount'], goal_priority=data['goal_priority'], goal_type=data['goal_type'],
                        payment_plan=payment, start_date=data['start_date'], user=user_data, goal_desc=data['goal_desc'], product=product)
                        goal.save()
                        group_admin , created = GoalGroupAdmin.objects.get_or_create(group_goal_id = goal.id, user_id=user_data.id, approve=1)
                        group_admin.save()
                        member_table, created = GoalMember.objects.get_or_create(members_id=user_data.id, goal_id = goal.id, request=1, owner=user_data)
                        member_table.save()
                        goal_admin = GoalMember.objects.get(members_id=user_data.id, goal_id = goal.id)
                        goal_admin.approve = 1
                        goal_admin.request = 0
                        goal_admin.save()
                        if sub_goals:
                            for sub_goal in sub_goals:
                                name=sub_goal['sub_goal_name']
                                date=sub_goal['sub_start_date']
                                amount=sub_goal['sub_goal_amount']
                                sub_goals_table , created = SubGoal.objects.get_or_create(sub_goal_id=goal.id, sub_goal_name=name,
                                sub_start_date=date, sub_goal_amount=amount)
                                sub_goals_table.save()
                        else:
                            pass
                        try:
                            goal_order = GoalOrder.objects.all()
                        except:
                            goal_order = None
                        if goal_order:
                            order_id_previous = GoalOrder.objects.latest('id')
                            generate_order_id = int(order_id_previous.order_id)+1
                            goal_order = GoalOrder.objects.create(goal_id=goal.id, user_id=user_data.id, product_id=product.id,
                            status='PENDING', order_id=generate_order_id)
                            goal_order.save()
                        else:
                            goal_order = GoalOrder.objects.create(goal_id=goal.id, user_id=user_data.id, product_id=product.id,
                            status='PENDING', order_id=1000)
                            goal_order.save()
                        if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                            follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                            for i in follow_user:
                                UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id,
                                notification_type='GOAL', notification=f'{user_data.first_name} create a new Goal.',
                                notification_id=goal.id)
                                if i.user_email.notification_settings == 1:
                                    message_title = "New Goal"
                                    message_body =  f'{user_data.first_name} create a new Goal.'
                                    payload = {
                                        'id': goal.id,
                                        'push_type': "GOAL",
                                    }
                                    if i.user_email.fcm_token:
                                        webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                    else:
                                        pass
                                else:
                                    pass
                        return Response({
                            'success': True, 
                            'message': 'Your Goal successfully created.'
                            })
                    else:
                        return Response({
                            'success': False, 
                            'message': 'Goal type not found.'
                            })
            if user_data.user_type != 'USER':
                return Response({
                    'success': False, 
                    'message': 'You have no permission to create Goals. Please contact with Admin.'
                    })
            else:
                return Response({
                    'success': False, 
                    'message': 'You have no permission to create Goals. Please contact with Admin.'
                    })
        else:
            return Response({
                'success': False, 
                'message': 'You are not a user type.'
                })

    permission_classes = [IsAuthenticated]
    def put(self, request):
        data = request.data
        members = data['members[]']
        sub_goals = data['sub_goals[]']
        members_delete = data['members_delete[]']
        admin = data['admin[]']
        admin_delete = data['admin_delete[]']
        sub_goals_delete = data['sub_goals_delete[]']
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        if user_data:
            if user_data.user_type == 'USER' and user_data.is_active == True:
                serializer = GoalSerializer(data = data)
                if not serializer.is_valid():
                    return Response({
                        'success': False, 
                        'payload': serializer.errors, 
                        'message': 'Something went wrong'
                        }) 
                else:
                    if data['goal_as'] == 'CUSTOM':
                        if data['goal_type'] == 'GROUP':
                                goal = UserGoal.objects.get(id=data['goal_id'])
                                goal.goal_name = data['goal_name'] 
                                goal.goal_desc = data['goal_desc'] 
                                goal.group_name = data['group_name'] 
                                goal.group_desc = data['group_desc'] 
                                goal.goal_priority = data['goal_priority'] 
                                goal.save()
                                if sub_goals:
                                    sub_goals_table = SubGoal.objects.filter(sub_goal_id=data['goal_id'])
                                    for sub_goal in sub_goals:
                                        sub_goals_table = SubGoal.objects.create(sub_goal_id=data['goal_id'], sub_goal_name = sub_goal['sub_goal_name'],
                                        sub_goal_amount = sub_goal['sub_goal_amount'], sub_start_date = sub_goal['sub_start_date'])
                                        sub_goals_table.save()
                                if sub_goals_delete:
                                    sub_goal_delete = SubGoal.objects.filter(sub_goal_id = data['goal_id'])
                                    l = []
                                    for i in sub_goal_delete:
                                        l.append(i.id)
                                        x = sub_goals_delete
                                    for i in x:      
                                        if int(i) in l:
                                            delete_sub_goal = SubGoal.objects.get(id=int(i))
                                            delete_sub_goal.delete()
                                else:
                                    pass
                                if members:
                                    for member in members:
                                        goals_memebers = GoalMember.objects.create(goal_id=data['goal_id'], members_id = member, request=1)
                                        goals_memebers.save()
                                if members_delete:
                                    goal_member_delete = GoalMember.objects.filter(goal_id = data['goal_id'])
                                    l = []
                                    for i in goal_member_delete:
                                        l.append(i.id)
                                        x = members_delete
                                    for i in x:   
                                        if int(i) in l:
                                            delete_goal_member = GoalMember.objects.get(id=i)
                                            delete_goal_member.delete()
                                else:
                                    pass
                                if admin:
                                    for ad in admin:
                                        goals_admin = GoalGroupAdmin.objects.create(group_goal_id=data['goal_id'], user_id = ad, approve=1)
                                        goals_admin.save()
                                if admin_delete:
                                    goal_admin_delete = GoalGroupAdmin.objects.filter(group_goal_id = data['goal_id'])
                                    l = []
                                    for i in goal_admin_delete:
                                        l.append(i.id)
                                        x = admin_delete
                                    for i in x:   
                                        if int(i) in l:
                                            delete_goal_admin = GoalGroupAdmin.objects.get(id=i)
                                            delete_goal_admin.delete()
                                else:
                                    pass
                                return Response({
                                    'success': True, 
                                    'message': 'Your Goal successfully Updated.'
                                    })
                        goal = UserGoal.objects.get(id=data['goal_id'])
                        goal.goal_name = data['goal_name'] 
                        goal.goal_desc = data['goal_desc'] 
                        goal.goal_priority = data['goal_priority'] 
                        goal.save()
                        if sub_goals:
                            sub_goals_table = SubGoal.objects.filter(sub_goal_id=data['goal_id'])
                            for sub_goal in sub_goals:
                                sub_goals_table = SubGoal.objects.create(sub_goal_id=data['goal_id'], sub_goal_name = sub_goal['sub_goal_name'],
                                sub_goal_amount = sub_goal['sub_goal_amount'], sub_start_date = sub_goal['sub_goal_amount'])
                                sub_goals_table.save()
                        if sub_goals_delete:
                            sub_goal_delete = SubGoal.objects.filter(sub_goal_id = data['goal_id'])
                            l = []
                            for i in sub_goal_delete:
                                l.append(i.id)
                                x = sub_goals_delete
                            for i in x:      
                                if int(i) in l:
                                    delete_sub_goal = SubGoal.objects.get(id=int(i))
                                    delete_sub_goal.delete()
                        else:
                            pass
                        if members:
                        #     goals_memebers = GoalMember.objects.get(goal_id = data['goal_id'])
                            for member in members:
                                goals_memebers = GoalMember.objects.create(goal_id=data['goal_id'], members_id = member)
                                goals_memebers.save()
                        if members_delete:
                            goal_member_delete = GoalMember.objects.filter(goal_id = data['goal_id'])
                            l = []
                            for i in goal_member_delete:
                                l.append(i.id)
                                x = members_delete
                            for i in x:   
                                if int(i) in l:
                                    delete_goal_member = GoalMember.objects.get(id=i)
                                    delete_goal_member.delete()
                        else:
                            pass
                        if admin:
                            for ad in admin:
                                goals_admin = GoalGroupAdmin.objects.create(group_goal_id=data['goal_id'], user_id = ad, approve=1)
                                goals_admin.save()
                        if admin_delete:
                            goal_admin_delete = GoalGroupAdmin.objects.filter(group_goal_id = data['goal_id'])
                            l = []
                            for i in goal_admin_delete:
                                l.append(i.id)
                                x = admin_delete
                            for i in x:   
                                if int(i) in l:
                                    delete_goal_admin = GoalGroupAdmin.objects.get(id=i)
                                    delete_goal_admin.delete()
                        else:
                            pass
                        return Response({
                            'success': True, 
                            'message': 'Your Goal successfully updated.'
                            })
                    if data['goal_as'] == 'PRODUCT':
                        if data['goal_type'] == 'GROUP':
                            goal = UserGoal.objects.get(id = data['goal_id'])
                            goal.goal_name = data['goal_name']
                            goal.goal_desc = data['goal_desc']
                            goal.group_name = data['group_name'] 
                            goal.group_desc = data['group_desc'] 
                            goal.goal_priority = data['goal_priority'] 
                            goal.save()
                            if sub_goals:
                                sub_goals_table = SubGoal.objects.filter(sub_goal_id=data['goal_id'])
                                for sub_goal in sub_goals:
                                    sub_goals_table = SubGoal.objects.create(sub_goal_id=data['goal_id'], sub_goal_name = sub_goal['sub_goal_name'],
                                    sub_goal_amount = sub_goal['sub_goal_amount'], sub_start_date = sub_goal['sub_goal_amount'])
                                    sub_goals_table.save()
                            if sub_goals_delete:
                                sub_goal_delete = SubGoal.objects.filter(sub_goal_id = data['goal_id'])
                                l = []
                                for i in sub_goal_delete:
                                    l.append(i.id)
                                    x = sub_goals_delete
                                for i in x:      
                                    if int(i) in l:
                                        delete_sub_goal = SubGoal.objects.get(id=int(i))
                                        delete_sub_goal.delete()
                            else:
                                pass
                            if members:
                                for member in members:
                                    goals_memebers = GoalMember.objects.create(goal_id=data['goal_id'], members_id = member)
                                    goals_memebers.save()
                            if members_delete:
                                goal_member_delete = GoalMember.objects.filter(goal_id = data['goal_id'])
                                l = []
                                for i in goal_member_delete:
                                    l.append(i.id)
                                    x = members_delete
                                for i in x:   
                                    if int(i) in l:
                                        delete_goal_member = GoalMember.objects.get(id=i)
                                        delete_goal_member.delete()
                            else:
                                pass
                            if admin:
                                for ad in admin:
                                    goals_admin = GoalGroupAdmin.objects.create(group_goal_id=data['goal_id'], user_id = ad, approve=1)
                                    goals_admin.save()
                            if admin_delete:
                                goal_admin_delete = GoalGroupAdmin.objects.filter(group_goal_id = data['goal_id'])
                                l = []
                                for i in goal_admin_delete:
                                    l.append(i.id)
                                    x = admin_delete
                                for i in x:   
                                    if int(i) in l:
                                        delete_goal_admin = GoalGroupAdmin.objects.get(id=i)
                                        delete_goal_admin.delete()
                            else:
                                pass
                            return Response({
                                    'success': True, 
                                    'message': 'Your Goal successfully updated.'
                                    })
                        goal = UserGoal.objects.get(id = data['goal_id'])
                        goal = UserGoal.objects.get(id = data['goal_id'])
                        goal.goal_name = data['goal_name']
                        goal.goal_desc = data['goal_desc']
                        goal.goal_priority = data['goal_priority'] 
                        goal.save()
                        if sub_goals:
                            sub_goals_table = SubGoal.objects.filter(sub_goal_id=data['goal_id'])
                            for sub_goal in sub_goals:
                                sub_goals_table = SubGoal.objects.create(sub_goal_id=data['goal_id'], sub_goal_name = sub_goal['sub_goal_name'],
                                sub_goal_amount = sub_goal['sub_goal_amount'], sub_start_date = sub_goal['sub_goal_amount'])
                                sub_goals_table.save()
                        if sub_goals_delete:
                            sub_goal_delete = SubGoal.objects.filter(sub_goal_id = data['goal_id'])
                            l = []
                            for i in sub_goal_delete:
                                l.append(i.id)
                                x = sub_goals_delete
                            for i in x:      
                                if int(i) in l:
                                    delete_sub_goal = SubGoal.objects.get(id=int(i))
                                    delete_sub_goal.delete()
                        else:
                            pass
                        if members:
                            # goals_memebers = GoalMember.objects.get(goal_id = data['goal_id'])
                            for member in members:
                                goals_memebers = GoalMember.objects.create(goal_id=data['goal_id'], members_id = member)
                                goals_memebers.save()
                        if members_delete:
                            goal_member_delete = GoalMember.objects.filter(goal_id = data['goal_id'])
                            l = []
                            for i in goal_member_delete:
                                l.append(i.id)
                                x = members_delete
                            for i in x:   
                                if int(i) in l:
                                    delete_goal_member = GoalMember.objects.get(id=i)
                                    delete_goal_member.delete()
                        else:
                            pass
                        if admin:
                            for ad in admin:
                                goals_admin = GoalGroupAdmin.objects.create(group_goal_id=data['goal_id'], user_id = ad, approve=1)
                                goals_admin.save()
                        if admin_delete:
                            goal_admin_delete = GoalGroupAdmin.objects.filter(group_goal_id = data['goal_id'])
                            l = []
                            for i in goal_admin_delete:
                                l.append(i.id)
                                x = admin_delete
                            for i in x:   
                                if int(i) in l:
                                    delete_goal_admin = GoalGroupAdmin.objects.get(id=i)
                                    delete_goal_admin.delete()
                        else:
                            pass
                        return Response({
                                    'success': True, 
                                    'message': 'Your Goal successfully updated.'
                                    })
                    else:
                        return Response({
                            'success': False, 
                            'message': 'Please '
                            })
            if user_data.user_type != 'USER':
                return Response({
                        'success': False, 
                        'message': 'You have no permission to create Goals. Please contact with Admin.'
                        })
            else:
                return Response({
                        'success': False, 
                        'message': 'You have no permission to create Goals. Please contact with Admin.'
                        })
        else:
            return Response({
                    'success': False, 
                    'message': 'You are not a user type.'
                    })

    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            try:
                goal = UserGoal.objects.filter(id = id, user_id = data1['user_id'])
            except:
                goal = None
            if user_data:
                if user_data.user_type == 'USER':
                    if goal:
                        goal.delete()
                        # if not serializer.is_valid():
                        return Response({
                            'success': True, 
                            'message': 'Goal Successfully Deleted.'
                            }) 
                    else:
                        return Response({
                                'success': False, 
                                'message': 'You have no Goal with this id. Please input validate id.'
                                })
                else:
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to delete Goal. Please contact with Admin.'
                            })
            else:
                return Response({
                        'success': False, 
                        'message': 'You have no permission to delete Goal. Please contact with Admin.'
                        })
        except:
            return Response({
                    'success': False, 
                    'message': 'Something went wrong!'
                    })

class PartipicentGoalView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            goal_member = GoalMember.objects.filter(members_id=user_data.id, approve=True).exclude(owner_id = user_data.id)
            result_obj = paginat.paginate_queryset(goal_member, request)
            goals_serializer = GoalMemberTestingSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goals_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Goals are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalMemberDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            goals = GoalMember.objects.filter(goal_id = id)
            goals_serializer = GoalMemberTestingSerializer(goals, many=True, context={'request':request})  
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': goals_serializer.data ,
                    'message': "All Goals members are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goal Members. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalSubGoalsDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            goal_member = UserGoal.objects.get(user_id = user_data.id, id = id)
            goals = SubGoal.objects.filter(sub_goal_id = id)
            goals_serializer = GoalSubGoalSerializer(goals, many=True, context={'request':request})  
            if user_data.user_type == 'USER':
                if goal_member:
                    return Response({
                        'status': True, 
                        'payload': goals_serializer.data ,
                        'message': "All Sub Goals are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "No sub-goal found with current user."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Sub Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GroupGoalIndividualView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            try:
                private_goals = UserGoal.objects.filter(user_id=user_data.id, goal_type='INDIVIDUAL').order_by('-id')
            except:
                private_goals = None
            if private_goals:
                result_obj = paginat.paginate_queryset(private_goals, request)
                goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                if user_data.user_type == 'USER':
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Goals are successfully fetched."
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals. Please contact with Admin."
                        })
                else:
                    return Response({
                        'success': False, 
                        'message': 'You have no permission to see Goals. Please contact with Admin.'
                        })
            else:
                return Response({
                'success': False, 
                'message': 'No Goal Found.'
                })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GroupGoalUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            group_goal = UserGoal.objects.filter(user_id=user_data.id, goal_type='GROUP').order_by('-id')
            result_obj = paginat.paginate_queryset(group_goal, request)
            goals_serializer = GoalTestingViewSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goals_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': page.data,
                    'message': "All Goals are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goals. Please contact with Admin."
                    })
            else:
                return Response({
                    'success': False, 
                    'message': 'You have no permission to see Goals. Please contact with Admin.'
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class HomeSliderView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                queryset = HomeSlider.objects.all()
                serializer = HomeSliderSerializer(queryset, many=True, context={'request':request})  
                return Response({
                    'status': True, 
                    'payload': serializer.data ,
                    'message': "All Slider are successfully fetched."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "No product found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            images = request.FILES.getlist('images')
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                for i in images:
                    images , created = HomeSlider.objects.get_or_create(images=i)
                    images.save()
                return Response({
                        'success': True, 
                        'message': 'Images successfully uploaded.'
                        })
            else:
                return Response({
                        'success': False, 
                        'message': 'You are not Authenticate User!'
                        })
        except:
            return Response({
                    'success': False, 
                    'message': 'Something went wrong!'
                    })

class HomeAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                queryset = HomeAPI.objects.all()
                serializer = HomeAPISerializer(queryset, many=True, context={'request':request})  
                return Response({
                    'status': True, 
                    'payload': serializer.data ,
                    'message': "All HomeAPI are successfully fetched."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "You are not Authenticate User!"
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            try:
                user = UserGoal.objects.get(id=id)
            except:
                user = None
            try:
                sub_goal = SubGoal.objects.get(sub_goal_id=id)
            except:
                sub_goal = None
            if user_data.user_type == 'USER':
                if user:
                    queryset = UserGoal.objects.get(id=id)
                    queryset1 = SubGoal.objects.filter(sub_goal_id=id)
                    serializer = GoalTestingViewSerializer(queryset, context={'request':request})  
                    goals_serializer = GoalSubGoalSerializer(queryset1, many=True, context={'request':request})   
                    return Response({
                        'status': True, 
                        'payload': serializer.data ,
                        'subgoal': goals_serializer.data ,
                        'message': "Your Goal is successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "No Goal found."
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalUserPersonalView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        user_details_id = self.request.GET['user_data_id']
        paginat=PageNumberPagination()
        paginat.page_size=5
        paginat.page_size_query_param='page_size'
        users_goals = UserGoal.objects.filter(user_id=user_details_id)
        try: 
            result_obj = paginat.paginate_queryset(users_goals, request)
            goals_serializer = UserGoalPersonalSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goals_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Goals are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.query_params.get('id')
            goal_type = self.request.query_params.get('goal_type')
            goals = UserGoal.objects.filter(user_id=id, goal_type=goal_type)
            paginat=PageNumberPagination()
            paginat.page_size=10
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(goals, request)
            goals_serializer = UserGoalSerializer(result_obj, many = True, context={'request':request})  
            pagination_data = goals_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': page.data,
                    'message': "All Goals are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class FavouriteGoalView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            fav_goal = FavouriteGoal.objects.filter(user=data1['user_id'])
            result_obj = paginat.paginate_queryset(fav_goal, request)
            goals_serializer = FavouriteGoalSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goals_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if fav_goal:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Favourite Goals are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Favourite Goals are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FavouriteGoalSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FavouriteGoal.objects.filter(goal_id = data['goal_id']).exists() and data['favourite'] == "0":
                            try:
                                fav_goal = FavouriteGoal.objects.get(goal_id = data['goal_id'])
                            except:
                                fav_goal = None
                            goal = UserGoal.objects.get(id = data['goal_id'])
                            fav_goal.delete()
                            return Response({
                                'success': True, 
                                'message': f'{goal.goal_name} has successfully remove from your Favourite list.'
                                }) 
                        if data['favourite'] == "1":
                            fav_goal_table , created = FavouriteGoal.objects.get_or_create(goal_id = data['goal_id'], user_id=user_data.id, favourite=data['favourite'])
                            fav_goal_table.save()
                            goal = UserGoal.objects.get(id = data['goal_id'])
                            return Response({
                                'success': True, 
                                'payload': serializer.data, 
                                'message': f'{goal.goal_name} has successfully save in your Favourite list.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Something Went Wrong'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Favourite Goals are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class FavouriteUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            fav_user = FavouriteUser.objects.filter(user=data1['user_id'])
            result_obj = paginat.paginate_queryset(fav_user, request)
            fav_user_serializer = FavouriteUserSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = fav_user_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if fav_user:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Favourite Users are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Favourite Users are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FavouriteUserSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FavouriteUser.objects.filter(fav_user_id = data['fav_user_id']).exists() and data['favourite'] == "0":
                            try:
                                fav_user = FavouriteUser.objects.filter(fav_user_id = data['fav_user_id'])
                            except:
                                fav_user = None
                            user = User.objects.get(id = data['fav_user_id'])
                            fav_user.delete()
                            return Response({
                                'success': True, 
                                'message': f'{user.first_name} has successfully remove from your Favourite list.'
                                }) 
                        if data['favourite'] == "1":
                            fav_user_table , created = FavouriteUser.objects.get_or_create(fav_user_id = data['fav_user_id'], user_id=user_data.id, favourite=data['favourite'])
                            fav_user_table.save()
                            user = User.objects.get(id = data['fav_user_id'])
                            return Response({
                                'success': True, 
                                'payload': serializer.data, 
                                'message': f'{user.first_name} has successfully save in your Favourite list.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Something Went Wrong'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Favourite Users are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class FavouritePostView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            fav_post = FavouritePost.objects.filter(user_id=user_data.id)
            result_obj = paginat.paginate_queryset(fav_post, request)
            posts_serializer = FavouritePostSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = posts_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if fav_post:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Favourite Posts are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Favourite Posts are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Posts. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FavouritePostSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FavouritePost.objects.filter(fav_post_id = data['fav_post_id']).exists() and data['favourite'] == "0":
                            try:
                                fav_post = FavouritePost.objects.get(fav_post_id = data['fav_post_id'])
                            except:
                                fav_post = None
                            post = PostUser.objects.get(id = data['fav_post_id'])
                            fav_post.delete()
                            return Response({
                                'success': True, 
                                'message': f'{post.title} has successfully remove from your Favourite list.'
                                }) 
                        if data['favourite'] == "1":
                            fav_post_table , created = FavouritePost.objects.get_or_create(fav_post_id = data['fav_post_id'], user_id=user_data.id, favourite=data['favourite'])
                            fav_post_table.save()
                            post = PostUser.objects.get(id = data['fav_post_id'])
                            return Response({
                                'success': True, 
                                'payload': serializer.data, 
                                'message': f'{post.title} has successfully save in your Favourite list.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Posts id is not found'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Favourite Posts are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class FavouriteProductView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            fav_product = FavouriteProduct.objects.filter(user_id=user_data.id)
            result_obj = paginat.paginate_queryset(fav_product, request)
            posts_serializer = FavouriteProductGETSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = posts_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if fav_product:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Favourite Products are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Favourite Product are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Products. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FavouriteProductSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FavouriteProduct.objects.filter(product_id = data['product_id']).exists() and data['favourite'] == "0":
                            try:
                                fav_product = FavouriteProduct.objects.get(product_id = data['product_id'])
                            except:
                                fav_product = None
                            product = Product.objects.get(id = data['product_id'])
                            fav_product.delete()
                            return Response({
                                'success': True, 
                                'message': f'{product.name} product has successfully remove from your Favourite list.'
                                }) 
                        if data['favourite'] == "1":
                            fav_product_table , created = FavouriteProduct.objects.get_or_create(product_id = data['product_id'], user_id=user_data.id, favourite=data['favourite'])
                            fav_product_table.save()
                            product = Product.objects.get(id = data['product_id'])
                            return Response({
                                'success': True, 
                                # 'payload': serializer.data, 
                                'message': f'{product.name} product has successfully save in your Favourite list.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Product id not found'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Favourite Product are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class FollowUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            follow_user = FollowUser.objects.filter(follow_user_id=data1['user_id'], follow=1)
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(follow_user, request)
            follow_user_serializer = FollowUserSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = follow_user_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if follow_user:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Followers are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Followers are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FollowUserSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FollowUser.objects.filter(follow_user_id = data['follow_user_id']).exists() and data['follow'] == "0":
                            try:
                                follow_user = FollowUser.objects.filter(follow_user_id = data['follow_user_id'])
                            except:
                                follow_user = None
                            user = User.objects.get(id = data['follow_user_id'])
                            follow_user.delete()
                            return Response({
                                'success': True, 
                                'message': f'{user.first_name} has successfully remove from your Following list.'
                                }) 
                        if data['follow'] == "1":
                            follow_user_table , created = FollowUser.objects.get_or_create(follow_user_id = data['follow_user_id'], user_email_id=user_data.id, req_status=1)
                            follow_user_table.save()
                            UserNotification.objects.create(sender_id=user_data.id, receiver_id=data['follow_user_id'], notification_type='FOLLOW', notification=f'{user_data.first_name} wants to follow you.', notification_id=follow_user_table.id)
                            follow = FollowUser.objects.get(follow_user_id = data['follow_user_id'], user_email_id=user_data.id)
                            user = User.objects.get(id = data['follow_user_id'])
                            if user.notification_settings == 1:
                                message_title = "Follow Request"
                                message_body =  f'{user_data.first_name} wants to follow you.'
                                payload = {
                                    'id': follow.id,
                                    'push_type': "FOLLOW",
                                }
                                if user.fcm_token:
                                    webpush_notification(user.fcm_token,message_title,message_body,payload)
                                else:
                                    pass
                            else:
                                pass
                            return Response({
                                'success': True, 
                                'request': follow.req_status, 
                                'follow': follow.follow, 
                                'approve_status': follow.approve_status,
                                'message': f'You have successfully sent Following request to {user.first_name}. Please wait for approval.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Something Went Wrong'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Follow User are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class UnFollowUserView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FollowUserSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FollowUser.objects.filter(user_email_id = data['user_email_id']).exists() and data['follow'] == "0":
                            try:
                                follow_user = FollowUser.objects.get(user_email_id = data['user_email_id'])
                            except:
                                follow_user = None
                            user = User.objects.get(id = data['user_email_id'])
                            follow_user.delete()
                            return Response({
                                'success': True, 
                                'message': f'{user.first_name} has successfully remove from your Followers list.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'User Id does not match.'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Follow User are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class UnFollowingUserView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FollowUserSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FollowUser.objects.filter(follow_user_id = data['follow_user_id']).exists() and data['follow'] == "0":
                            try:
                                follow_user = FollowUser.objects.get(user_email_id = data['user_email_id'])
                            except:
                                follow_user = None
                            user = User.objects.get(id = data['user_email_id'])
                            follow_user.delete()
                            return Response({
                                'success': True, 
                                'message': f'{user.first_name} has successfully remove from your Followers list.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'User Id does not match.'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Follow User are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class FollowingUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            following_user = FollowUser.objects.filter(user_email_id=user_data.id, follow=1)
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(following_user, request)
            follow_user_serializer = FollowUserSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = follow_user_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if following_user:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Following Users are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "No Following Users are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Following users. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FollowUserSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else: 
                        if data['following'] == "1":
                            follow_user_table , created = FollowUser.objects.get_or_create(following_user_id = data['following_user_id'], user_email_id=user_data.id, req_status=1)
                            follow_user_table.save()
                            user = User.objects.get(id = data['following_user_id'])
                            return Response({
                                'success': True, 
                                'payload': serializer.data, 
                                'message': f'You have successfully sent Following request to {user.first_name}. Please wait for approval.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Something Went Wrong'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Follow User are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class FollowRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, req_status=1)
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(follow_user, request)
            follow_user_serializer = FollowUserSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = follow_user_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if follow_user:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Requests are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "No Following Request not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            follow_user = FollowUser.objects.filter(follow_user_id = user_data.id, req_status=1)
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FollowUserSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if follow_user:
                            if FollowUser.objects.filter(user_email_id = data['user_email_id']).exists() and data['approve_status'] == "0":
                                try:
                                    follow_user = FollowUser.objects.filter(user_email_id = data['user_email_id'])
                                except:
                                    follow_user = None
                                user = User.objects.get(id = data['user_email_id'])
                                follow_user.delete()
                                # follow_user.req_status = False
                                # follow_user.save()
                                return Response({
                                    'success': True, 
                                    'message': f'{user.first_name} has successfully Decline Following Requests.'
                                    }) 
                            if data['approve_status'] == "1":
                                follow_user_data = FollowUser.objects.get(follow_user_id = user_data.id, user_email_id=data['user_email_id'], req_status=1)
                                follow_user_data.follow = True
                                # follow_user_data.following = True
                                follow_user_data.approve_status = True
                                follow_user_data.req_status = False
                                follow_user_data.save()
                                user = User.objects.get(id = data['user_email_id'])
                                return Response({
                                    'success': True, 
                                    'payload': serializer.data, 
                                    'message': f'You have successfully accept {user.first_name} request.'
                                    }) 
                        else:
                                return Response({
                                    'success': False, 
                                    'message': 'No Request Found.'
                                    }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Follow User are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class RatingUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            rating_user = RatingUser.objects.filter(user_id=data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(rating_user, request)
            rating_user_serializer = RatingUserSerializer(rating_user, many=True, context={'request':request})  
            pagination_data = rating_user_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if rating_user:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Rating are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "No User Rating not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see User Rating. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = RatingUserSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if not RatingUser.objects.filter(rate_user_id = data['rate_user_id'], user_id=user_data.id).exists():
                            rating_user_table , created = RatingUser.objects.get_or_create(group_id=data['group_id'], rate_user_id=data['rate_user_id'], user_id=user_data.id, rating=data['rating'], review=data['review'])
                            rating_user_table.save()
                            total_user = []
                            total_rating = []
                            for i in RatingUser.objects.filter(rate_user_id=data['rate_user_id']):
                                if i.rate_user_id==data['rate_user_id']:
                                    total_user.append(i.rate_user_id)
                                    total_rating.append(i.rating)
                            for i in range(0, len(total_rating)):
                                total_rating[i] = int(total_rating[i])
                            avg = sum(total_rating)//len(total_user)
                            avg_user = User.objects.get(id=data['rate_user_id'])
                            avg_user.avg_rating = avg
                            avg_user.save()
                            serializer = RatingUserSerializer(rating_user_table, context={'request':request})
                            user = User.objects.get(id = data['rate_user_id'])
                            return Response({
                                'success': True, 
                                'payload': serializer.data, 
                                'message': f'You have successfully submit rating to {user.first_name}.'
                                }) 
                        rating_user_table = RatingUser.objects.get(rate_user_id = data['rate_user_id'], user_id=user_data.id)
                        rating_user_table.rating = data['rating']
                        rating_user_table.review = data['review']
                        rating_user_table.save()
                        total_user = []
                        total_rating = []
                        for i in RatingUser.objects.filter(rate_user_id=data['rate_user_id']):
                            if i.rate_user_id==data['rate_user_id']:
                                total_user.append(i.rate_user_id)
                                total_rating.append(i.rating)
                        for i in range(0, len(total_rating)):
                            total_rating[i] = int(total_rating[i])
                        avg = sum(total_rating)//len(total_user)
                        avg_user = User.objects.get(id=data['rate_user_id'])
                        avg_user.avg_rating = avg
                        avg_user.save()
                        serializer = RatingUserSerializer(rating_user_table, context={'request':request})
                        user = User.objects.get(id = data['rate_user_id'])
                        return Response({
                            'success': True, 
                            'payload': serializer.data, 
                            'message': f'You have successfully updated rating to {user.first_name}.'
                            }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class PostUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            posts = PostUser.objects.filter(user_id = data1['user_id']).order_by('-id')
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(posts, request)
            post_serializer = PostDetailSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = post_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if posts:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Posts are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "No Posts are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see User Rating. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = PostSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if data['image'] and data['video']:
                            posts , created = PostUser.objects.get_or_create(user_id=user_data.id, title=data['title'], desc=data['desc'], image=data['image'], video=data['video'])
                            posts.save()
                            if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                for i in follow_user:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id, notification_type='POST', notification=f'{user_data.first_name} create a New Post.', notification_id=posts.id)
                                    if i.user_email.notification_settings == 1:
                                        message_title = "New Post"
                                        message_body =  f'{user_data.first_name} create a new post.'
                                        payload = {
                                            'id': posts.id,
                                            'push_type': "POST",
                                        }
                                        if i.user_email.fcm_token:
                                            webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                        else:
                                            pass
                                    else:
                                        pass
                            return Response({
                                'success': True, 
                                'message': 'You have successfully created a Post.'
                                })
                        if data['image'] and data['youtube_id']:
                            posts , created = PostUser.objects.get_or_create(user_id=user_data.id, title=data['title'], desc=data['desc'], image=data['image'], youtube_id=data['youtube_id'])
                            posts.save()
                            if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                for i in follow_user:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id, notification_type='POST', notification=f'{user_data.first_name} create a New Post.', notification_id=posts.id)
                                    if i.user_email.notification_settings == 1:
                                        message_title = "New Post"
                                        message_body =  f'{user_data.first_name} create a new post.'
                                        payload = {
                                            'id': posts.id,
                                            'push_type': "POST",
                                        }
                                        if i.user_email.fcm_token:
                                            webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                        else:
                                            pass
                                    else:
                                        pass
                            return Response({
                                'success': True, 
                                'message': 'You have successfully created a Post.'
                                })
                        if not data['image'] and not data['video']:
                            posts , created = PostUser.objects.get_or_create(user_id=user_data.id, title=data['title'], desc=data['desc'], youtube_id=data['youtube_id'])
                            posts.save()
                            if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                for i in follow_user:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id, notification_type='POST', notification=f'{user_data.first_name} create a New Post.', notification_id=posts.id)
                                    if i.user_email.notification_settings == 1:
                                        message_title = "New Post"
                                        message_body =  f'{user_data.first_name} create a new post.'
                                        payload = {
                                            'id': posts.id,
                                            'push_type': "POST",
                                        }
                                        if i.user_email.fcm_token:
                                            webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                        else:
                                            pass
                                    else:
                                        pass
                            return Response({
                                'success': True, 
                                'message': 'You have successfully created a Post.'
                                })
                        if not data['video'] and not data['youtube_id']:
                            posts , created = PostUser.objects.get_or_create(user_id=user_data.id, title=data['title'], desc=data['desc'],
                            image=data['image'])
                            posts.save()
                            if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                for i in follow_user:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id, notification_type='POST', notification=f'{user_data.first_name} create a New Post.', notification_id=posts.id)
                                    if i.user_email.notification_settings == 1:
                                        message_title = "New Post"
                                        message_body =  f'{user_data.first_name} create a new post.'
                                        payload = {
                                            'id': posts.id,
                                            'push_type': "POST",
                                        }
                                        if i.user_email.fcm_token:
                                            webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                        else:
                                            pass
                                    else:
                                        pass
                            return Response({
                                'success': True, 
                                'message': 'You have successfully created a Post.'
                                }) 
                        if not data['youtube_id'] and not data['image']:
                            posts , created = PostUser.objects.get_or_create(user_id=user_data.id, title=data['title'], desc=data['desc'],
                            video=data['video'])
                            posts.save()
                            if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                for i in follow_user:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id, notification_type='POST', notification=f'{user_data.first_name} create a New Post.', notification_id=posts.id)
                                    if i.user_email.notification_settings == 1:
                                        message_title = "New Post"
                                        message_body =  f'{user_data.first_name} create a new post.'
                                        payload = {
                                            'id': posts.id,
                                            'push_type': "POST",
                                        }
                                        if i.user_email.fcm_token:
                                            webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                        else:
                                            pass
                                    else:
                                        pass
                            return Response({
                                'success': True, 
                                'message': 'You have successfully created a Post.'
                                })
                        if data['youtube_id'] and data['image'] and data['video']:
                            posts , created = PostUser.objects.get_or_create(user_id=user_data.id, title=data['title'], desc=data['desc'],
                            video=data['video'], youtube_id=data['youtube_id'], image=data['image'])
                            posts.save()
                            if FollowUser.objects.filter(follow_user_id=user_data.id, follow=1).exists():
                                follow_user = FollowUser.objects.filter(follow_user_id=user_data.id, follow=1)
                                for i in follow_user:
                                    UserNotification.objects.create(sender_id=user_data.id, receiver_id=i.user_email_id, notification_type='POST', notification=f'{user_data.first_name} create a New Post.', notification_id=posts.id)
                                    if i.user_email.notification_settings == 1:
                                        message_title = "New Post"
                                        message_body =  f'{user_data.first_name} create a new post.'
                                        payload = {
                                            'id': posts.id,
                                            'push_type': "POST",
                                        }
                                        if i.user_email.fcm_token:
                                            webpush_notification(i.user_email.fcm_token,message_title,message_body,payload)
                                        else:
                                            pass
                                    else:
                                        pass
                            return Response({
                                'success': True, 
                                'message': 'You have successfully created a Post.'
                                })
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def put(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = PostSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if PostUser.objects.filter(user_id=user_data.id, id=data['post_id']).exists():
                            post_data = PostUser.objects.get(user_id=user_data.id, id=data['post_id'])
                            if data['title']:
                                post_data.title = data['title']
                            if data['desc']:
                                post_data.desc = data['desc']
                            if data['video']:
                                post_data.video = data['video']
                            if data['image']:
                                post_data.image = data['image']   
                            if data['youtube_id']:
                                post_data.youtube_id = data['youtube_id']   
                            post_data.save()
                            return Response({
                                'success': True, 
                                'message': 'Your Post Successfully updated.'
                                })   
                        else:
                            return Response({
                                'success': False, 
                                'message': 'No Post Found.'
                                })              
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            id = self.request.GET['params']
            try:
                post = PostUser.objects.filter(id = id, user_id=user_data.id)
            except:
                post = None
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    if post:
                        post.delete()
                        return Response({
                            'success': True, 
                            'message': 'Your post Successfully Deleted.'
                            }) 
                    else:
                        return Response({
                                'success': False, 
                                'message': 'Post id not found in our database.'
                                })
                else:
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to Delete Posts. Please contact with Admin.'
                            })
            else:
                return Response({
                        'success': False, 
                        'message': 'You have no permission to Delete Posts. Please contact with Admin.'
                        })
        except:
            return Response({
                    'success': False, 
                    'message': 'Something went wrong!'
                    })

class PostDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            post = self.request.GET['post_id']
            post_user = PostUser.objects.get(id = post)
            # check_view = PostViewCount.objects.get(post_id = post, user_id = user_data.id, post_view=1)
            posts_serializer = PostDetailSerializer(post_user, context={'request':request})  
            if user_data.user_type == 'USER':
                if post_user:
                    return Response({
                        'status': True, 
                        'payload': posts_serializer.data ,
                        'message': "All Favourite Posts are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Favourite Posts are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Posts. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class UserDetailsPageView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            user_details_id = self.request.GET['user_data_id']
            if user_data.user_type == 'USER':
                user_details = User.objects.get(id=int(user_details_id))
                try:
                    goal_details = UserGoal.objects.filter(user_id=user_details_id, goal_type='INDIVIDUAL').count()
                except:
                    goal_details = None
                try:
                    user_fav = FavouriteUser.objects.get(user_id = user_data.id, fav_user_id = user_details_id)
                except:
                    user_fav = None
                try:
                    user_rating  = RatingUser.objects.get(user_id = user_data.id, rate_user_id = user_details_id)
                except:
                    user_rating = None
                try:
                    user_post  = PostUser.objects.filter(user_id = user_details_id)
                except:
                    user_post = None
                try:
                    user_profile  = User.objects.get(id = user_details_id)
                except:
                    user_profile = None
                try:
                    user_group  = UserGoal.objects.filter(user_id = user_details_id, goal_type='GROUP').count()
                except:
                    user_group = None
                try:
                    follow_user  = FollowUser.objects.get(user_email_id = user_data.id, follow_user_id = user_details_id)
                except:
                    follow_user = None
                paginat=PageNumberPagination()
                paginat.page_size=5
                paginat.page_size_query_param='page_size'
                result_obj = paginat.paginate_queryset(user_post, request)
                fav_user_serializer = FavouriteUserSerializer(user_fav, context={'request':request})
                user_serializer = UserDetailsPageSerializer(user_details, context={'request':request})  
                rating_serializer = RatingUserSerializer(user_rating, context={'request':request})  
                post_serializer = PostDetailSerializer(result_obj, many=True, context={'request':request})  
                follow_user_serializer = FollowUserSerializer(follow_user, context={'request':request})  
                # profile_serializer = UserDetailsPageSerializer(user_profile, context={'request':request})  
                pagination_data = post_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                # user_data_details = user_serializer.data + rating_serializer.data
                return Response({
                    'status': True, 
                    'user': user_serializer.data,
                    'fav_user': fav_user_serializer.data ,
                    'follow_user': follow_user_serializer.data,
                    'rating': rating_serializer.data ,
                    'post': page.data ,
                    'goal': goal_details,
                    'group_goal': user_group,
                    'message': "All Details are successfully fetched."
                    })
            else:
                return Response({
                        'status': False, 
                        'message': "You have not permission to see user profile. Please contact to Admin."
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GroupGoalView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        paginat=PageNumberPagination()
        paginat.page_size=5
        paginat.page_size_query_param='page_size'
        group_goals = UserGoal.objects.filter(user_id=user_data.id)
        try: 
            result_obj = paginat.paginate_queryset(group_goals, request)
            goals_serializer = GroupGoalSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goals_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Group Goals are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        questions = data['question[]']
        token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
        data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
        user_data = User.objects.get(id = data1['user_id'])
        try:
            goal = UserGoal.objects.get(id = data['goal_id'], user_id=user_data.id)
        except:
            goal = None
        if user_data:
            if goal:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = GroupGoalSerializer(data = data)
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if goal.goal_type == 'INDIVIDUAL':
                            group_goal = UserGoal.objects.get(id = goal.id)
                            group_goal.group_name = data['group_name']
                            group_goal.group_desc = data['group_desc']
                            group_goal.goal_type = 'GROUP'
                            group_goal.save()
                            if data['members[]']:
                                for i in data['members[]']:
                                    group_member , created = GoalMember.objects.get_or_create(goal_id = goal.id, members_id=i, request=1, owner=user_data)
                                    group_member.save()
                            if data['admin[]']:
                                for i in data['admin[]']:
                                    group_admin , created = GoalGroupAdmin.objects.get_or_create(group_goal_id = goal.id, user_id=i)
                                    group_admin.save()
                            goal_admin = GoalMember.objects.get(members_id=user_data.id, goal_id = goal.id)
                            goal_admin.approve = 1
                            goal_admin.request = 0
                            goal_admin.save()
                            group , created = ChatGroup.objects.get_or_create(group_name=goal.goal_name, goal_id=goal.id, members=data['members[]'],  owner=user_data.id, room_id=random_with_N_digits(12))
                            group.save()
                            if questions:
                                for ques in questions:
                                    question=ques['question']
                                    answer=ques['answer']
                                    questions_table, created = GroupQuestion.objects.get_or_create(questions=question, answer=answer, 
                                    group_id=goal.id)
                                    questions_table.save()
                            else:
                                pass
                            return Response({
                                'success': True, 
                                'message': 'Your Goal is successfully converted into the Group.'
                                })
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Goal id not found and goal type is not INDIVIDUAL.'
                                })
                if user_data.user_type != 'USER':
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to create Goals. Please contact with Admin.'
                            })
                else:
                    return Response({
                            'success': False, 
                            'message': 'You have no permission to create Goals. Please contact with Admin.'
                            })
            else:
                return Response({
                        'success': False, 
                        'message': 'This goal id not associated with current user.'
                        })
        else:
            return Response({
                    'success': False, 
                    'message': 'You are not a user type.'
                    })

class FavouriteGroupGoalView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            fav_goal = FavouriteGoal.objects.filter(user=data1['user_id'])
            result_obj = paginat.paginate_queryset(fav_goal, request)
            goals_serializer = FavouriteGoalSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goals_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                if fav_goal:
                    return Response({
                        'status': True, 
                        'payload': page.data ,
                        'message': "All Favourite Goals are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Favourite Goals are not found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Favourite Goals. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = FavouriteGoalSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if FavouriteGoal.objects.filter(goal_id = data['goal_id']).exists() and data['favourite'] == "0":
                            try:
                                fav_goal = FavouriteGoal.objects.get(goal_id = data['goal_id'])
                            except:
                                fav_goal = None
                            goal = UserGoal.objects.get(id = data['goal_id'])
                            fav_goal.delete()
                            return Response({
                                'success': True, 
                                'message': f'{goal.goal_name} has successfully remove from your Favourite list.'
                                }) 
                        if data['favourite'] == "1":
                            fav_goal_table , created = FavouriteGoal.objects.get_or_create(goal_id = data['goal_id'], user_id=user_data.id, favourite=data['favourite'])
                            fav_goal_table.save()
                            goal = UserGoal.objects.get(id = data['goal_id'])
                            return Response({
                                'success': True, 
                                'payload': serializer.data, 
                                'message': f'{goal.goal_name} has successfully save in your Favourite list.'
                                }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'Something Went Wrong'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Favourite Goals are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class RequestGoalView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.GET['goal_id']
            try:
                request_user = RequestGoal.objects.filter(user_id=user_data.id, goal_id=goal_id)
            except:
                request_user = None
            if request_user:
                total_member = []
                sum = 0
                for i in request_user:
                    total_member.append(i.member)
                if user_data.user_type == 'USER':
                    for i in request_user:
                        if i.approve == 1:
                            sum += 1 
                    if (len(total_member) - sum) == 0:
                        return Response({
                                'status': True, 
                                'request_sent': True,
                                'approve': True,
                                'message': "Your Goal Request is successfully accepted by Admin."
                                })
                    else:
                        return Response({
                            'status': True, 
                            'request_sent': True,
                            'approve': False,
                            'message': "Your Goal Request is still Pending for Admin Approval."
                            })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goal Request. Please contact with Admin."
                        })
            else:
                return Response({
                    'status': False, 
                    'request_sent': False,
                    'message': "This goal is not associated with current login user."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_members_list = []
            try:
                goal_member = GoalMember.objects.filter(goal_id = data['goal_id'], approve=1)
                for i in goal_member:
                    goal_members_list.append(i.members_id)
            except:
                goal_member: None
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = RequestGoalSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if data['request'] == '1':
                            for i in goal_members_list:
                                if i == user_data.id:
                                    return Response({
                                    'success': False, 
                                    'message': f'You have already member of request Goal.'
                                    })
                                if PaymentToken.objects.filter(user_id=user_data.id).exists(): 
                                    request_goal , created = RequestGoal.objects.get_or_create(user_id=user_data.id, goal_id=data['goal_id'], 
                                    request=1, member=i)
                                    request_goal.save()
                                else:
                                    return Response({
                                        'success': False, 
                                        'message': 'Please Add Payment Method first.'
                                        }) 
                            return Response({
                                'success': True, 
                                'message': 'You have successfully sent request to Goals Admin.'
                                }) 
                        if data['request'] == '0':
                            goal_member = RequestGoal.objects.filter(goal_id = data['goal_id'], user_id=user_data.id).delete()
                            return Response({
                                'success': True, 
                                'message': 'You have successfully withdrawal your request.'
                                })
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class RequestGoalMemberView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.GET['goal_id']
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            member = RequestGoal.objects.filter(member=user_data.id, goal_id=goal_id, request=1)
            result_obj = paginat.paginate_queryset(member, request)
            if user_data.user_type == 'USER':
                goals_serializer = RequestGoalSerializer(result_obj, many=True, context={'request':request}) 
                pagination_data = goals_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                return Response({
                    'status': True, 
                    'payload': page.data,
                    'message': 'All new members request is successfully fetch.'
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goal Request. Please contact with Admin."
                    })
            else:
                return Response({
                    'status': False, 
                    'request_sent': False,
                    'message': "This goal is not associated with current login user."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            user_detail = User.objects.get(id = data['user_id'])
            try:
                goal_member = RequestGoal.objects.get(goal_id = data['goal_id'], member=user_data.id, user_id=data['user_id'], request=1)
            except:
                goal_member: None
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = RequestGoalSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if data['approve'] == '1':
                            goal_member.request = 0
                            goal_member.approve = 1
                            goal_member.save()
                            total_member_count = RequestGoal.objects.filter(user_id=data['user_id'], goal_id=data['goal_id']).count()
                            total_member_approve = RequestGoal.objects.filter(user_id=data['user_id'], goal_id=data['goal_id'],
                            approve=1).count()     
                            if (total_member_count - total_member_approve) == 0:
                                add_member, created = GoalMember.objects.get_or_create(members_id=data['user_id'], goal_id=data['goal_id'], approve=1, request=0)
                                add_member.save()
                            return Response({
                                'success': True, 
                                'message': f'You have successfully accept {user_detail.first_name + user_detail.last_name} user goal request.'
                                }) 
                        if data['approve'] == '0':
                            goal_member = RequestGoal.objects.filter(goal_id = data['goal_id'], user_id=data['user_id']).delete()
                            return Response({
                                'success': True, 
                                'message': f'You have successfully decline {user_detail.first_name + user_detail.last_name} user goal request.'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class RoomView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            user_id = self.request.GET['user-id']
            room_id = f'{user_data.id}' + '_room_' + f'{user_id}'
            room_id1 = f'{user_id}' + '_room_' + f'{user_data.id}'
            try:
                room = Room.objects.get(Q(room=room_id) | Q(room=room_id1))
                if room:
                    if user_data.user_type == 'USER':
                        chat_serializer = RoomSerializer(room, context={'request':request}) 
                        return Response({
                            'status': True, 
                            'payload': chat_serializer.data,
                            'message': 'You can chat now.'
                            })
                    if user_data.user_type == 'VENDOR':
                        return Response({
                            'status': False, 
                            'message': "You have no permission to see Chat. Please contact with Admin."
                            })
                    else:
                        return Response({
                            'status': False, 
                            'message': "You have no permission to see Chat. Please contact with Admin.."
                            })
            except:
                room_data, created = Room.objects.get_or_create(user1_id=user_data.id, user2_id=user_id, room=room_id)
                room_data.save()
                if user_data.user_type == 'USER':
                    chat_serializer = RoomSerializer(room_data, context={'request':request}) 
                    return Response({
                        'status': True, 
                        'payload': chat_serializer.data,
                        'message': 'You can chat now.'
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Chat. Please contact with Admin."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Chat. Please contact with Admin."
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class ChatView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            room_id = self.request.GET['room_id']
            room1 = room_id.split('_')
            room_id1 = f'{room1[0]}' + '_room_' + f'{room1[-1]}'
            room_id2 = f'{room1[-1]}' + '_room_' + f'{room1[0]}'
            try:
                room = Room.objects.get(Q(room=room_id1) | Q(room=room_id2))
            except:
                room = None
            if room:
                try:
                    message = Chat.objects.filter(room_id_id = room.id).order_by('-id')
                except:
                    message = None
                if user_data.user_type == 'USER':
                    chat_serializer = ChatSerializer(message, many=True, context={'request':request}) 
                    return Response({
                        'status': True, 
                        'payload': chat_serializer.data,
                        'message': 'All Chat is successfully fetch.'
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Chat. Please contact with Admin."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Chat. Please contact with Admin."
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "No Chat Found between both users."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class UserRoomView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            name = self.request.query_params.get('name')
            paginat=PageNumberPagination()
            paginat.page_size=10
            paginat.page_size_query_param='page_size'
            try:
                chat_query = f"""SELECT "superadmin_room"."id", "superadmin_room"."user1_id", "superadmin_room"."user2_id", 
                "superadmin_room"."room","superadmin_chat"."created" FROM "superadmin_room" LEFT OUTER JOIN "superadmin_chat"
                 ON ("superadmin_room"."id" = "superadmin_chat"."room_id_id") WHERE ("superadmin_room"."user1_id" = {user_data.id}
                 OR "superadmin_room"."user2_id" = {user_data.id}) group by "superadmin_room"."id" 
                 ORDER BY "superadmin_chat"."created" DESC;"""
                data_raw = Room.objects.raw(chat_query)
                group_chat = GoalMember.objects.filter(members_id = user_data.id, approve=1)
                for i in group_chat:
                    group_room = ChatGroup.objects.filter(goal_id=i.goal_id)
            except:
                data_raw = None
                group_room = None
            result_obj = paginat.paginate_queryset(data_raw, request)
            if user_data.user_type == 'USER':
                chat_serializer = UserRoomSerializer(result_obj, many=True, context={'request':request}) 
                if name:
                    groupchat_serializer = GroupChatSerializer(group_room.filter(Q(group_name__contains=name)),
                    many=True, context={'request':request}) 
                else:
                    groupchat_serializer = GroupChatSerializer(group_room, many=True, context={'request':request}) 
                pagination_data = chat_serializer.data + groupchat_serializer.data
                page = paginat.get_paginated_response(pagination_data)
                return Response({
                    'status': True,
                    'payload': page.data,
                    'message': 'All Chat Rooms are successfully fetch.'
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Chat. Please contact with Admin."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Chat. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class UserChatView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            room_id = self.request.GET['room-id']
            user_id = self.request.GET['user-id']
            try:
                chat1 = Chat.objects.filter(room_id_id = room_id, receiver_id = user_id, sender_id = user_data.id)
                chat2 = Chat.objects.filter(room_id_id = room_id, receiver_id = user_data.id, sender_id = user_id)
            except:
                chat1 = None
                chat2 = None
            all_chat = chat1 | chat2
            if user_data.user_type == 'USER':
                chat_serializer = ChatViewSerializer(all_chat, many=True, context={'request':request}) 
                return Response({
                    'status': True, 
                    'payload': chat_serializer.data,
                    'message': 'All Chat Rooms are successfully fetch.'
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Chat. Please contact with Admin."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Chat. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GroupChatView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.GET['goal_id']
            member = GoalMember.objects.get(goal_id=goal_id, members_id=user_data.id, approve=1)
            goal = UserGoal.objects.get(id =goal_id)
            try:
                groups = ChatGroup.objects.get(goal_id = goal_id)
            except:
                groups = None
            if member:
                members_data = []
                goal_members = GoalMember.objects.filter(goal_id=goal_id, approve=1)
                for i in goal_members:
                    members_data.append(i.members_id)
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = GroupChatSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    if not groups:
                        if not goal.group_name:
                            group , created = ChatGroup.objects.get_or_create(group_name=goal.goal_name, goal_id=goal_id, members=members_data,  owner=user_data.id, room_id=random_with_N_digits(12))
                            group.save()
                            chat1 = ChatGroup.objects.get(id=group.id)
                            serializer1 = GroupChatSerializer(chat1, context={'request':request})
                            return Response({
                                'status': True, 
                                 'payload': serializer1.data,
                                'message': "Your Chat Group Successfully Created."
                                })
                        else:
                            group , created = ChatGroup.objects.get_or_create(group_name=goal.group_name, goal_id=goal_id, members_id=members_data,  owner=user_data, room_id=random_with_N_digits(12))
                            group.save()
                            chat2 = ChatGroup.objects.get(id=group.id)
                            serializer2 = GroupChatSerializer(chat2, context={'request':request})
                            return Response({
                                'status': True, 
                                'payload': serializer2.data,
                                'message': "Your Chat Group Successfully Created."
                                })
                    else:
                        chat = ChatGroup.objects.get(goal_id=goal_id)
                        serializer = GroupChatSerializer(chat, context={'request':request})
                        return Response({
                            'status': True, 
                            'payload': serializer.data,
                            'message': "You can send massage."
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "You are not Authenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GroupRoomChatView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            room_id = self.request.GET['room_id']
            try:
                room = ChatGroup.objects.get(room_id = room_id)
            except:
                room = None
            if room:
                try:
                    message = GroupMassage.objects.filter(group_id = room.id).order_by('-id')
                except:
                    message = None
                if user_data.user_type == 'USER':
                    chat_serializer = GroupRoomChatSerializer(message, many=True, context={'request':request}) 
                    return Response({
                        'status': True, 
                        'payload': chat_serializer.data,
                        'message': 'All Chat is successfully fetch.'
                        })
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Chat. Please contact with Admin."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Chat. Please contact with Admin."
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "No Chat Found in this group."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class PostLikeDislikeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            post = self.request.GET['post_id']
            try:
                post_user = PostLikeDislike.objects.get(user_id=user_data.id, post_id = post)
            except:
                post_user = None
            post_user_serializer = PostLikeSerializer(post_user, partial=True, context={'request':request})  
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': post_user_serializer.data ,
                    'message': "All Requests are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Post Like. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            try:
                post_user = PostLikeDislike.objects.get(user_id = user_data.id, post_id = data['post_id'])
            except:
                post_user = None
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = PostLikeSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if post_user:
                            serializer = PostLikeSerializer(data = data, context={'request':request})
                            if data['dislike'] == '1' and data['like'] == '0':
                                post_user.post_dislike = True
                                post_user.post_like = False
                                post_user.save()
                                post_data = PostLikeDislike.objects.get(id=post_user.id)
                                serializer = PostLikeSerializer(post_data, context={'request':request})
                                return Response({
                                    'success': True, 
                                    'payload': serializer.data,
                                    'message': 'You have successfully dislike this post..'
                                    }) 
                            if data['like'] == '1' and data['dislike'] == '0' :
                                post_user.post_dislike = False
                                post_user.post_like = True
                                post_user.save()
                                post_data = PostLikeDislike.objects.get(id=post_user.id)
                                serializer = PostLikeSerializer(post_data, context={'request':request})
                                return Response({
                                    'success': True, 
                                    'payload': serializer.data,
                                    'message': 'You have successfully like this post..'
                                    })
                            if data['like'] == '0' and data['dislike'] == '0' :
                                post_user.delete()
                                post_data = PostLikeDislike.objects.filter(post_id=data['post_id'])
                                serializer = PostLikeSerializer(post_data, context={'request':request})
                                return Response({
                                    'success': True, 
                                    'payload': serializer.data,
                                    'message': 'You have successfully revert changes.'
                                    })
                        else:
                            if data['like'] == '1':
                                new_post_user = PostLikeDislike.objects.create(post_id = data['post_id'], user_id=user_data.id, post_like=data['like'], post_dislike=data['dislike'])
                                new_post_user.save()
                                user_post = PostUser.objects.get(id=data['post_id'])
                                UserNotification.objects.create(sender_id=user_data.id, receiver_id=user_post.user_id, notification_type='LIKE', notification=f'{user_data.first_name} liked your post.', notification_id=new_post_user.id)
                                if user_post.user.notification_settings == 1:
                                    message_title = "Post Like"
                                    message_body =  f'{user_data.first_name} liked your post.'
                                    payload = {
                                        'id': user_post.id,
                                        'push_type': "LIKE",
                                    }
                                    if user_post.user.fcm_token:
                                        webpush_notification(user_post.user.fcm_token,message_title,message_body,payload)
                                    else:
                                        pass
                                else:
                                    pass
                                post_data = PostLikeDislike.objects.get(id=new_post_user.id)
                                serializer = PostLikeSerializer(post_data, context={'request':request})
                                return Response({
                                    'success': True, 
                                    'payload': serializer.data,
                                    'message': 'You have successfully like this post.'
                                    }) 
                            if data['dislike'] == '1':
                                new_post_user = PostLikeDislike.objects.create(post_id = data['post_id'], user_id=user_data.id, post_like=data['like'], post_dislike=data['dislike'])
                                new_post_user.save()
                                post_data = PostLikeDislike.objects.get(id=new_post_user.id)
                                serializer = PostLikeSerializer(post_data, context={'request':request})
                                return Response({
                                    'success': True, 
                                    'payload': serializer.data,
                                    'message': 'You have successfully dislike this post.'
                                    }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Follow User are not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class PostCountView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try: 
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            post = self.request.GET['post_id']
            try:
                post_user = PostLikeDislike.objects.get(user_id=user_data.id, post_id = post)
            except:
                post_user = None
            post_user_serializer = PostLikeSerializer(post_user, context={'request':request})  
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': post_user_serializer.data ,
                    'message': "All Requests are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Post Like. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            try:
                post_view = PostViewCount.objects.get(user_id = user_data.id, post_id = data['post_id'])
            except:
                post_view = None
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = PostLikeSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if not post_view:
                            serializer = PostCountSerializer(data = data, context={'request':request})
                            if data['post_id']:
                                post_view_data = PostViewCount.objects.create(post_id=data['post_id'], user_id=user_data.id, post_view=1)
                                post_view_data.save()
                                post_data = PostViewCount.objects.get(id=post_view_data.id)
                                serializer = PostCountSerializer(post_data, context={'request':request})
                                return Response({
                                    'success': True, 
                                    # 'payload': serializer.data,
                                    'message': 'You have successfully view this post..'
                                    }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'You have Already View this Post.'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalOrderView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_status = self.request.query_params.get('status')
            paginat=PageNumberPagination()
            paginat.page_size=5
            paginat.page_size_query_param='page_size'
            if goal_status:
                goal_order = GoalOrder.objects.filter(product__user=user_data.email, status=goal_status).order_by('-id')
            else:
                goal_order = GoalOrder.objects.filter(product__user=user_data.email).order_by('-id')
            result_obj = paginat.paginate_queryset(goal_order, request)
            goals_order_serializer = GoalOrderSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goals_order_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': True, 
                    'payload': page.data ,
                    'message': "All Orders are successfully fetched."
                    })
            if user_data.user_type == 'USER':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Goals Order. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class VendorHomeAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            today_order = self.request.query_params.get('today_order')
            today_earning = self.request.query_params.get('today_earning')
            if today_order:
                goal_order_today = GoalOrder.objects.filter(product__user=user_data.email, created__contains=datetime.date.today()).count()
            else:
                goal_order_today = None
            goal_order = GoalOrder.objects.filter(product__user=user_data.email).count()
            if not today_earning:
                received_payment = VendorInvoice.objects.filter(vendor_id=data1['user_id'], status='COMPLETED').aggregate(received_amount=Sum('amount'))
            else:
                amount_payment_date = date.today()
                received_payment = VendorInvoice.objects.filter(vendor_id=data1['user_id'], status='COMPLETED', amount_date=amount_payment_date).aggregate(received_amount=Sum('amount'))
            if not today_order:
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': True, 
                        'total_earning': f"$ {received_payment['received_amount']}",
                        'total_order': goal_order,
                        'message': "Your Orders and Earning successfully fetch."
                        })
                if user_data.user_type == 'USER':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals Order. Please contact with Admin."
                        })
            else:
                if user_data.user_type == 'VENDOR':
                    return Response({
                        'status': True, 
                        'total_earning': '$ 52450',
                        'total_order': goal_order_today,
                        'message': "Your Orders and Earning successfully fetch."
                        })
                if user_data.user_type == 'USER':
                    return Response({
                        'status': False, 
                        'message': "You have no permission to see Goals Order. Please contact with Admin."
                        })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GroupQuestionAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            group_question = GroupAdminQuestion.objects.all()
            group_question_serializer = GroupQuestionSerializer(group_question, many=True, context={'request':request})  
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': group_question_serializer.data,
                    'message': "All Group Questions are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Group Questions. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalQuestionAnswerAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.query_params.get('goal_id')
            group_question = GroupQuestion.objects.filter(group_id=goal_id)
            group_question_serializer = GoalQuestionAnswerSerializer(group_question, many=True, context={'request':request})  
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': group_question_serializer.data,
                    'message': "All Group Questions are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Group Questions. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            try:
                goal_question = GroupQuestion.objects.filter(group_id=data['goal_id'])
            except:
                goal_question = None
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = PostLikeSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if goal_question:
                            if GoalGroupAdmin.objects.filter(user_id=user_data.id, group_goal_id=data['goal_id'], approve=1).exists():
                                for i in goal_question:
                                    i.delete()
                                for ques_ans in data['questions[]']:
                                    question=ques_ans['question']
                                    answer=ques_ans['answer']
                                    goal_question = GroupQuestion.objects.create(questions=question, answer=answer, group_id=data['goal_id'])
                                    goal_question.save()
                                return Response({
                                    'success': True, 
                                    'message': 'You have successfully updated group policy.'
                                    }) 
                            else:
                                return Response({
                                    'success': False, 
                                    'message': 'You are not admin of this group.'
                                    }) 
                        else:
                            for ques_ans in data['questions[]']:
                                question=ques_ans['question']
                                answer=ques_ans['answer']
                                goal_question = GroupQuestion.objects.create(questions=question, answer=answer, group_id=data['goal_id'])
                                goal_question.save()
                            return Response({
                                'success': True, 
                                'message': 'You have successfully updated group policy.'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalCommentAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.query_params.get('goal_id')
            try:
                goal_comment = GoalComment.objects.filter(goal_id=goal_id).order_by('-id')
            except:
                goal_comment = None
            paginat=PageNumberPagination()
            paginat.page_size=10
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(goal_comment, request)
            goal_comment_serializer = GoalCommentSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goal_comment_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': page.data,
                    'message': "Group Comments are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Group Comments. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = GoalCommentSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if GoalMember.objects.filter(members_id=user_data.id, goal_id=data['goal_id'], approve=1).exists():
                            if data['image'] and data['comment']:
                                goal_comment = GoalComment.objects.create(comment=data['comment'], goal_id=data['goal_id'], image=data['image'], user_id=user_data.id)
                                goal_comment.save()
                                return Response({
                                    'success': True, 
                                    'message': 'You have successfully posted your comment.'
                                    }) 
                            if data['comment'] and not data['image']:
                                goal_comment = GoalComment.objects.create(comment=data['comment'], goal_id=data['goal_id'], user_id=user_data.id)
                                goal_comment.save()
                                return Response({
                                    'success': True, 
                                    'message': 'You have successfully posted your comment.'
                                    }) 
                            if data['image'] and not data['comment']:
                                goal_comment = GoalComment.objects.create(image=data['image'], goal_id=data['goal_id'], user_id=user_data.id)
                                goal_comment.save()
                                return Response({
                                    'success': True, 
                                    'message': 'You have successfully posted your comment.'
                                    }) 
                        else:
                            return Response({
                                'success': False, 
                                'message': 'You are not member of this group.'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GoalCommentRatingAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            # goal_id = self.request.query_params.get('goal_id')
            try:
                goal_comment_rating = GoalCommentRating.objects.filter(user_id=user_data.id).order_by('-id')
            except:
                goal_comment_rating = None
            paginat=PageNumberPagination()
            paginat.page_size=10
            paginat.page_size_query_param='page_size'
            result_obj = paginat.paginate_queryset(goal_comment_rating, request)
            goal_comment_rating_serializer = GoalCommentRatingSerializer(result_obj, many=True, context={'request':request})  
            pagination_data = goal_comment_rating_serializer.data
            page = paginat.get_paginated_response(pagination_data)
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': page.data,
                    'message': "Group Comment Ratings are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Group Comment Ratings. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try: 
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data:
                if user_data.user_type == 'USER' and user_data.is_active == True:
                    serializer = GoalCommentRatingSerializer(data = data, context={'request':request})
                    if not serializer.is_valid():
                        return Response({
                            'success': False, 
                            'payload': serializer.errors, 
                            'message': 'Something went wrong'
                            }) 
                    else:
                        if not GoalCommentRating.objects.filter(comment_id=data['comment_id'], user_id=user_data.id).exists():
                            total_user = []
                            total_rating = []
                            goal_comment_rating = GoalCommentRating.objects.create(comment_id=data['comment_id'], rating=data['rating'], user_id=user_data.id)
                            goal_comment_rating.save()
                            for i in GoalCommentRating.objects.filter(comment_id=data['comment_id']):
                                if i.comment_id==int(data['comment_id']):
                                    total_user.append(i.user)
                                    total_rating.append(i.rating)
                            for i in range(0, len(total_rating)):
                                total_rating[i] = int(total_rating[i])
                            avg = sum(total_rating)//len(total_user)
                            avg_comment_rating = GoalComment.objects.get(id=data['comment_id'])
                            avg_comment_rating.avg_rating = avg
                            avg_comment_rating.save()
                            return Response({
                                'success': True, 
                                'message': 'You have successfully posted your rating.'
                                }) 
                        else:
                            total_user = []
                            total_rating = []
                            goal_comment_rating = GoalCommentRating.objects.get(comment_id=data['comment_id'], user_id=user_data.id)
                            goal_comment_rating.rating = data['rating']
                            goal_comment_rating.save()
                            for i in GoalCommentRating.objects.filter(comment_id=data['comment_id']):
                                if i.comment_id==int(data['comment_id']):
                                    total_user.append(i.comment_id)
                                    total_rating.append(i.rating)
                            for i in range(0, len(total_rating)):
                                total_rating[i] = int(total_rating[i])
                            avg = sum(total_rating)//len(total_user)
                            avg_comment_rating = GoalComment.objects.get(id=data['comment_id'])
                            avg_comment_rating.avg_rating = avg
                            avg_comment_rating.save()
                            return Response({
                                'success': True, 
                                'message': 'You have successfully update your rating.'
                                }) 
                else:
                    return Response({
                        'status': False, 
                        'message': "You are Unauthenticated User!"
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "User not found."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

class GroupAdminListing(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            group_id = self.request.query_params.get('group_id')
            try:
                goal_admin = GoalGroupAdmin.objects.filter(group_goal_id=group_id, approve=1).order_by('-id')
            except:
                goal_admin = None
            goal_comment_rating_serializer = GoalGroupAdminSerializer(goal_admin, many=True, context={'request':request})  
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': goal_comment_rating_serializer.data,
                    'message': "Group Comment Ratings are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Group Comment Ratings. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            try:
                group_admin = GoalGroupAdmin.objects.get(group_goal_id=data['group_id'], approve=1, user_id=['admin_id'])
            except:
                group_admin = None
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if GoalGroupAdmin.objects.filter(user_id=user_data.id, approve=1).exists():
                    if GoalMember.objects.filter(members_id=user_data.id, goal_id=data['group_id'], approve=1, request=0, owner_id=user_data.id).exists():
                        for i in data['admin_list[]']:
                            group_admin = GoalGroupAdmin.objects.get(user_id=i, group_goal_id=data['group_id'])
                            group_admin.delete()
                        return Response({
                            'status': True, 
                            'message': "You have successfully removed admin from group."
                            })
                    else:
                        return Response({
                            'success': False, 
                            'message': 'You have no permission to remove admin.'
                            })
                else:
                    return Response({
                        'success': False, 
                        'message': 'You are not a Group admin.'
                        })
            else:
                return Response({
                    'success': False, 
                    'message': 'You have no permission to access group. Please contact with Admin.'
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class GroupMemberListing(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            group_id = self.request.query_params.get('group_id')
            try:
                goal_member = GoalMember.objects.filter(goal_id=group_id, approve=1).exclude(members_id=user_data.id).order_by('-id')
            except:
                goal_member = None
            goal_member_serializer = GroupMemberListingSerializer(goal_member, many=True, context={'request':request})  
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'payload': goal_member_serializer.data,
                    'message': "All Group members are successfully fetched."
                    })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Group members. Please contact with Admin."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something Went Wrong'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if GoalGroupAdmin.objects.filter(user_id=user_data.id, approve=1).exists():
                    if GoalMember.objects.filter(members_id=user_data.id, goal_id=data['group_id'], approve=1, request=0).exists():
                        for i in data['members_list[]']:
                            group_member = GoalMember.objects.get(members_id=i, goal_id=data['group_id'])
                            group_member.delete()
                        return Response({
                            'status': True, 
                            'message': "You have successfully removed member from group."
                            })
                    else:
                        return Response({
                            'success': False, 
                            'message': 'You have no permission to remove member.'
                            })
                else:
                    return Response({
                        'success': False, 
                        'message': 'You are not a Group admin.'
                        })
            else:
                return Response({
                    'success': False, 
                    'message': 'You have no permission to access group. Please contact with Admin.'
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class PaymentTokenView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                user_payment = PaymentToken.objects.filter(user_id=user_data.id)
                user_payment_serializer = PaymentTokenSerializer(user_payment, many=True)
                return Response({
                    'status': True, 
                    'payload': user_payment_serializer.data,
                    'message': "All saved card successfully fetched."
                    })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                user_payment = PaymentToken.objects.filter(user_id=user_data.id)
                user_payment_serializer = PaymentTokenSerializer(user_payment, many=True)
                return Response({
                    'status': True, 
                    'payload': user_payment_serializer.data,
                    'message': "All saved card successfully fetched."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if PaymentToken.objects.filter(user_id=user_data.id, token=data['token']).exists():
                    return Response({
                        'status': True, 
                        'message': "This Card already added."
                        })
                if not PaymentToken.objects.filter(user_id=user_data.id, default_payment=1).exists():
                    user_payment = PaymentToken.objects.create(user_id=user_data.id, token=data['token'], default_payment=1)
                    user_payment.save()
                else:
                    user_payment = PaymentToken.objects.create(user_id=user_data.id, token=data['token'])
                    user_payment.save()
                try:
                    stripe.Customer.create_source(
                        user_data.customer_id,
                        source=data['token']
                        )
                    user_card = stripe.Customer.list_sources(
                        user_data.customer_id,
                        object="card",
                    )
                    for i in user_card['data']:
                        if not PaymentToken.objects.filter(card_id=i['id']).exists():
                            user_payment.card_id = i['id']
                            user_payment.save()
                    return Response({
                        'status': True, 
                        'message': "You have successfully saved card."
                        })
                except stripe.error.CardError as e:
                    return Response({
                        'status': False, 
                        'message': e.error
                        })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                if PaymentToken.objects.filter(user_id=user_data.id, token=data['token']).exists():
                    return Response({
                        'status': True, 
                        'message': "This Card already added."
                        })
                else:
                    user_payment = PaymentToken.objects.create(user_id=user_data.id, token=data['token'])
                    user_payment.save()
                try:
                    stripe.Customer.create_source(
                        user_data.customer_id,
                        source=data['token']
                        )
                    user_card = stripe.Customer.list_sources(
                        user_data.customer_id,
                        object="card",
                    )
                    for i in user_card['data']:
                        if not PaymentToken.objects.filter(card_id=i['id']).exists():
                            user_payment.card_id = i['id']
                            user_payment.save()
                    return Response({
                        'status': True, 
                        'message': "You have successfully saved card."
                        })
                except stripe.error.CardError as e:
                    return Response({
                        'status': False, 
                        'message': e.error
                        })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'status': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            card_id = self.request.query_params.get('card_id')
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if card_id:
                    card_total = PaymentToken.objects.filter(user_id=user_data.id).count()
                    if card_total == 1: 
                        if not RequestGoal.objects.filter(user_id=user_data.id, approve=0).exists():
                            if not UserSubscription.objects.filter(user_id=user_data.id).exists():
                                try:
                                    stripe.Customer.delete_source(
                                        user_data.customer_id,
                                        card_id,
                                        )
                                    PaymentToken.objects.filter(card_id=card_id).delete()
                                    return Response({
                                        'status': True, 
                                        'message': "Card Removed!."
                                        })
                                except stripe.error.CardError as e:
                                    return Response({
                                        'status': False, 
                                        'message': e.error
                                        })
                            return Response({
                                'status': False, 
                                'message': "Your Subscription Plan is Active. Please Cancel Plan and try again."
                                })
                        else:
                            return Response({
                                'status': False, 
                                'message': "You have requested in Goal. Please withdrawal your request first."
                                })
                    else:
                        try:
                            stripe.Customer.delete_source(
                                user_data.customer_id,
                                card_id,
                                )
                            PaymentToken.objects.filter(card_id=card_id).delete()
                            return Response({
                                'status': True, 
                                'message': "Card Removed!."
                                })
                        except stripe.error.CardError as e:
                            return Response({
                                'status': False, 
                                'message': e.error
                                })
                else:
                    return Response({
                        'status': False, 
                        'message': "Please provide card ID."
                        })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': False, 
                    'message': "You have no permission to donate fund."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class PaymentDefaultView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if PaymentToken.objects.filter(user_id=user_data.id, card_id=data['card_id']).exists():
                    remove_default = PaymentToken.objects.get(user_id=user_data.id, default_payment=1)
                    remove_default.default_payment = 0
                    remove_default.save()
                    set_default = PaymentToken.objects.get(user_id=user_data.id, card_id=data['card_id'])
                    set_default.default_payment = 1
                    set_default.save()
                    return Response({
                        'status': True, 
                        'message': "You have successfully set default payment method."
                        })
                else:
                    return Response({
                        'success': False, 
                        'message': 'No Card found.'
                        })
            else:
                return Response({
                    'success': False, 
                    'message': 'You have no access to set payment method. Please contact with Admin.'
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class GoalDonationView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                user_payment = GoalDonation.objects.filter(user_id=user_data.id).order_by('-id')
                user_payment_serializer = GoalDonationSerializer(user_payment, many=True)
                return Response({
                    'status': True, 
                    'payload': user_payment_serializer.data,
                    'message': "All Transactions has successfully fetched.."
                    })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                user_payment = PaymentToken.objects.filter(user_id=user_data.id)
                user_payment_serializer = PaymentTokenSerializer(user_payment, many=True)
                return Response({
                    'status': True, 
                    'payload': user_payment_serializer.data,
                    'message': "All saved card successfully fetched."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                try:
                    payment = stripe.Charge.create(
                        customer=user_data.customer_id,
                        amount=int(float(data['amount'])*100),
                        currency='usd',
                        source=data['card_id'],
                        )
                    if payment['paid'] == True:
                        user_payment = GoalDonation.objects.create(user_id=user_data.id, amount=payment['amount']/100, transaction_id=payment['balance_transaction'], status=payment['paid'], goal_id=data['goal_id'])
                        user_payment.save()
                        receipt_url = payment['receipt_url']
                        goal_id = UserGoal.objects.get(id=data['goal_id'])
                        user_email = user_data.email
                        amount = data['amount']
                        sendConfirmationMail(receipt_url, goal_id, user_email, amount)
                        user_payment = GoalDonation.objects.filter(user_id=user_data.id).last()
                        user_payment_serializer = GoalDonationSerializer(user_payment)
                        goal_members = GoalMember.objects.filter(goal_id=data['goal_id'], approve=1)
                        for i in goal_members:
                            if i.members.notification_settings == 1:
                                message_title = "Payment received"
                                message_body =  f'{user_data.first_name} donate a {int(amount)/100} payment.'
                                payload = {
                                    'id': data['goal_id'],
                                    'push_type': "DONATION",
                                }
                                if i.members.fcm_token:
                                    webpush_notification(i.members.fcm_token,message_title,message_body,payload)
                                else:
                                    pass
                            else:
                                pass
                        return Response({
                            'status': True, 
                            'payload': user_payment_serializer.data,
                            'message': "Your payment successfully received."
                            })
                    else:
                        return Response({
                            'status': False, 
                            'message': "Your last payment was failed. Please try again!"
                            })
                except stripe.error.CardError as e:
                    return Response({
                        'status': False, 
                        'message': e.error
                        })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                user_payment = PaymentToken.objects.create(user_id=user_data.id, token=data['token'])
                user_payment.save()
                return Response({
                    'status': True, 
                    'message': "You have successfully saved card."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class GoalLeaveRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                user_request = GoalLeaveRequest.objects.filter(user_id=user_data.id).order_by('-id')
                user_request_serializer = GoalLeaveRequestSerializer(user_request, many=True)
                return Response({
                    'status': True, 
                    'payload': user_request_serializer.data,
                    'message': "All Leave request has successfully fetched.."
                    })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': True, 
                    'message': "You have no permission to see leave request."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if GoalMember.objects.filter(goal_id=data['goal_id'], members_id=user_data.id, approve=1, request=0).exists():
                    if not GoalLeaveRequest.objects.filter(goal_id=data['goal_id'], user_id=user_data.id).exists():
                        if data['request'] == '1':
                            request_member = GoalLeaveRequest.objects.create(goal_id=data['goal_id'], user_id=user_data.id, request=1)
                            request_member.save()
                            return Response({
                                'status': True, 
                                'message': "You have successfully raise leave request."
                                })
                    if data['request'] == '0':
                        withdraw_request = GoalLeaveRequest.objects.get(goal_id=data['goal_id'], user_id=user_data.id)
                        withdraw_request.delete()
                        return Response({
                            'status': True, 
                            'message': "You have successfully withdraw your leave request."
                            })
                    else:
                        return Response({
                            'status': True, 
                            'message': "You have already requested this goal."
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "You are not asscoiate with this goal."
                        })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': False, 
                    'message': "You have no permission to visit Goal."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class GoalAdminLeaveRequestView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.query_params.get('goal_id')
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if UserGoal.objects.filter(id=goal_id, user_id=user_data.id).exists():
                    user_request = GoalLeaveRequest.objects.filter(goal_id=goal_id).order_by('-id')
                    user_request_serializer = GoalAdminLeaveRequestSerializer(user_request, many=True)
                    return Response({
                        'status': True, 
                        'payload': user_request_serializer.data,
                        'message': "All Leave request has successfully fetched.."
                        })
                return Response({
                    'status': False, 
                    'message': "You are not a group Admin of this goal."
                    })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': True, 
                    'message': "You have no permission to see leave request."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if UserGoal.objects.filter(id=data['goal_id'], user_id=user_data.id).exists():
                    if GoalLeaveRequest.objects.filter(goal_id=data['goal_id'], user_id=data['user_id']).exists():
                        if data['approve'] == '1':
                            accept_request = GoalLeaveRequest.objects.get(goal_id=data['goal_id'], user_id=data['user_id'])
                            accept_request.approve = 1
                            accept_request.reject = None
                            accept_request.save()
                            members = GoalMember.objects.filter(goal_id=data['goal_id'], approve=1).exclude(members_id=data['user_id'])
                            for i in members:
                                newdate = date.today() + timedelta(days=15)
                                create_poll = GoalPoll.objects.create(goal_id=data['goal_id'], leave_user_id=data['user_id'], 
                                goal_member_id=i.members_id, due_date=newdate, remove_self=1)
                                create_poll.save()
                            return Response({
                                'status': True, 
                                'message': "You have successfully approve user request."
                                })
                        if data['approve'] == '0':
                            reject_request = GoalLeaveRequest.objects.get(goal_id=data['goal_id'], user_id=data['user_id'])
                            reject_request.reject = 1
                            reject_request.approve = 0
                            reject_request.save()
                            return Response({
                                'status': True, 
                                'message': "You have successfully reject user request."
                                })
                    else:
                        return Response({
                            'status': True, 
                            'message': "You have already requested this goal."
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "You are not asscoiate with this goal."
                        })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': False, 
                    'message': "You have no permission to visit Goal."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class GoalPollView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.query_params.get('goal_id')
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if GoalMember.objects.filter(goal_id=goal_id, members_id=user_data.id, approve=1).exists():
                    try:
                        user_request = GoalPoll.objects.get(goal_id=goal_id, goal_member_id=user_data.id)
                    except:
                        user_request = None
                    if user_request:
                        user_request_serializer = GoalPollSerializer(user_request)
                        return Response({
                            'status': True, 
                            'payload': user_request_serializer.data,
                            'message': "Poll Started."
                            })
                    else:
                        return Response({
                            'status': True, 
                            'message': "No request found."
                            })
                return Response({
                    'status': False, 
                    'message': "You are not a member of this goal."
                    })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': True, 
                    'message': "You have no permission to see poll."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if GoalPoll.objects.filter(goal_member_id=user_data.id, goal_id=data['goal_id']).exists():
                    if data['approve'] == '1':
                        poll = GoalPoll.objects.get(goal_id=data['goal_id'], goal_member_id=user_data.id)
                        poll.is_poll = 1
                        poll.approve = 1
                        poll.save()
                        return Response({
                            'status': True, 
                            'message': "You have successfully submitted your response."
                            })
                    if data['approve'] == '0':
                        poll = GoalPoll.objects.get(goal_id=data['goal_id'], goal_member_id=user_data.id)
                        poll.is_poll = 1
                        poll.save()
                        return Response({
                            'status': True, 
                            'message': "You have successfully submitted your response."
                            })
                    else:
                        return Response({
                            'status': False, 
                            'message': "Please send valid input."
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "You are not asscoiate with this goal."
                        })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': False, 
                    'message': "You have no permission to visit Goal."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class RemoveGoalMemberView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if GoalMember.objects.filter(goal_id=data['goal_id'], owner_id=user_data.id, approve=1, request=0).exists():
                    if GoalGroupAdmin.objects.filter(group_goal_id=data['goal_id'], user_id=user_data.id, approve=1).exists():
                        if data['remove'] == '1':
                            request_member = GoalMember.objects.get(goal_id=data['goal_id'], members_id=data['user_id'])
                            request_member.delete()
                            GoalGroupAdmin.objects.filter(user_id__in=[data['user_id']]).delete()
                            if UserSubscription.objects.filter(user_id=data['user_id'], goal_id=data['goal_id']).exists():
                                user_subscription = UserSubscription.objects.get(user_id=data['user_id'], goal_id=data['goal_id'])
                                stripe.Subscription.delete(
                                    user_subscription.subscription_id
                                    )
                                user_subscription.delete()
                            else:
                                pass
                            UserSubscription.objects.filter(user_id=data['user_id'], goal_id=data['goal_id']).delete()
                            members = GoalMember.objects.filter(goal_id=data['goal_id'], approve=1, request=0)
                            for i in members:
                                newdate = date.today() + timedelta(days=7)
                                create_poll = GoalPoll.objects.create(goal_id=data['goal_id'], leave_user_id=data['user_id'], 
                                goal_member_id=i.members_id, due_date=newdate, remove_admin=1)
                                create_poll.save()
                            return Response({
                                'status': True, 
                                'message': "User Removed Successfully."
                                })
                        else:
                            return Response({
                                'status': False, 
                                'message': "Invalid Request parameter."
                                })
                    else:
                        return Response({
                            'status': False, 
                            'message': "You are not a SuperAdmin of this Goal."
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "You are not asscoiate with this goal."
                        })
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                return Response({
                    'status': False, 
                    'message': "You have no permission to visit Goal."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class VendorSubscriptionView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            payment_plan = SubscriptionPlan.objects.get(plan_type=data['plan'])
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                if payment_plan.free_trail == 0:
                    checkout_session = stripe.checkout.Session.create(
                        client_reference_id = data['customer_id'],
                        success_url = settings.SUCCESS_URL,
                        cancel_url = settings.CANCEL_URL,
                        payment_method_types= ["card"],
                        mode = "subscription",
                        customer = user_data.customer_id,
                        line_items=[
                        {
                            'price': payment_plan.subscription_price_id,
                            'quantity': 1,
                        }
                        ]
                    )
                    return Response({
                        'status': True, 
                        'payload': checkout_session,
                        'message': "Please hit payment url and pay the fees."
                        })
                if not SubscriptionUsed.objects.filter(user_id=user_data.id).exists():
                    plan = SubscriptionPlan.objects.get(plan_type=data['plan'])
                    newdate = date.today() + timedelta(days=int(plan.days))
                    vendor_subscription = VendorSubscription.objects.create(customer_id=data['customer_id'], vendor_id=user_data.id, plan_id=plan.id,
                    start_at=datetime.today(), expire_at=newdate)
                    vendor_subscription.save()
                    SubscriptionUsed.objects.create(subscription_plan_id=plan.id, used=True, user_id=user_data.id)
                    return Response({
                        'status': True, 
                        'message': "Your Free Trail is Active."
                        })
                return Response({
                    'status': False, 
                    'message': "You have already used free trail."
                    })
            if user_data.user_type == 'USER':
                return Response({
                    'status': False, 
                    'message': "You have no permission to visit Goal."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class VendorSubscriptionPlanView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                payment_plan = SubscriptionPlan.objects.all()
                plan_serializer = VendorSubscriptionPlanSerializer(payment_plan, many=True, context={'request':request})
                return Response({
                    'status': True, 
                    'payload': plan_serializer.data,
                    'message': "All Subscrioption Plans are successfully fetched."
                    })
            if user_data.user_type == 'USER':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see payment Plan."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            subscription = self.request.query_params.get('subscription_id')
            free_trail = self.request.query_params.get('free_trail')
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                if subscription:
                    vendor_subscription_details = stripe.Subscription.retrieve(
                        subscription
                        )
                    if VendorSubscription.objects.filter(vendor_id=user_data.id, subscription_id=subscription).exists():
                        try:
                            stripe.Subscription.delete(
                                vendor_subscription_details['id']
                                )
                            VendorSubscription.objects.filter(subscription_id=subscription, vendor_id=user_data.id).delete()
                            return Response({
                                'status': True, 
                                'message': "Your Subscription Plan successfully cancelled!."
                                })
                        except stripe.error.CardError as e:
                            return Response({
                                'status': False, 
                                'message': e.error
                                })
                    else:
                        return Response({
                            'status': False, 
                            'message': "No Subscription Plan found."
                            })
                if free_trail:
                    VendorSubscription.objects.filter(subscription_id=subscription, vendor_id=user_data.id).delete()
                    return Response({
                        'status': True, 
                        'message': "Your Free Trail Plan successfully cancelled!."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Please provide valid Subscription ID."
                        })
            if user_data.user_type == 'USER' and user_data.is_active == True:
                return Response({
                    'status': False, 
                    'message': "You have no permission to cancelled subscription."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class VendorPaymentView(APIView):   
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                if data['status'] == 'done':
                    vendor_subscription = VendorSubscription.objects.create(customer_id=data['customer_id'], subscription_id=data['subscription_id'], vendor_id=user_data.id)
                    vendor_subscription.save()
                    return Response({
                        'status': True, 
                        'message': "Your payment successfully received."
                        })
                if data['status'] == 'failed':
                    return Response({
                        'status': False, 
                        'message': "Your last payment was failed. Please try again."
                        })
            if user_data.user_type == 'USER':
                return Response({
                    'status': False, 
                    'message': "You have no permission to a  proceed payment."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class CheckSubscriptionPaymentView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            stripe_id = self.request.query_params.get('stripe_id')
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                if stripe_id:
                    payment_checkout = stripe.checkout.Session.retrieve(
                            stripe_id
                        )
                    vendor_subscription_details = stripe.Subscription.retrieve(
                        payment_checkout['subscription']
                        )
                    product_details = stripe.Product.retrieve(
                        vendor_subscription_details['items']['data'][0]['price']['product']
                        )
                    plan_data = SubscriptionPlan.objects.get(plan_type=product_details['name'])
                    plan_end_date = datetime.fromtimestamp(vendor_subscription_details['current_period_end']).strftime('%Y-%m-%d %H:%M:%S')
                    plan_start_date = datetime.fromtimestamp(vendor_subscription_details['current_period_start']).strftime('%Y-%m-%d %H:%M:%S')
                    if not VendorSubscription.objects.filter(subscription_id=vendor_subscription_details['id']).exists():
                        vendor_subscription = VendorSubscription.objects.create(customer_id=user_data.customer_id, subscription_id=payment_checkout['subscription'], start_at=plan_start_date, expire_at=plan_end_date, vendor_id=user_data.id, plan_id=plan_data.id)
                        vendor_subscription.save()
                        vendor_data = VendorSubscription.objects.get(id=vendor_subscription.id)
                        return Response({
                            'status': True, 
                            'message': "Your subscription plan successfully activated."
                            })
                    vendor_data = VendorSubscription.objects.get(subscription_id=vendor_subscription_details['id'])
                    return Response({
                        'status': True, 
                        'message': "Your subscription plan successfully activated."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "Please provide stripe ID."
                        })
            if user_data.user_type == 'USER':
                return Response({
                    'status': True, 
                    'message': "You have no permission to see payment Plan."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class GoalPaymentPlanView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.query_params.get('goal_id')
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if UserGoal.objects.filter(id=goal_id).exists():
                    if GoalMember.objects.filter(goal_id=goal_id, members_id=user_data.id, owner_id=user_data.id).exists():
                        try:
                            goal_amount = GoalAmountPlan.objects.get(goal_id=goal_id)
                        except:
                            goal_amount = None
                        if goal_amount:
                            if goal_amount.members == GoalMember.objects.filter(goal_id=goal_id, approve=1).count():
                                goal_amount_serializer = GoalPaymentPlanSerializer(goal_amount)
                                return Response({
                                    'status': True, 
                                    'payload': goal_amount_serializer.data,
                                    'message': "Goal Payment Plan successfully fetched."
                                    })   
                            else:
                                members = GoalMember.objects.filter(goal_id=goal_id, approve=1).count()
                                goal_amount = GoalAmountPlan.objects.get(goal_id=goal_id)
                                goal_amount.members = members
                                goal_amount.save()
                                goal_plan = GoalAmountPlan.objects.get(goal_id=goal_id)
                                goal_plan_serializer = GoalPaymentPlanSerializer(goal_plan)
                                return Response({
                                    'status': True, 
                                    'payload': goal_plan_serializer.data,
                                    'message': "Goal Payment Plan successfully fetched."
                                    })
                        else:
                            goal = UserGoal.objects.get(id=goal_id)
                            goal_members = GoalMember.objects.filter(goal_id=goal_id, approve=1).count()
                            goal_payment = GoalAmountPlan.objects.create(amount=goal.goal_amount, goal_id=goal.id, members=goal_members)
                            goal_payment.save()
                            goal_amount = GoalAmountPlan.objects.get(goal_id=goal_id)
                            goal_amount_serializer = GoalPaymentPlanSerializer(goal_amount)
                            return Response({
                                'status': True, 
                                'payload': goal_amount_serializer.data,
                                'message': "Goal Payment Plan successfully fetched."
                                })
                    else:
                        return Response({
                            'status': False, 
                            'message': "You are not a Admin of current Goal."
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "Please provide Valid Goal ID."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': True, 
                    'message': "You have no permission to see payment Plan."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            data = request.data
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if UserGoal.objects.filter(id=data['goal_id']).exists():
                    if GoalMember.objects.filter(goal_id=data['goal_id'], owner=user_data.id).exists():
                        try:
                            goal_plan = GoalAmountPlan.objects.get(goal_id=data['goal_id'])
                        except:
                            goal_plan = None
                        goal_name = UserGoal.objects.get(id=data['goal_id'])
                        goal_product = stripe.Product.create(
                            name = goal_name.goal_name
                        )
                        goal_plan.product_id = goal_product['id']
                        goal_plan.save()
                        goal_data = UserGoal.objects.get(id=data['goal_id'])
                        goal_duration_check = {1:1, 2:6, 3:12}
                        commission = AdminCommission.objects.get(id=1)
                        goal_price = stripe.Price.create(
                            unit_amount=int(int(data['amount']) + ((int(data['amount'])*int(commission.amount_percentage))/100)),
                            currency="usd",
                            recurring={"interval": "month", "interval_count":goal_duration_check.get(goal_data.payment_plan_id)},
                            product=goal_product['id'],
                            )
                        goal_plan.price_id = goal_price['id']
                        goal_plan.save()
                        members = []
                        members_email = []
                        goal_members = GoalMember.objects.filter(goal_id=data['goal_id'], approve=1)
                        for i in goal_members:
                            members_email.append(i.members.email)
                            members.append(i.members_id)
                        user_customer = User.objects.filter(id__in=members)
                        PaymentToken.objects.filter(user_id__in=members)
                        user_cards =  PaymentToken.objects.values_list('user_id', flat=True).filter(user_id__in=members)
                        check_list = list(set(user_cards).symmetric_difference(set(members)))
                        if len(user_cards) == len(members):
                            for i in user_customer:
                                user_subscription = stripe.Subscription.create(
                                    customer=i.customer_id,
                                    items=[
                                        {"price": goal_price['id']},
                                    ],
                                    )
                                payment_date = user_subscription['items']['data'][0]['price']['recurring']['interval_count']
                                goal_plan_duration = {1:"Monthly", 6:"Quarterly", 12:"Yearly"}
                                plan_start_date = datetime.fromtimestamp(user_subscription['current_period_start']).strftime('%Y-%m-%d %H:%M:%S')
                                plan_end_date = datetime.fromtimestamp(user_subscription['current_period_end']).strftime('%Y-%m-%d %H:%M:%S')
                                user_subscription_data = UserSubscription.objects.create(user_id=i.id, plan=goal_plan_duration.get(payment_date), customer_id=i.customer_id, subscription_id=user_subscription['id'], price_id=user_subscription['items']['data'][0]['price']['id'], start_at=plan_start_date, next_billing_date=plan_end_date, goal_id=data['goal_id'])
                                user_subscription_data.save()
                            sendSubscriptionMail(plan_end_date, goal_name.goal_name, members_email, data['amount'])
                            goal_plan.amount = data['amount']
                            goal_plan.start_at = data['start_date']
                            goal_plan.save()
                            return Response({
                                'status': True, 
                                'message': "Your have successfully set payment plan."
                                })
                        else:
                            missing_card_users = User.objects.values_list('first_name', flat=True).filter(id__in=check_list)
                            names = ', '.join(missing_card_users)
                            return Response({
                                'status': False, 
                                'message': f"{names} has not set card yet. Please add card first."
                                })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': False, 
                    'message': "You have no permission to a proceed payment."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class UserGoalSubscriptionView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            goal_id = self.request.query_params.get('goal_id')
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if GoalMember.objects.filter(members_id=user_data.id, approve=1, goal_id=goal_id).exists():
                    if GoalAmountPlan.objects.filter(goal_id=goal_id).exists():
                        try:
                            user_subscription = UserSubscription.objects.get(goal_id=goal_id, user_id=user_data.id)
                        except:
                            user_subscription = None
                        if user_subscription:
                            user_subscription_plan = GoalSubscriptionPlanSerializer(user_subscription)
                            return Response({
                                'status': True, 
                                'payload': user_subscription_plan.data,
                                'message': "Your subscription plan details successfully fetched."
                                })
                        else:
                            return Response({
                                'status': False, 
                                'message': "No subsciption plan active."
                                })
                    else:
                        return Response({
                            'status': False, 
                            'message': "Please provide valid Goal ID."
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "Please provide valid Goal ID."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': True, 
                    'message': "You have no permission to see payment Plan."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class VendorInvoiceView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=10
            paginat.page_size_query_param='page_size'
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                vendor_invoice = VendorInvoice.objects.filter(vendor_id=user_data.id)
                pagination_data = paginat.paginate_queryset(vendor_invoice, request)
                invoice_serializer = VendorInvoiceSerializer(pagination_data, many=True).data
                pagination_serializer = paginat.get_paginated_response(invoice_serializer).data
                return Response({
                    'status': True, 
                    'payload': pagination_serializer,
                    'message': "All Completed Order successfully fetched."
                    })
            if user_data.user_type == 'USER':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see Invoice."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            data = request.data
            if data:
                if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                    serializer = VendorRequestInvoiceSerializer(data=data)
                    if serializer.is_valid():
                        goal_order = GoalOrder.objects.filter(order_id=data['order_id'])
                        if goal_order.exists() and not VendorInvoice.objects.filter(order_id=data['order_id']).exists():
                            invoice_request = GoalOrder.objects.get(order_id=data['order_id'])
                            invoice_request.invoice_request = 1
                            invoice_request.save()
                            vendor_invoice = VendorInvoice.objects.create(vendor_id=user_data.id, amount=data['amount'], goal_id=goal_order[0].goal_id, order_id=data['order_id'])
                            invoice_serializer = VendorInvoiceSerializer(vendor_invoice).data
                            return Response({
                                "status": True,
                                'payload': invoice_serializer,
                                "message": "Invoice created.",
                            })
                        else:
                            return Response({
                                "status": False,
                                "message": "Already created invoice with order ID or invalid order ID.",
                            })
                    else:
                        return Response({
                            "status": False,
                            "message": "Please Input validate data!",
                        })
                else:
                    return Response({
                        "status": False,
                        "message": "Invalid user type!",
                    })
            else:
                return Response({
                    "status": False,
                    "message": "Please Input validate data!",
                })
        except:
            return Response({
                "status": False,
                "message": "Something went wrong!",
            })

class VendorTransactionView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            paginat=PageNumberPagination()
            paginat.page_size=10
            paginat.page_size_query_param='page_size'
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                vendor_invoice = VendorInvoice.objects.filter(vendor_id=user_data.id, status='COMPLETED')
                pagination_data = paginat.paginate_queryset(vendor_invoice, request)
                invoice_serializer = VendorTransactionSerializer(pagination_data, many=True, context={'request':request}).data
                pagination_serializer = paginat.get_paginated_response(invoice_serializer).data
                return Response({
                    'status': True, 
                    'payload': pagination_serializer,
                    'message': "All transactions successfully fetched."
                    })
            if user_data.user_type == 'USER':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see transactions."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class VendorTransactionHeadingView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'VENDOR' and user_data.is_active == True:
                products = Product.objects.filter(user=user_data).values_list('id')
                received_payment = VendorInvoice.objects.filter(vendor_id=data1['user_id'], status='COMPLETED').aggregate(received_amount=Sum('amount'))
                due_amount = UserGoal.objects.filter(product_id__in=products).aggregate(goal_amount=Sum('goal_amount')).get('goal_amount')
                if received_payment['received_amount']:
                    due_amount -= received_payment['received_amount']
                else:
                    received_payment['received_amount'] = 0
                vendor_transaction_dashboard = {
                    'received_payment':received_payment['received_amount'],
                    'due_amount':f'$ {round(due_amount, 2)}',
                    'refund_amount':0
                }
                return Response({
                    'status': True, 
                    'payload': vendor_transaction_dashboard,
                    'message': "All transactions successfully fetched."
                    })
            if user_data.user_type == 'USER':
                return Response({
                    'status': False, 
                    'message': "You have no permission to see transactions."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class UserNotificationView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            if user_data.user_type == 'USER' and user_data.is_active == True:
                if UserNotification.objects.filter(receiver_id=user_data.id).exists():
                    paginat=PageNumberPagination()
                    paginat.page_size=10
                    paginat.page_size_query_param='page_size'
                    user_notification = UserNotification.objects.filter(receiver_id=user_data.id).order_by('-id')
                    result_obj = paginat.paginate_queryset(user_notification, request)
                    user_notification_serializer = UserNotificationSerializer(result_obj, many=True)
                    pagination_data = user_notification_serializer.data
                    page = paginat.get_paginated_response(pagination_data)
                    return Response({
                        'status': True, 
                        'payload': page.data,
                        'message': "All Notifications are successfully fetched."
                        })
                else:
                    return Response({
                        'status': False, 
                        'message': "No Notification found."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': True, 
                    'message': "You have no permission to see user notification."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

class PaypalView(APIView):
    def post(self, request):
        url = "https://api.sandbox.paypal.com/v1/oauth2/token"
        data = {
                    "client_id":settings.PAYPAL_CLIENT_ID,
                    "client_secret":settings.PAYPAL_SECRET_KEY,
                    "grant_type":"client_credentials"
                }
        headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Basic {0}".format(base64.b64encode((settings.PAYPAL_CLIENT_ID + ":" + settings.PAYPAL_SECRET_KEY).encode()).decode())
                }
        token = requests.post(url, data, headers=headers)
        return Response({
            'status': True, 
            'payload': token,
            })

class CurrencyConvertorView(APIView):
    def get(self, request):
        try:
            return Response({
                'status': True, 
                'payload': supported_currency,
                'message': "All supported currencies."
                })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })

    # permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data1 = jwt.decode(token, 'secret', algorithms=['HS256'], options=jwt_options)
            user_data = User.objects.get(id = data1['user_id'])
            data = request.data
            if user_data.user_type == 'USER' and user_data.is_active == True:
                currencyData = CurrencyConverter()
                if data['currency'] in supported_currency:
                    try:
                        convertAmount = currencyData.convert(data['amount'], 'USD', data['currency'])
                        return Response({
                            'status': True, 
                            'payload': round(convertAmount, 2),
                            'message': "Amount converted."
                            })
                    except Exception as e:
                        return Response({
                            'status': False, 
                            'message': 'Rate not found.'
                            })
                else:
                    return Response({
                        'status': False, 
                        'message': "Currency not supported."
                        })
            if user_data.user_type == 'VENDOR':
                return Response({
                    'status': True, 
                    'message': "You have no permission to see user notification."
                    })
            else:
                return Response({
                    'status': False, 
                    'message': "Unauthenticated User."
                    })
        except:
            return Response({
                'success': False, 
                'message': 'Something went wrong!'
                })


@csrf_exempt
def goalSubscriptionCompletedwebhook(request):
    endpoint_secret = settings.STRIPE_ENDPOINT_SECRET
    event = None
    payload = request.body
    sig_header = request.headers['STRIPE_SIGNATURE']
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        raise e
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise e

    # Handle the event
    if event['type'] == 'invoice.paid':
        subscription_schedule = event['data']['object']
        commission = AdminCommission.objects.get(id=1)
        goal = UserSubscription.objects.get(subscription_id=subscription_schedule['lines']['data'][0]['subscription'])
        GoalSubscriptionTransaction.objects.create(product_id=subscription_schedule['lines']['data'][0]['price']['product'], customer_id=subscription_schedule['customer'], goal_id = goal.goal_id, subscription_id=subscription_schedule['lines']['data'][0]['subscription'], amount=int(int(subscription_schedule['amount_paid'])+((int(subscription_schedule['amount_paid'])*int(commission.amount_percentage))/100)))
        user_goal = UserGoal.objects.get(id=goal.goal_id)
        user = User.objects.get(customer_id=subscription_schedule['customer'])
        goal_collect_amount = GoalSubscriptionTransaction.objects.filter(goal_id=goal.goal_id).aggregate(goal_amount=Sum('amount'))
        if int(goal_collect_amount['goal_amount']) >= int(user_goal.goal_amount):
            stripe.Subscription.delete(
            subscription_schedule['lines']['data'][0]['subscription']
            )
            user_goal.plan_status = 'COMPLETED'
            user_goal.status = 'COMPLETED'
            user_goal.save()
            sendGoalCompleteMail(user_goal, user)
            if user_goal.goal_as == 'PRODUCT':
                goal_order = GoalOrder.objects.get(goal_id=user_goal.id)
                goal_order.status = 'COMPLETED'
                goal_order.save()
        else:
            pass
    else:
      print('Unhandled event type {}'.format(event['type']))

    return JsonResponse({
        'success':True
    })