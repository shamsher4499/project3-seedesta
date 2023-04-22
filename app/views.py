from datetime import datetime, timedelta
from email import message
import json
from re import template
from django.dispatch import receiver
from django.shortcuts import render, redirect
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.utils import timezone
# from numpy import source
from superadmin.choices import *
from superadmin.email import *
from app.email import sendWelcomeMailVendor, sendWelcomeMailUser, sendForgetPassOTPUser, sendContactUsMail, sendSubscriptionMail
from django.http import HttpResponse, JsonResponse, request, response
from superadmin.models import *
from django.contrib.auth import authenticate, login
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import login as auth_login
from django.db.models import Count, Sum
import stripe
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt
from allauth.account.signals import user_signed_up
from django.dispatch import receiver
# Create your views here.

def check_password(password):
    return bool(re.match('(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)', password))==True


def home(request):
    template_name = 'app/home.html'
    request.session["select_follow_user"] =  []
    request.session["select_admin_user"] = []
    
    social = SocialIcon.objects.all()
    testimonial = TestimonialManagement.objects.all()
    about = AboutUs.objects.get()
    slide = SlideApp.objects.all()
    latest_goal = UserGoal.objects.filter(goal_priority='PUBLIC').order_by('-id')[:5]
    context = {'social':social, 'about':about, 'slide':slide, 'testimonial':testimonial, 'latest_goal':latest_goal}
    return render(request, template_name, context)


def aboutus(request):
    template_name = 'app/about-us.html'
    social = SocialIcon.objects.all()
    about = AboutUs.objects.get()
    return render(request, template_name, {'social':social, 'about':about})

def contactus(request):
    template_name = 'app/contact-us.html'
    social = SocialIcon.objects.all()
    touch = GetInTouch.objects.get()
    return render(request, template_name, {'social':social, 'touch':touch})

def profile(request):
    try:
        social = SocialIcon.objects.all()
        id = request.user.id    
        if id:
            user1 = User.objects.get(id=id)
        else:
            return redirect('signin')
        template_name = 'app/auth/profile.html'
        if request.method == 'POST':
            name = request.POST.get('username')
            bio = request.POST.get('bio')
            oldpassword= request.POST.get('oldpassword')
            newPassword = request.POST.get('newPassword')
            confirmPassword = request.POST.get('confirmPassword')
            image = request.FILES.get('image')
            if name == '':
                messages.error(request, 'Name must be valid not be blank.')
                return render(request, template_name, {'user1':user1})
            if newPassword.isspace():
                messages.error(request, 'New password must be valid not be blank.')
                return render(request, template_name, {'user1':user1})
            if confirmPassword.isspace():
                messages.error(request, 'Confirm password must be valid not be blank.')
                return render(request, template_name, {'user1':user1})
            if newPassword != confirmPassword:
                messages.error(request, 'New password and Confirm Password must be same.')
                return render(request, template_name, {'user1':user1})
            if not len(newPassword) >= 8 and not   len(newPassword) <= 16:
                messages.error(request, 'Password length should be 8-16 only.')
                return render(request, template_name, {'user1':user1})
            if not check_password(newPassword) and not newPassword == '':
                messages.error(request, 'Password must be contains special, small char, upper char and one digit.')
                return render(request, template_name, {'user1':user1}) 
            if oldpassword == confirmPassword and not oldpassword == '':
                messages.error(request, 'change password')
                return render(request, template_name, {'user1':user1})    
            user1.first_name = name
            user1.bio = bio
            user1.profile_pic=image
            user1.set_password(confirmPassword)
            user1.save()

            auth_login(request,user1,  backend="django.contrib.auth.backends.ModelBackend",)
            if image:
                user1.profile_pic = image
            user1.save()
            messages.success(request, 'Successfully changed')
            return redirect('profile')
        return render(request, template_name, {'user1':user1})
    except:
        return render(request, template_name, {'user1':user1, 'social':social})

def contactus_ajax(request):
    template_name = 'app/contact-us.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        name = request.POST.get('name')
        message = request.POST.get('message')
        if not name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Name field must be entered.",
                },
                status=404,
            )
        if not email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Email field must be entered.",
                },
                status=404,
            )
        if '@' not in email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Email field must be entered.",
                },
                status=404,
            )
        if not subject:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Subject field must be entered.",
                },
                status=404,
            )
        if not message:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Message field must be entered.",
                },
                status=404,
            )
        data, created = ContactUs.objects.get_or_create(email=email, subject=subject, message=message, name=name, status='PENDING')
        data.save()
        sendContactUsMail(data)
        return JsonResponse(
            {
                "status": "success",
                "message":  data.name +'! '+ "Your Request have Successfully Received, We response soon.",
            },
            status=200,
        )
    return render(request, template_name, {'social':social})

def termsCondition(request):
    template_name = 'app/terms-conditions.html'
    social = SocialIcon.objects.all()
    return render(request, template_name, {'social':social})

def privacyPolicy(request):
    template_name = 'app/privacy-policy.html'
    social = SocialIcon.objects.all()
    return render(request, template_name, {'social':social})

def help(request):
    template_name = 'app/help.html'
    social = SocialIcon.objects.all()
    return render(request, template_name, {'social':social})

def login(request):
    template_name = 'app/auth/login.html'
    social = SocialIcon.objects.all()
   
    # u = User.objects.get(id=171)
    # u.delete()
    return render(request, template_name, {'social':social})

def select_user(request):
    if request.method == "POST":
        setuser = request.POST.get("setuser")
        obj = request.user
        obj.user_type = setuser
        obj.save()

        return JsonResponse({"status": "success"}, 200)


@receiver(user_signed_up)
def social_login_active_user(sender=User, **kwargs):
    user = kwargs['user']
    user.is_active = True
    user.user_type = 'USER'
    customer_data = stripe.Customer.create(
                name=user.first_name,
                email=user.email,
                phone=user.mobile,
            )
    user.customer_id = customer_data['id']
    user.save()

def loginAjax(request):
    
    template_name = 'app/auth/login.html'
    social = SocialIcon.objects.all()

    if request.method == 'POST':

            email = request.POST.get('email')
            password = request.POST.get('password')
            user = auth.authenticate(email=email , password=password)
            
            if user:
                auth_login(request,user)
                return JsonResponse(
                    {
                        "status": "success",
                        "message": "Successfully Login.",
                    },
                    status=200,
                )
            else:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "Invalid Credentails!",
                    },
                    status=404,
                )
    return render(request, template_name, {'social':social})

def logoutUser(request):
    auth.logout(request)
    messages.success(request, "You have Successfully Logout")
    return redirect('signin')

def signup(request):
    template_name = 'app/auth/signup.html'
    social = SocialIcon.objects.all()
    return render(request, template_name, {'roll':USER_TYPE, 'social':social})

def signupUserAjax(request):
    template_name = 'app/auth/signup.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        agree = request.POST.get('agree')
        mobile = request.POST.get('mobile')
        data = User.objects.filter(email = request.POST.get('email'))
        data1 = User.objects.filter(mobile = request.POST.get('mobile'))
        if not first_name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "First Name field must be entered.",
                },
                status=404,
            )
        if not last_name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Last Name field must be entered.",
                },
                status=404,
            )
        if not email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Email field must be entered.",
                },
                status=404,
            )
        if '@' and '.' not in email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Please enter valid Email Address",
                },
                status=404,
            )
        if mobile.startswith('-', 0):
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Mobile field must be only number.",
                },
                status=404,
            )
        if not (len(mobile) >= 10 and len(mobile) <= 12):
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Mobile field must be 10-12 number.",
                },
                status=404,
            )
        if data1:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Mobile field must be unique.",
                },
                status=404,
            )
        if not password:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Password field must be entered.",
                },
                status=404,
            )
        if not agree:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Please click on Terms & Condition!",
                },
                status=404,
            )
        if not data:
            user, created = User.objects.get_or_create(email=email, password=password, first_name=first_name, mobile=mobile, last_name=last_name, user_type='USER')
            user.set_password(user.password)
            customer_data = stripe.Customer.create(
                name=user.company_username,
                email=user.email,
                phone=user.mobile,
            )
            user.customer_id = customer_data['id']
            user.save()
            slug = user.slug
            sendOTP(user)
            return JsonResponse(
                {
                    "status": "success",
                    "message": "You have Successfully Registerd!",
                    "slug": slug
                },
                status=200,
            )
        else:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "This email address is already exists!",
                },
                status=404,
            )
    return render(request, template_name, {'roll':USER_TYPE, 'social':social})

def signupVendorAjax(request):
    template_name = 'app/auth/signup.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        company_name = request.POST.get('company_name')
        company_regisration_number = request.POST.get('company_regisration_number')
        company_username = request.POST.get('company_username')
        agree = request.POST.get('agree')
        company_document = request.FILES.get('company_document')
        mobile = request.POST.get('mobile')
        data = User.objects.filter(email = request.POST.get('email'))
        data1 = User.objects.filter(mobile = request.POST.get('mobile'))
        if not company_name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Company Name field must be entered.",
                },
                status=404,
            )
        if not company_regisration_number:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Registration Number field must be entered.",
                },
                status=404,
            )
        if not company_username:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Company Username field must be entered.",
                },
                status=404,
            )
        if not company_document:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Company Document field must be upload.",
                },
                status=404,
            )
        if not email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Email field must be entered.",
                },
                status=404,
            )
        if '@' and '.' not in email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Please enter valid Email Address",
                },
                status=404,
            )
        if mobile.startswith('-', 0):
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Mobile field must be only number.",
                },
                status=404,
            )
        if not (len(mobile) >= 10 and len(mobile) <= 12):
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Mobile field must be 10-12 number.",
                },
                status=404,
            )
        if data1:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Mobile field must be unique.",
                },
                status=404,
            )
        if not password:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Password field must be entered.",
                },
                status=404,
            )
        if not agree:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Please click on Terms & Condition!",
                },
                status=404,
            )
        if not data:
            user, created = User.objects.get_or_create(email=email, password=password, company_name=company_name, company_username=company_username, mobile=mobile, company_regisration_number=company_regisration_number, company_document=company_document, user_type='VENDOR')
            customer_data = stripe.Customer.create(
                name=user.company_username,
                email=user.email,
                phone=user.mobile,
            )
            user.customer_id = customer_data['id']
            user.set_password(user.password)
            user.save()
            slug = user.slug
            sendOTP(user)
            return JsonResponse(
                {
                    "status": "success",
                    "message": "You have Successfully Registerd!",
                    "slug": slug
                },
                status=200,
            )
        else:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "This email address is already exists!",
                },
                status=404,
            )
    return render(request, template_name, {'roll':USER_TYPE, 'social':social})

#add user and vendor view function
def registerUser(request):
    template_name = 'frontend/auth/signup.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        mobile = request.POST.get('mobile')
        user_type = request.POST.get('user_type')
        data = User.objects.filter(email = request.POST.get('email'))
        if not data:
            user, created = User.objects.get_or_create(email=email, password=password, first_name=first_name, last_name=last_name, mobile=mobile, user_type=user_type)
            customer_data = stripe.Customer.create(
                name=user.first_name +' '+user.last_name,
                email=user.email,
                phone=user.mobile,
            )
            user.customer_id = customer_data['id']
            user.set_password(user.password)
            user.save()
            sendOTP(user)
            messages.success(request, "You have Successfully Registerd!")
            return redirect('/admin/verify/'+str(user.slug)+'/')
        else:
            messages.error(request, "This email address is already exists!")
    return render(request, template_name,{'roll':USER_TYPE, 'social':social})

#users login view function and need to modify when UI is avialable
def loginUser(request):
    template_name = 'user-login.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            customer = User.objects.get(email=email)
            if customer:
                if not customer.check_password(password):
                    messages.error(request, "Invalid Password")
                    return redirect('login-user')
                messages.success(request, "Login")
                return redirect('dashboard')
            elif customer is None:
                messages.error(request, "User not found")
                return redirect('login-user')
        except:
            messages.error(request, "User not found")
            return redirect('login-user')
    return render(request, template_name, {'social':social})



def verifyUser(request, slug):
    social = SocialIcon.objects.all()
    template_name = 'app/auth/verification.html'
    try:
        user = User.objects.get(slug=slug)
        if request.method == 'POST':
            otp1 = request.POST.get('otp1')
            otp2 = request.POST.get('otp2')
            otp3 = request.POST.get('otp3')
            otp4 = request.POST.get('otp4')
            if not otp1:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('verify-otp', str(user.slug))
            if not otp2:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('verify-otp', str(user.slug))
            if not otp3:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('verify-otp', str(user.slug))
            if not otp4:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('verify-otp', str(user.slug))
            otp = otp1 + otp2 + otp3 + otp4
            
            if user.otp == otp:
                user.is_verified = True
                if user.user_type == 'USER':
                    user.is_active = True
                    user.save()
                    sendWelcomeMailUser(user)
                if user.user_type == 'VENDOR':
                    user.is_active = False
                    user.save()
                    sendWelcomeMailVendor(user)
                messages.success(request, 'Email Verification Complete.')
                return redirect('signin')
            else:
                messages.error(request, 'OTP does not match!')
                return redirect('verify-otp', str(user.slug))
        else:
            return render(request, template_name, {'social':social, 'slug':slug})
    except:
        messages.error(request, "Something went wrong")
        return render(request, template_name, {'social':social})



def forgetPassword1(request):
    template_name = 'app/auth/forgot-password.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            messages.error(request, "Please enter email address.")
            return redirect('forget-password1')
        try:
            user = User.objects.get(email=email)
            if user:
                if user.user_type == 'USER':
                    sendForgetPassOTPUser(user)
                    messages.success(request, "Please Check registerd Email Address!")
                    return redirect('/forget-password/step2/'+str(user.slug)+'/')

                if user.user_type == 'VENDOR':
                    if user.is_active == True:
                        sendForgetPassOTPUser(user)
                        messages.success(request, "Please Check registerd Email Address!")
                        return redirect('/forget-password/step2/'+str(user.slug)+'/')
                    else:
                        messages.success(request, "Your account still inactive. Please contact to the Admin.")
                        return redirect('/forget-password/step1/'+str(user.slug)+'/')
                else:
                    messages.error(request, "You have not registered yet.")
                    return redirect('forget-password1')
            else:
                messages.error(request, "Your email address not found in our database.")
                return redirect('forget-password1')
        except:
            messages.error(request, "Your email address not found in our database.")
            return redirect('forget-password1')
    return render(request, template_name, {'social':social})

def forgetResendOtp(request, slug):
    user = User.objects.get(slug=slug)
    sendForgetPassOTPUser(user)
    messages.success(request, "Please Check registerd Email Address!")
    return redirect('/forget-password/step2/'+str(user.slug)+'/')

def resendOtp(request, slug):
    user = User.objects.get(slug=slug)
    sendOTP(user)
    messages.success(request, "Please Check registerd Email Address!")
    return redirect('/verify/'+str(user.slug)+'/')

def forgetPassword2(request, slug):
    template_name = 'app/auth/forget-password-otp.html'
    social = SocialIcon.objects.all()
    # user = request.user
    user = User.objects.get(slug=slug)
    try:
        if request.method == 'POST':
            otp1 = request.POST.get('otp1')
            otp2 = request.POST.get('otp2')
            otp3 = request.POST.get('otp3')
            otp4 = request.POST.get('otp4')
            if not otp1:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('/forget-password/step2/' + str(slug))
            if not otp2:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('/forget-password/step2/'+ str(slug))
            if not otp3:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('/forget-password/step2/'+ str(slug))
            if not otp4:
                messages.error(request, 'Please Enter OTP first.')
                return redirect('/forget-password/step2/'+ str(slug))
            otp = otp1+otp2+otp3+otp4
            
            if user:
                if user.otp != otp:
                    messages.error(request, 'OTP does not match!')
                    return redirect('/forget-password/step2/'+ str(slug))
                else:
                    messages.success(request, "OTP successfully matched!")
                    return redirect('/forget-password/step3/'+str(user.slug)+'/')
            else:
                messages.error(request, "Your email address not found in our database.")
                return redirect('/forget-password/step2/'+ str(slug))
        else:
            return render(request, template_name, {'social':social,'slug':slug})
    except:
        messages.error(request, "Something went wrong")
        return render(request, template_name, {'social':social})


def forgetPassword3(request, slug):
    template_name = 'app/reset-password.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        if not new_password:
            messages.error(request, 'Please Enter New Password.')
            return redirect('/forget-password/step3/'+str(slug)+'/')
        if not confirm_password:
            messages.error(request, 'Please Enter Confirm Password.')
            return redirect('/forget-password/step3/'+str(slug)+'/')
        try:
            user = User.objects.get(slug=slug)
            if user:
                if new_password == confirm_password:  
                    user.set_password(confirm_password)
                    user.save()
                    messages.success(request,  "Password is successfully changed.!")
                    return redirect('signin')
                else:
                    messages.error(request, 'password does matched.')
                    return redirect('/forget-password/step3/'+str(user.slug)+'/')
            else:
                messages.error(request, "Permission Denied!")
                return redirect('/forget-password/step3/'+str(user.slug)+'/')
        except:
            messages.error(request, "Something went wrong!")
            return redirect('/forget-password/step3/'+str(user.slug)+'/')
    return render(request, template_name, {'social':social})

@login_required
def followerUserListView(request):
    template_name = 'app/follower-management/followers.html'
    social = SocialIcon.objects.all()
    follow_user = FollowUser.objects.filter(follow_user_id=request.user.id, req_status=0, follow=1)
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        if user_id :
            data = FollowUser.objects.get(id=user_id)
            data.delete()
    follow_request = FollowUser.objects.filter(follow_user_id=request.user.id, req_status=1)
    
    return render(request, template_name, {'follow_user': follow_user, 'follow_request':follow_request, 'social':social})

@login_required
def followerReqAccept(request, slug):
    req_accept = FollowUser.objects.get(slug=slug)
    req_accept.follow=True
    req_accept.req_status=False
    req_accept.save()
    return redirect('follow_user')
    

@login_required
def followerRequestListView(request):
    template_name = 'app/follower-management/follow-req.html'
    social = SocialIcon.objects.all()
    follow_user = FollowUser.objects.filter(follow_user_id=request.user.id, req_status=1)
    return render(request, template_name, {'follow_user': follow_user, 'social':social})

@login_required
def followingUserListView(request):
    template_name = 'app/follower-management/following.html'
    social = SocialIcon.objects.all()
    following_user = FollowUser.objects.filter(user_email_id=request.user.id, follow=1)
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        if user_id :
            data = FollowUser.objects.get(id=user_id)
            data.delete()
    return render(request, template_name, {'following_user': following_user, 'social':social})

@login_required
def favouriteUserDelete(request,id):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        post_id = request.POST.get('post_id')
        goal_id = request.POST.get('goal_id')
        if user_id :
            data = FavouriteUser.objects.get(id=user_id)
            data.delete()
        if post_id :
            postdata=FavouritePost.objects.get(id=post_id)
            postdata.delete()
        if goal_id :
            goaldata=FavouriteGoal.objects.get(id=goal_id)
            goaldata.delete()                    
        else:
            pass
    return redirect('favourite_user')
  

@login_required
def favouriteUserListView(request):
    template_name = 'app/favourite-user-management/favorites-users.html'
    social = SocialIcon.objects.all()
    favourite_user = FavouriteUser.objects.filter(user_id=request.user.id, favourite=1).order_by('-id')
    favourite_goal = FavouriteGoal.objects.filter(user_id=request.user.id, favourite=1).order_by('-id')
    favourite_post = FavouritePost.objects.filter(user_id=request.user.id, favourite=1).order_by('-id')
    return render(request, template_name, {'favourite_user': favourite_user, 'favourite_goal':favourite_goal, 'favourite_post':favourite_post, 'social':social})




@login_required
def editQuestion(request, id):
    template_name = 'app/goal-management/edit-question.html'
    social = SocialIcon.objects.all()
    goal_question=GroupQuestion.objects.filter(group_id=id)
    goal_question_count = goal_question.count()
    editgoal=request.session['goaledit_data']
    if request.method == 'POST':
        if GroupQuestion.objects.filter(group_id = id).exists():
            GroupQuestion.objects.filter(group_id = id).delete()
        count_q = request.POST.get('input_count_q')
        x = 1
        while x <= int(count_q):
            quest_name = f'que{x}Input'
            ans_name = f'answer{x}'
            questions = request.POST.get(quest_name)
            answers = request.POST.get(ans_name)
            GroupQuestion.objects.create(questions=questions, answer=answers, group_id = id)
            x += 1
        editgoalusers = UserGoal.objects.filter(id=id).update(goal_name=editgoal.get('goal_name'), goal_desc=editgoal.get('goal_desc'))
        goal=UserGoal.objects.get(id=id)
        if goal.goal_type == 'GROUP':
            messages.success(request, 'Goal successfully update')
            return redirect('group_goal_list')
        else:
            messages.success(request, 'Goal successfully update')
            return redirect('goal_lists')

    return render(request, template_name, {'goal_question_count': goal_question_count, 'social':social, 'goal_question':goal_question})


@login_required
def editUserList(request, slug):
    template_name = 'app/goal-management/edit-user-list.html'
    social = SocialIcon.objects.all()
    user_goal=UserGoal.objects.get(slug=slug)
    user = GoalMember.objects.filter(goal_id=user_goal.id).exclude(members_id=request.user.id)
    if request.method == 'POST':
        follow_user = request.POST.get('user_id')
        if GoalMember.objects.filter(members_id=follow_user, goal_id=user_goal.id, owner_id=request.user.id).exists():
            # messages.error(request,"allready followed")
            # delete_members=GoalMember.objects.get(members_id=follow_user, goal_id=user_goal.id, owner_id=request.user.id).delete()
            # if delete_members:
            detelechat=ChatGroup.objects.get(goal_id=user_goal.id, owner=request.user.id)
            ret=detelechat.members
            
            # for i in ret:            
            return redirect("edit_user_list", slug)

    return render(request, template_name, {'social':social, 'user':user})



@login_required
def editGoal(request, slug):
    template_name = 'app/goal-management/edit-goal.html'
    social = SocialIcon.objects.all()
    goal=UserGoal.objects.get(slug=slug)
    if request.method == 'POST':
        data=request.POST
        goal_name = request.POST.get('goal_name')
        goal_desc = request.POST.get('goal_desc')
        if goal_name == '':
            messages.error(request, 'Goal name not be blank.')
            return render(request, template_name, {'data':data})
        if goal_desc == '':
            messages.error(request, 'Shortdescription not be blank.')
            return render(request, template_name, {'data':data})
        request.session['goaledit_data']= data    
        return redirect('edit_question', str(goal.id))
    return render(request, template_name, {'social':social, 'goal':goal})
    

@login_required
def createGoal(request):
    template_name = 'app/goal-management/create-goal.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        data=request.POST
        print(data, '---------------------------')
        product_id = request.POST.get('product_id')
        goal_name = request.POST.get('goal_name')
        goal_as = request.POST.get('goal_as')
        priority = request.POST.get('goal_priority')
        goal_type = request.POST.get('goal_type')
        start_date = request.POST.get('start_date')
        amount = request.POST.get('goal_amount')
        goal_desc = request.POST.get('goal_desc')
        
        if goal_name == '' or goal_name == None:
            messages.error(request, 'Goal name not be blank.')
            return render(request, template_name, {'data':data})
        if goal_desc == '' or goal_desc == None:
            messages.error(request, 'Shortdescription not be blank.')
            return render(request, template_name, {'data':data})
        if priority == '' or priority == None:
            messages.error(request, 'Priority not be blank.')
            return render(request, template_name, {'data':data})
        if goal_type == '' or goal_type == None:
            messages.error(request, 'Goal type not be blank.')
            return render(request, template_name, {'data':data})
        if start_date == '' or start_date == None:
            messages.error(request, 'Start date not be blank.')
            return render(request, template_name, {'data':data})
        if amount == '' or amount == None:
            messages.error(request, 'Amount not be blank.')
            return render(request, template_name, {'data':data})
         
        if goal_type == 'INDIVIDUAL':
            request.session['goalcreate_data']= data
            return redirect('user_queston')
        else:
            request.session['goalcreate_data']= data
            return redirect('user_list')

    return render(request, template_name, {'social':social, })
    
@login_required
def userList(request):
    template_name = 'app/goal-management/user-list.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        follow_user = request.POST.get('user_id')
        if int(follow_user) in request.session["select_follow_user"]:
            follow_user_list = request.session["select_follow_user"]
            follow_user_list.remove(int(follow_user))
            request.session["select_follow_user"] = follow_user_list
            request.session.modified = True
        else:
            prod = request.session["select_follow_user"]
            prod.append(int(follow_user))   
            request.session["select_follow_user"] = prod 
       
    else:
        request.session["select_follow_user"] = []
   
    users = User.objects.filter(user_type='USER', is_active=1, is_verified=1).exclude(id=request.user.id).order_by('-id')
    p = Paginator(users, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    
   
    return render(request, template_name, {'users': page_obj, 'social':social, 'requested': request.session["select_follow_user"]})

@login_required
def adminUser(request):
    template_name = 'app/goal-management/admin-user.html'
    social = SocialIcon.objects.all()
    goal_details=request.session['goalcreate_data']
    if 'select_follow_user' in request.session:
        follow_user_ids = request.session['select_follow_user']
        users = User.objects.filter(id__in=follow_user_ids)
    if request.method == 'POST':
        admin_user = request.POST.get('user_id')
        if int(admin_user) in request.session["select_admin_user"]:
            admin_user_list = request.session["select_admin_user"]
            admin_user_list.remove(int(admin_user))
            request.session["select_admin_user"] = admin_user_list
            request.session.modified = True
        else:
            prods = request.session["select_admin_user"]
            prods.append(int(admin_user))
            request.session["select_admin_user"] = prods  
        return render(request, template_name, {'users':users, 'requested':request.session["select_admin_user"] })
    
    return render(request, template_name, {'users':users})

@login_required
def userQueston(request):
    template_name = 'app/goal-management/question-user.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        data=request.POST
        question1 = request.POST.get('que1Input')
        question2 = request.POST.get('que2Input')
        answer1  = request.POST.get('question1')
        answer2 = request.POST.get('question2')
        if answer1 == '':
            messages.error(request, 'answer not be blank.')
            return render(request, template_name, {'data':data})
        if answer2 == '':
            messages.error(request, 'answer not be blank.')
            return render(request, template_name, {'data':data})    
        request.session['question_data']= data
        return redirect('payment_plan')
    return render(request, template_name, {'social':social})

@login_required
def paymentPlan(request):
    # try:
        template_name = 'app/goal-management/payment-plan.html'
        social = SocialIcon.objects.all()
        goal_data=request.session['goalcreate_data']    
        print(goal_data, '-----------')
        follow=request.session["select_follow_user"]
        follow.append(request.user.id)
        follow_count=len(follow)
        admin_user=request.session["select_admin_user"]
        admin_user.append(request.user.id)
        questions=request.session['question_data']
        if request.method == "POST":
            payment_value = request.POST.get('payment_value')
            if payment_value == '':
                messages.error(request, 'Please select payment plan.')
                return render(request, template_name, {'social':social})
            if goal_data.get('product_id'):
                print('=====================')
                users = UserGoal.objects.create(goal_name=goal_data.get('goal_name'), goal_as=goal_data.get('goal_as'), goal_priority=goal_data.get('goal_priority'), start_date=goal_data.get('start_date'), goal_amount=goal_data.get('goal_amount'), goal_desc=goal_data.get('goal_desc'), payment_plan_id=payment_value, goal_type=goal_data.get('goal_type'), total_members=follow_count, user_id=request.user.id, product_id=goal_data.get('product_id'))
                for i in follow:
                    members=GoalMember.objects.create(goal_id=users.id, members_id=i, owner_id=request.user.id, approve=0, request=1)
                    if members:
                        members=GoalMember.objects.filter(goal_id=users.id, members_id=request.user.id, owner_id=request.user.id).update(approve=1, request=0)
                for j in admin_user:
                    admin=GoalGroupAdmin.objects.create(group_goal_id=users.id, user_id=j, approve=0)
                    
                    if admin:
                        admin=GoalGroupAdmin.objects.filter(group_goal_id=users.id, user_id=request.user.id).update(approve=1)
                
                qus_ans1=GroupQuestion.objects.create(questions=questions.get('que1Input'), answer=questions.get('question1'), group_id=users.id)
                
                qus_ans2=GroupQuestion.objects.create(questions=questions.get('que2Input'), answer=questions.get('question2'), group_id=users.id)
                chat_create = ChatGroup.objects.get_or_create(group_name=goal_data.get('goal_name'), goal_id=users.id, members=follow,  owner=request.user.id, room_id=random_with_N_digits(12))
                try:
                    goal_order = GoalOrder.objects.all()
                except:
                    goal_order = None
                if goal_order:
                    order_id_previous = GoalOrder.objects.latest('id')
                    
                    generate_order_id = int(order_id_previous.order_id)+1    
                    goal_order = GoalOrder.objects.create(goal_id=users.id, user_id=request.user.id, product_id=goal_data.get('product_id'),
                    status='PENDING', order_id=generate_order_id)
                    goal_order.save()
                    if goal_data.get('goal_type') == 'GROUP': 
                        return redirect('group_goal_list')
                    else:
                        return redirect('goal_lists')
                else:
                    goal_order = GoalOrder.objects.create(goal_id=users.id, user_id=request.user.id, product_id=goal_data.get('product_id'),
                    status='PENDING', order_id=1000)
                    goal_order.save()
                    if goal_data.get('goal_type') == 'GROUP': 
                        return redirect('group_goal_list')
                    else:
                        return redirect('goal_lists')
            else:
                users = UserGoal.objects.create(goal_name=goal_data.get('goal_name'), goal_as=goal_data.get('goal_as'), goal_priority=goal_data.get('goal_priority'), start_date=goal_data.get('start_date'), goal_amount=goal_data.get('goal_amount'), goal_desc=goal_data.get('goal_desc'), payment_plan_id=payment_value, goal_type=goal_data.get('goal_type'), total_members=follow_count, user_id=request.user.id)
                chat_create = ChatGroup.objects.get_or_create(group_name=goal_data.get('goal_name'), goal_id=users.id, members=follow,  owner=request.user.id, room_id=random_with_N_digits(12))
                for i in follow:
                    members=GoalMember.objects.create(goal_id=users.id, members_id=i, owner_id=request.user.id, approve=0, request=1)
                    if members:
                        members=GoalMember.objects.filter(goal_id=users.id, members_id=request.user.id, owner_id=request.user.id).update(approve=1, request=0)
                for j in admin_user:
                    admin=GoalGroupAdmin.objects.create(group_goal_id=users.id, user_id=j, approve=0)
                    
                    if admin:
                        admin=GoalGroupAdmin.objects.filter(group_goal_id=users.id, user_id=request.user.id).update(approve=1)
                
                qus_ans1=GroupQuestion.objects.create(questions=questions.get('que1Input'), answer=questions.get('question1'), group_id=users.id)
                
                qus_ans2=GroupQuestion.objects.create(questions=questions.get('que2Input'), answer=questions.get('question2'), group_id=users.id)        
                if goal_data.get('goal_type') == 'GROUP':
                    messages.success(request, 'Goal successfully created')
                    return redirect('group_goal_list')
                else:
                    messages.success(request, 'Goal successfully created')
                    return redirect('goal_lists')        
    # except:
    #     messages.error(request, 'Something went wrong')
    #     return redirect('group_goal_list')
                  
        return render(request, template_name, {'social':social}) 

@login_required
def goalListView(request):
    template_name = 'app/goal-management/goal.html'
    social = SocialIcon.objects.all()
    goal = UserGoal.objects.filter(user_id=request.user.id, goal_type='INDIVIDUAL').order_by('-id')
    goal_member = GoalMember.objects.filter(members_id=request.user.id, approve=1)
    goalm = GoalMember.objects.filter(members_id=request.user.id, approve=0)
    goal_owner = GoalMember.objects.filter(members_id=request.user.id, owner=request.user.id)
    p = Paginator(goal, 6)
    page_number = request.GET.get('page')
    request.session['goal_as'] = 'goallist'
    request.session.modified = True
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'goal': page_obj, 'social':social, 'goal_member':goal_member, 'goal_owner':goal_owner, 'goalm':goalm})

@login_required
def goalReqAccept(request):
    
    if request.method == "POST":
        data=request.POST
        reaccept=request.POST.get('req_accept')
        raccept=request.POST.get('re_accept')
        card=PaymentToken.objects.filter(user_id=reaccept, default_payment=1)    
        if card:
            req_accept = GoalMember.objects.get(members_id=reaccept, goal_id=raccept)
            req_accept.approve=True
            req_accept.request=False
            req_accept.save()
            if GoalGroupAdmin.objects.filter(user_id=reaccept, group_goal_id=raccept).exists():
                re_accept = GoalGroupAdmin.objects.get(user_id=reaccept, group_goal_id=raccept)
                re_accept.approve=True
                re_accept.request=False
                re_accept.save()
        else:
            messages.error(request,"Please add card.")
            return redirect('user_payment_card')
    return redirect('group_goal_list')


def DeletegoalReq(request):
    if request.method == "POST":
        data=request.POST
        reaccept=request.POST.get('members_id')
        raccept=request.POST.get('goal_id')
        req_accept = GoalMember.objects.get(members_id=reaccept, goal_id=raccept)
        req_accept.delete()
        re_accept = GoalGroupAdmin.objects.get(user_id=reaccept, group_goal_id=raccept)
        re_accept.delete()
        return JsonResponse({'status':'success','message':'request delete successfully'})
        
def make_paginator(object, page_number):
    p = Paginator(object, 6)
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return page_obj

@login_required
def groupGoalListView(request):
    template_name = 'app/goal-management/group-management.html'
    social = SocialIcon.objects.all()
    goal = UserGoal.objects.filter(user_id=request.user.id, goal_type='GROUP').order_by('-id')
    goal_member = GoalMember.objects.filter(members_id=request.user.id, approve=1).exclude(owner_id=request.user.id)
    goalm = GoalMember.objects.filter(members_id=request.user.id, request=1, approve=0)
    goal_owner = GoalMember.objects.filter(members_id=request.user.id, owner=request.user.id)
    currntdate = datetime.now().date()
    goal_request = GoalMember.objects.filter( sentrequest=1, approve=0)
    goal_req = []
    for i in goal_request:
        goal_requests = GoalMember.objects.filter( sentrequest=1, approve=0, owner_id=i.owner_id)
        goal_req.append(goal_requests)
        return render(request, template_name, {'goal': goal, 'social':social, 'goal_member':goal_member, 'goalm':goalm, 'goal_req':goal_req, 'goal_requests':goal_requests, 'goal_request':goal_request, 'goal_owner':goal_owner, 'currntdate':currntdate})
    page_number = request.GET.get('page')
    page_goal_owner = request.GET.get('page_goal_owner')
    page_goalm = request.GET.get('page_goalm')
    page_goal_request = request.GET.get('page_goal_request')
    page_obj = make_paginator(goal_member, page_number)
    page_obj_goal_owner = make_paginator(goal_owner, page_goal_owner)
    page_obj_goalm = make_paginator(goalm, page_goalm)
    page_obj_goal_request = make_paginator(goalm, page_goal_request)
    request.session['goal_as'] = 'groupgoallist'
    request.session.modified = True
    return render(request, template_name, {'goal': goal, 'social':social, 'goal_member':page_obj, 'goalm':page_obj_goalm, 'goal_req':goal_req,  'goal_request':page_obj_goal_request, 'goal_owner':page_obj_goal_owner, 'currntdate':currntdate})

@login_required
def sentGoalReqAccept(request):
    
    if request.method == "POST":
        data=request.POST
        reaccept=request.POST.get('req_accept')
        raccept=request.POST.get('re_accept')
        card=PaymentToken.objects.filter(user_id=reaccept, default_payment=1)    
        if card:
            req_accept = GoalMember.objects.get(members_id=reaccept, goal_id=raccept)
            req_accept.approve=True
            req_accept.sentrequest=False
            req_accept.save()
            if GoalGroupAdmin.objects.filter(user_id=reaccept, group_goal_id=raccept).exists():
                re_accept = GoalGroupAdmin.objects.get(user_id=reaccept, group_goal_id=raccept)
                re_accept.approve=True
                re_accept.sentrequest=False
                re_accept.save()
        else:
            messages.error(request,"Please add card.")
            return redirect('user_payment_card')
    return redirect('group_goal_list')

@login_required
def postListView(request):
    template_name = 'app/post-management/post-management.html'
    social = SocialIcon.objects.all()
    post = PostUser.objects.filter(user_id=request.user.id).order_by('-id')
    return render(request, template_name, {'post': post, 'social':social})

@login_required
def postCreateView(request):
    template_name = 'app/post-management/create-post.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        data=request.POST
        title = request.POST.get('title')
        desc = request.POST.get('desc')
        youtube_id = request.POST.get('youtube_id')
        image = request.FILES.get('image')
        if title == '':
            messages.error(request, 'Title must be valid not be blank.')
            return render(request, template_name, {'data':data})
        if desc.isspace() or desc == '':
            messages.error(request, 'Shortdescription must be valid not be blank.')
            return render(request, template_name, {'data':data})     
        postcreate=PostUser.objects.create(user_id=request.user.id, title=title, youtube_id=youtube_id, image=image, desc=desc)
        postcreate.save()
        messages.success(request, 'Add successfully.')
        return redirect('post_lists')
    return render(request, template_name, {'social':social})

@login_required
def allUserListView(request):
    template_name = 'app/all-users.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST':
        follow_user = request.POST.get('user_id')
        if FollowUser.objects.filter(follow_user_id=follow_user, user_email_id=request.user.id).exists():

            FollowUser.objects.get(follow_user_id=follow_user, user_email_id=request.user.id).delete()
            return redirect("all_users")
        else:
            FollowUser.objects.create(follow_user_id = follow_user, user_email_id=request.user.id, req_status=1)
            return redirect("all_users")
    requested = FollowUser.objects.filter(user_email_id=request.user.id, req_status=True).values_list('follow_user_id', flat=True)
    following = FollowUser.objects.filter(user_email_id=request.user.id, follow=True).values_list('follow_user_id', flat=True)
    users = User.objects.filter(user_type='USER', is_active=1, is_verified=1).exclude(id=request.user.id).order_by('-id')
    p = Paginator(users, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    
    return render(request, template_name, {'users': page_obj, 'social':social, 'requested': requested, 'following': following})

@login_required
def locationUpdate(request):
    if request.method == 'POST':
        location = User.objects.get(id=request.user.id)
        if location.location_settings == 1:
            location.location_settings = 0
            location.save()
            return JsonResponse(
                    {
                        "status": "success",
                        "message": "Location update successfully.",
                    },
                    status=200,
            )
        else:
            location.location_settings = 1
            location.save()
            return JsonResponse(
                    {
                        "status": "success",
                        "message": "Location update successfully.",
                    },
                    status=200,
            )   
    messages.error(request, 'Something went wrong!')
    return redirect('profile')  

@login_required
def notificationUpdate(request):
    if request.method == 'POST':
        notification = User.objects.get(id=request.user.id)
        if notification.notification_settings == 1:
            notification.notification_settings = 0
            notification.save()
            return JsonResponse(
                    {
                        "status": "success",
                        "message": "Notification update successfully.",
                    },
                    status=200,
            )
        else:
            notification.notification_settings = 1
            notification.save()
            return JsonResponse(
                    {
                        "status": "success",
                        "message": "Notification update successfully.",
                    },
                    status=200,
            )    
    messages.error(request, 'Something went wrong!')
    return redirect('profile')  


@login_required
def userFollow(request, slug):
    user = User.objects.get(slug=slug)
    if not FollowUser.objects.filter(user_email_id=request.user.id, follow_user_id=user.id).exists():
        dr=FollowUser.objects.create(user_email_id=request.user.id, follow_user_id=user.id, req_status=True)
    else:
        FollowUser.objects.filter(user_email_id=request.user.id, follow_user_id=user.id).delete()
    return redirect('user_details', slug)

@login_required
def userFavourute(request, slug):
    user = User.objects.get(slug=slug)
    if not FavouriteUser.objects.filter(user_id=request.user.id, fav_user_id=user.id).exists():
        FavouriteUser.objects.create(user_id=request.user.id, fav_user_id=user.id, favourite=True)
    else:
        FavouriteUser.objects.filter(user_id=request.user.id, fav_user_id=user.id).delete()
    return redirect('user_details', slug)

@login_required
def userFavourutePost(request, slug):
    post_detail = PostUser.objects.get(slug=slug)

    if not FavouritePost.objects.filter(user_id=request.user.id, fav_post_id=post_detail.id).exists():
        FavouritePost.objects.create(user_id=request.user.id, fav_post_id=post_detail.id, favourite=True)
    else:
        FavouritePost.objects.filter(user_id=request.user.id, fav_post_id=post_detail.id).delete()
    return redirect('user_post_detail', str(slug))

@login_required
def postLike(request, slug):
    post_detail = PostUser.objects.get(slug=slug)
    
    if not PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).exists():
        
        PostLikeDislike.objects.create(user_id=request.user.id, post_id=post_detail.id,post_like=1)

    elif PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id,post_dislike=1).exists():
        PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).update(post_like=1, post_dislike=0)
    else:    
        PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).delete()
    return redirect('user_post_detail', str(slug))

@login_required
def postDislike(request, slug):
    post_detail = PostUser.objects.get(slug=slug)
    if PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id,post_like=1).exists():
        PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).update(post_like=0, post_dislike=1)
    elif not PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).exists():
        PostLikeDislike.objects.create(user_id=request.user.id, post_id=post_detail.id,post_dislike=1)
    else:
        PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id,post_dislike=1).delete()
    return redirect('user_post_detail', str(slug))

from datetime import datetime
@login_required
def userPostDetail(request, slug):
    template_name = 'app/user-post-details.html'
    social = SocialIcon.objects.all()
    post_detail = PostUser.objects.get(slug=slug)
    if not PostViewCount.objects.filter(post_id=post_detail.id, user_id=request.user.id).exists():
        PostViewCount.objects.create(post_id=post_detail.id, user_id=request.user.id, post_view=1)
    if FavouritePost.objects.filter(fav_post_id=post_detail.id, user_id=request.user.id).exists():
        fav_post = FavouritePost.objects.get(fav_post_id=post_detail.id, user_id=request.user.id)
    else:
        fav_post = None
    if PostLikeDislike.objects.filter(post_id=post_detail.id, user_id=request.user.id).exists():
        like_post = PostLikeDislike.objects.get(post_id=post_detail.id, user_id=request.user.id)
    else:
        like_post = None
    # dates in string format
    str_d1 = post_detail.created.date()
    str_d2 = datetime.now().date()
    # convert string to date object
    d1 = datetime.strptime(str(str_d1), "%Y-%m-%d")
    d2 = datetime.strptime(str(str_d2), "%Y-%m-%d")
    # difference between dates in timedelta
    delta = d2 - d1
    post_like = PostLikeDislike.objects.filter(post_id=post_detail.id, post_like=1).count()
    post_dislike = PostLikeDislike.objects.filter(post_id=post_detail.id, post_dislike=1).count()        
    post_count = PostViewCount.objects.filter(post_id=post_detail.id).count()
    return render(request, template_name,{'social':social, 'post_count':post_count, 'post_detail':post_detail, 'fav_post':fav_post, 'like_post':like_post, 'delta':delta, 'post_like':post_like, 'post_dislike':post_dislike   })

@login_required
def userGoal(request, slug):
    template_name = 'app/goal-management/user-goals.html'
    social = SocialIcon.objects.all()
    user = User.objects.get(slug=slug)
    user_goal = UserGoal.objects.filter(user_id=user.id, goal_type='INDIVIDUAL')
    p = Paginator(user_goal, 6)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'social':social, 'user_goal':page_obj})

@login_required
def userGroupGoal(request, slug):
    template_name = 'app/goal-management/user-group-goal.html'
    social = SocialIcon.objects.all()
    user = User.objects.get(slug=slug)
    user_group_goal = UserGoal.objects.filter(user_id=user.id, goal_type='GROUP')
    
    p = Paginator(user_group_goal, 6)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'social':social, 'user_group_goal':page_obj})

@login_required
def usersFavouruteGoal(request, slug):
    user_goal_detail = UserGoal.objects.get(slug=slug)
    if not FavouriteGoal.objects.filter(user_id=request.user.id, goal_id=user_goal_detail.id).exists():
        FavouriteGoal.objects.create(user_id=request.user.id, goal_id=user_goal_detail.id, favourite=True)
    else:
        FavouriteGoal.objects.filter(user_id=request.user.id, goal_id=user_goal_detail.id).delete()
    return redirect('user_group_goal_detail', str(slug))

@login_required
def userGroupGoalDetail(request, slug):
    
    template_name = 'app/goal-management/list-details-group.html'
    social = SocialIcon.objects.all()
    group_goal_detail = UserGoal.objects.get(slug=slug)
    created_date=group_goal_detail.start_date.date()
    currntdate = datetime.now().date()
    goal_amount = GoalDonation.objects.filter(goal_id=group_goal_detail.id).values('amount').aggregate(donation_amount=Sum('amount'))
    donation_amount = 0
    if goal_amount.get('donation_amount'):
        donation_amount = round(goal_amount.get('donation_amount'),2)
    
    
    if FavouriteGoal.objects.filter(goal_id=group_goal_detail.id, user_id=request.user.id).exists():
        fav_goal = FavouriteGoal.objects.get(goal_id=group_goal_detail.id, user_id=request.user.id)
    else:
        fav_goal = None
    if SubGoal.objects.filter(sub_goal_id=group_goal_detail.id).exists():
        sub_goal = SubGoal.objects.get(sub_goal_id=group_goal_detail.id)
    else:
        sub_goal = None
    member_count = GoalMember.objects.filter(goal_id=group_goal_detail.id, approve=1).count()
    check_member = GoalMember.objects.filter(goal_id=group_goal_detail.id,members_id=request.user.id)

    return render(request, template_name, {'social':social,'check_member':check_member, 'created_date':created_date,'currntdate':currntdate,'user':'user',  'group_goal_detail':group_goal_detail, 'fav_goal':fav_goal, 'sub_goal':sub_goal, 'member_count':member_count, 'donation_amount':donation_amount })

@login_required
def sentRequest(request, slug):
    goal_id=UserGoal.objects.get(slug=slug)
    if not GoalMember.objects.filter(goal_id=goal_id.id, members_id=request.user.id).exists():
        members=GoalMember.objects.create(goal_id=goal_id.id, members_id=request.user.id, owner_id=goal_id.user_id, approve=0, sentrequest=1) 
    return redirect('user_group_goal_detail', slug)
 
@login_required
def membersDeatils(request, slug):
    template_name = 'app/goal-management/group-board.html'
    group_goal_detail = UserGoal.objects.get(slug=slug)
    group_goals = GoalMember.objects.filter(goal_id=group_goal_detail.id, approve =1).order_by('-id')
    rating_stre =[]
    for i in group_goals:
        owner_name =User.objects.get(id=i.owner_id)
        goal_group = GoalMember.objects.filter(goal_id=group_goal_detail.id, approve =1).order_by('-id').exclude(members_id=request.user.id)
        comm=GoalComment.objects.filter(goal_id=i.goal_id).order_by('created')    
        avg_rating = User.objects.filter(id = i.members_id)   
        rating_stre.append(avg_rating)
    group_goal = GoalMember.objects.filter(goal_id=group_goal_detail.id, approve =1).count()
    goal_groupddd = GoalMember.objects.filter(goal_id=group_goal_detail.id, approve =1)
    
    return render(request, template_name, {'goal_group':goal_group, 'group_goals':group_goals, 'group_goal_detail':group_goal_detail, 'group_goal':group_goal, 'owner_name':owner_name, "comm":comm,'avg_rating':rating_stre})



@login_required
def userComment(request, slug):
    group_goal_detail = UserGoal.objects.get(slug=slug)
    if request.method == 'POST':
        com = request.POST.get('comment')
        coments=GoalComment.objects.create(user_id=request.user.id, goal_id=group_goal_detail.id, comment=com)
        coments.save()
    return redirect('members_deatils', str(slug))

@login_required
def userRating(request, id):
    user = User.objects.get(slug=id)
    return render('user_details')


@login_required
def userGoalDetail(request, slug):
    template_name = 'app/goal-management/list-details-goal.html'
    social = SocialIcon.objects.all()
    user_goal_detail = UserGoal.objects.get(slug=slug)
    if FavouriteGoal.objects.filter(goal_id=user_goal_detail.id, user_id=request.user.id).exists():
        fav_goal = FavouriteGoal.objects.get(goal_id=user_goal_detail.id, user_id=request.user.id)
    else:
        fav_goal = None
    if SubGoal.objects.filter(sub_goal_id=user_goal_detail.id).exists():
        sub_goal = SubGoal.objects.get(sub_goal_id=user_goal_detail.id)
    else:
        sub_goal = None
    return render(request, template_name, {'social':social, 'user':'user',  'user_goal_detail':user_goal_detail, 'fav_goal':fav_goal, 'sub_goal':sub_goal})

@login_required
def userRating(request):
    userIdList = []

    if request.method == "POST":
        id = request.POST.get('user_id')
        user_data = User.objects.get(id=id)
        userIdList.append(id)
        return JsonResponse({'status':'success','user_id':id,  'user_name':(user_data.first_name),'user_image':(user_data.profile_pic.url)})
    
    stre=RatingUser.objects.filter(rate_user_id=userIdList, user_id=request.user.id)
    
from django.db.models import Avg

@login_required
def userStarRating(request):
    total_avg_list = []
    if request.method == "POST":
        star_rating = request.POST.get('get_rating')
        user_id = request.POST.get('user_id')
        review_data = request.POST.get('review')
        goal_data = request.POST.get('goal_id')
        users=GoalMember.objects.filter(members_id=user_id)
        users1=GoalMember.objects.filter(members_id=user_id)
        if not RatingUser.objects.filter(rate_user_id=user_id, user_id=request.user.id):
            RatingUser.objects.create(rate_user_id=user_id, review=review_data, user_id=request.user.id, rating=star_rating)
        else:
            RatingUser.objects.filter(rate_user_id=user_id, user_id=request.user.id).update(review=review_data, rating=star_rating)
        total_user_count = RatingUser.objects.filter(rate_user_id=user_id).count()
        total_avg = RatingUser.objects.filter(rate_user_id=user_id, rating=star_rating)
        avg=RatingUser.objects.filter(rate_user_id=user_id).aggregate(avg_rating=Avg('rating'))
        gg=avg.values()
        for values in gg:
            user = User.objects.get(id=user_id)
            user.avg_rating = values
            user.save()
            total_avg_list.append(user_id) 
    mem_name =User.objects.get(id=total_avg_list[0])
    return JsonResponse({'status':'success','message':"submit rating succssfully"})

@login_required
def postUsertLike(request, slug):
    post_detail = PostUser.objects.get(slug=slug)
    if not PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).exists():
        PostLikeDislike.objects.create(user_id=request.user.id, post_id=post_detail.id,post_like=1)
    elif PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id,post_dislike=1).exists():
        PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).update(post_like=1, post_dislike=0)
    else:
        PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).delete()
    return redirect('user_details', str(post_detail.user.slug))


def postUserDislike(request, slug):
    post_detail = PostUser.objects.get(slug=slug)
    if PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id,post_like=1).exists():
        PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).update(post_like=0, post_dislike=1)
    elif not PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id).exists():
        PostLikeDislike.objects.create(user_id=request.user.id, post_id=post_detail.id,post_dislike=1)
    else:
         PostLikeDislike.objects.filter(user_id=request.user.id, post_id=post_detail.id,post_dislike=1).delete()
    return redirect('user_details', str(post_detail.user.slug))


@login_required
def userDetailsView(request, slug):
    template_name = 'app/user-details.html'
    try:
        social = SocialIcon.objects.all()
        user = User.objects.get(slug=slug)
        post_detail = PostUser.objects.filter(user_id=user.id)
        post_detail_ids = post_detail.values_list('id', flat=True)
        if FollowUser.objects.filter(follow_user_id=user.id, user_email_id=request.user.id).exists():
            follow_user = FollowUser.objects.get(follow_user_id=user.id, user_email_id=request.user.id)
        else:
            follow_user = None
        if FavouriteUser.objects.filter(fav_user_id=user.id, user_id=request.user.id).exists():
            fav_user = FavouriteUser.objects.get(fav_user_id=user.id, user_id=request.user.id)
        else:
            fav_user = None
       
        if PostLikeDislike.objects.filter(post_id__in=post_detail_ids, user_id=request.user.id).exists():
            like_posts = PostLikeDislike.objects.get(post_id__in=post_detail_ids, user_id=request.user.id)
        else:
            like_posts = None
        if PostLikeDislike.objects.filter(post_id__in=post_detail_ids, user_id=request.user.id).exists():
            dislike_posts = PostLikeDislike.objects.get(post_id__in=post_detail_ids, user_id=request.user.id)
        else:
            dislike_posts = None  
        user_count = RatingUser.objects.filter(rate_user_id=user.id).count()   
        goal_group = UserGoal.objects.filter(user_id=user.id, goal_type='GROUP').count()
        goal_user = UserGoal.objects.filter(user_id=user.id, goal_type='INDIVIDUAL').count()
        post_user = PostUser.objects.filter(user_id=user.id)
        post_user_ids = post_user.values_list('id', flat=True)
        post_like = PostLikeDislike.objects.filter(post_id__in=post_user_ids)
        post_id_list = post_like.values_list('post_id', flat=True)
        post_count = {}
        for i in post_user_ids:
            post_count[i] = []
            
            if i in post_id_list:
                post_count[i].append(post_like.filter(post_id=i, post_like=1).count())
                post_count[i].append(post_like.filter(post_id=i, post_dislike=1).count())
            else:
                post_count[i].append(0)
                post_count[i].append(0)
        review_count = RatingUser.objects.filter(rate_user_id=user.id).count()
        posts_like = PostLikeDislike.objects.filter(post_id__in=post_detail_ids, post_like=1).count()
        posts_dislike = PostLikeDislike.objects.filter(post_id__in=post_detail_ids, post_dislike=1).count()      
        view_count = PostViewCount.objects.filter(post_id__in=post_detail_ids).count()
        
        
        group_goal_detail = GoalMember.objects.filter(members_id=request.user.id ,approve=1)
        for i in group_goal_detail:
            aa = GoalMember.objects.filter(members_id=user.id ,approve=1,goal_id = i.goal_id)

        return render(request, template_name, {'user':user, 'user_count':user_count, 'fav_user':fav_user, 'follow_user':follow_user, 'social':social, 'post_user':post_user, 'post_count':post_count, 'goal_group':goal_group, 'goal_user':goal_user, 'post_detail':post_detail, 'view_count':view_count, 'posts_like':posts_like, 'dislike_posts':dislike_posts, 'like_posts':like_posts, 'review_count':review_count, 'posts_dislike':posts_dislike, 'aa':aa})
    except:
        user = User.objects.get(slug=slug)
        # post_detail = PostUser.objects.get(user_id=user.id)
        if FollowUser.objects.filter(follow_user_id=user.id, user_email_id=request.user.id).exists():
            follow_user = FollowUser.objects.get(follow_user_id=user.id, user_email_id=request.user.id)
        else:
            follow_user = None
        if FavouriteUser.objects.filter(fav_user_id=user.id, user_id=request.user.id).exists():
            fav_user = FavouriteUser.objects.get(fav_user_id=user.id, user_id=request.user.id)
        else:
            fav_user = None
            
        
        goal_group = UserGoal.objects.filter(user_id=user.id, goal_type='GROUP').count()
        goal_user = UserGoal.objects.filter(user_id=user.id, goal_type='INDIVIDUAL').count()
        post_user = PostUser.objects.filter(user_id=user.id)
        post_user_ids = post_user.values_list('id', flat=True)
        post_like = PostLikeDislike.objects.filter(post_id__in=post_user_ids)
        post_id_list = post_like.values_list('post_id', flat=True)
        post_count = {}
        for i in post_user_ids:
            post_count[i] = []
            if i in post_id_list:
                post_count[i].append(post_like.filter(post_id=i, post_like=1).count())
                post_count[i].append(post_like.filter(post_id=i, post_dislike=1).count())
            else:
                post_count[i].append(0)
                post_count[i].append(0)
                
        return render(request, template_name,{'user':user, 'fav_user':fav_user, 'follow_user':follow_user, 'social':social, 'post_user':post_user, 'post_detail':post_detail, 'post_count':post_count, 'goal_group':goal_group, 'goal_user':goal_user})

@login_required
def userFavouruteGoal(request, slug):
    goal = UserGoal.objects.get(slug=slug)
    if not FavouriteGoal.objects.filter(user_id=request.user.id, goal_id=goal.id).exists():
        FavouriteGoal.objects.create(user_id=request.user.id, goal_id=goal.id, favourite=True)
    else:
        FavouriteGoal.objects.filter(user_id=request.user.id, goal_id=goal.id).delete()
    return redirect('goal_details', str(slug))

@login_required
def goalDonate(request):
    template_name = 'app/goal-management/donate-fund.html'
    social = SocialIcon.objects.all()
    if request.method == 'POST': 
        id = request.user.id
        user_goal_slug = request.POST.get('user_goal_slug')
    return render(request, template_name, {'user_goal_slug': user_goal_slug, 'social':social, 'STRIPE_PUBLIC_KEY': settings.STRIPE_PUBLIC_KEY})

@login_required
def goalView(request, slug):
    template_name = 'app/goal-management/goal-management-posted-details.html'
    social = SocialIcon.objects.all()
    goal = UserGoal.objects.get(slug=slug)
    goa = User.objects.get(id=goal.user_id)
    goal_amount = GoalDonation.objects.filter(goal_id=goal.id).values('amount').aggregate(donation_amount=Sum('amount'))
    user_subscription_data = UserSubscription.objects.filter(user_id=request.user.id, goal_id=goal.id).first()
    donation_amount = 0
    goals=UserGoal.objects.filter(id=goal.id, user_id=request.user.id)
    currntdate = datetime.now().date()
    if goal_amount.get('donation_amount'):
        donation_amount = round(goal_amount.get('donation_amount'),2)

    if FavouriteGoal.objects.filter(goal_id=goal.id, user_id=request.user.id).exists():
        fav_goal = FavouriteGoal.objects.get(goal_id=goal.id, user_id=request.user.id)
    else:
        fav_goal = None
    if SubGoal.objects.filter(sub_goal_id=goal.id).exists():
        sub_goal = SubGoal.objects.get(sub_goal_id=goal.id)
    else:
        sub_goal = None
    return render(request, template_name, {'social':social, 'sub_goal':sub_goal, 'donation_amount': donation_amount, 'goal':goal, 'fav_goal':fav_goal, 'goals':goals, 'currntdate':currntdate, 'user_subscription_data':user_subscription_data})


@login_required
def goalDonateStripe(request):
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    domain = body['domain']
    stripe.api_key = settings.STRIPE_SECRET_KEY
    checkout_session = stripe.checkout.Session.create(
        customer=request.user.customer_id,
        payment_method_types=["card"],
        mode = 'payment',
        success_url = domain + "/goal-donate-stripe-success/",
        cancel_url = domain + "/cancelled/",
        line_items=[
            {
                'name': 'Donation for goal',
                'currency': 'usd',
                'amount': int(float(body['donate_amount']) * 100),
                'quantity': 1,
            },
        ],
    )

    request.session['donation_data'] = {
        'user_goal_slug': body['user_goal_slug'],
        'payment_intent': checkout_session.payment_intent
    }
    request.session.modified = True
    return JsonResponse({'sessionId': checkout_session['id']})

@login_required
def goalDonateStripeSuccess(request):
    social = SocialIcon.objects.all()
    message = 'Something Went Wrong'
    if request.session.has_key('donation_data'):
        donation_data = request.session['donation_data']
        user_goal_slug = donation_data['user_goal_slug']
        payment_intent_id = donation_data['payment_intent']
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        charge_data = payment_intent['charges']['data'][0]
        status = charge_data['status']
        goal_donation = GoalDonation()
        transaction_id = charge_data['balance_transaction']
        amount = payment_intent['amount'] / 100
        if status == 'succeeded':
            goal_donation.status = 1
            message = 'Donated Successfully'
            messages.success(request,'Successfully Donated to Goal')
        else:
            goal_donation.status = 0
            message = 'Failed to Donate'
            messages.error(request,'Failed To Donate')
        goal_donation.transaction_id = transaction_id
        goal_donation.amount = amount
        goal_donation.goal_id = UserGoal.objects.get(slug=user_goal_slug).id
        goal_donation.user_id = request.user.id
        goal_donation.save()
        del request.session['donation_data']
        request.session.modified = True
        
    return render(request, 'app/donation-result.html',  {'user_goal_slug':user_goal_slug, 'social':social, 'message': message})
    

@login_required
def web_chat(request):
    
    user_id = request.user.id
    following_user = FollowUser.objects.filter(user_email_id = user_id, approve_status = True)
    chat_query = f"""SELECT "superadmin_room"."id", "superadmin_room"."user1_id", "superadmin_room"."user2_id", 
            "superadmin_room"."room","superadmin_chat"."created" FROM "superadmin_room" LEFT OUTER JOIN "superadmin_chat"
                ON ("superadmin_room"."id" = "superadmin_chat"."room_id_id") WHERE ("superadmin_room"."user1_id" = {user_id}
                OR "superadmin_room"."user2_id" = {user_id}) group by "superadmin_room"."id" 
                ORDER BY "superadmin_chat"."created" DESC;"""
    data_raw = Room.objects.raw(chat_query)
    return render(request, 'app/web_chat/chat.html', {'following_user': following_user, 'chat_users': data_raw}) 

@csrf_exempt
def create_room_for_chat(request):
    user_id = request.user.id
    to_chat_user_id = request.POST.get('to_chat_user')
    to_chat_user_data = User.objects.get(id = to_chat_user_id)
    room1 = f'{user_id}_room_{to_chat_user_id}' 
    room2 = f'{to_chat_user_id}_room_{user_id}'
    if not Room.objects.filter(Q(room = room1)|Q(room = room2)).exists():
        chat_room = Room.objects.create(room = room1, user1_id = user_id, user2_id = to_chat_user_id)
        chat_data = None
        return render(request, 'app/web_chat/chat_data.html', {"chat_data": chat_data, 'to_chat_user_data': to_chat_user_data, 'chat_room' : chat_room})
    else:
        chat_room = Room.objects.get(Q(room = room1)| Q(room = room2))
        chat_data = Chat.objects.filter(Q(sender_id = user_id,receiver_id = to_chat_user_id)| Q(sender_id = to_chat_user_id,receiver_id = user_id)).order_by("id")
        return render(request, 'app/web_chat/chat_data.html', {"chat_data": chat_data, 'to_chat_user_data': to_chat_user_data, 'chat_room' : chat_room})
    
def chat_count(request):
    user_id = request.user.id
    chat_count = Room.objects.filter(Q(user1_id = user_id)|Q(user2_id = user_id)).count()        
    return JsonResponse({"chat_count": chat_count})   

def delete_chat(request, slug):
    try:
        user_id = request.user.id
        to_chat_user_id = User.objects.get(slug = slug).id
        room1 = f'{user_id}_room_{to_chat_user_id}' 
        room2 = f'{to_chat_user_id}_room_{user_id}'
        Room.objects.filter(Q(room = room1)|Q(room = room2)).delete()
        return redirect('web_chat')
    except:
        messages.error(request, "Something Went Wrong")
        return redirect('web_chat')  
# Web Chat End

# Group Web Chat Start
def group_web_chat(request, slug):
    web_chat_data = ChatGroup.objects.get(goal__slug = slug)
    chat_members_data = web_chat_data.members
    jsonDec = json.decoder.JSONDecoder()
    chat_members = jsonDec.decode(chat_members_data)
    receiver_id = []
    chat_user = []
    for chat in chat_members:
        chat_user.append(User.objects.get(id = chat))
        if not chat == str(request.user.id):
            receiver_id.append(int(chat))
    return render(request, 'app/web_chat/group_web_chat.html', {'web_chat_data': web_chat_data, 'chat_user': chat_user, 'receiver_id': receiver_id} )

@csrf_exempt
def create_room_for_group_chat(request):
    user_id = str(request.user.id)
    group_id = request.POST.get('group_id')
    chat_data = GroupMassage.objects.filter(group_id = group_id).order_by("id")
    sender_ids = chat_data.values_list('sender', flat=True)
    sender_data = User.objects.filter(id__in = sender_ids)
    for chat in chat_data:
        for sender in sender_data:
            if sender.id == int(chat.sender):
                chat.sender_name = sender.first_name + ' ' + sender.last_name
    return render(request, "app/web_chat/group_web_chat_data.html", {'chat_data': chat_data, 'user_id': user_id})
@csrf_exempt
def get_name_of_sender(request):
    sender_id = request.POST.get('sender_id')    
    user = User.objects.get(id = sender_id)
    sender_name = user.first_name + user.last_name
    date = timezone.now()
    return JsonResponse({'sender_name': sender_name, 'date': date})
# Group Web Chat End


@login_required
def productListView(request):
    template_name = 'app/product-management/product-listing.html'
    social = SocialIcon.objects.all()
    products = Product.objects.all()
    product_images = ProductImages.objects.filter(product_id__in=products.values_list('id'))
    p = Paginator(products, 6)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)    
    return render(request, template_name, {'social':social, 'products':page_obj, 'product_images':product_images})

@login_required
def productView(request, id):
    template_name = 'app/product-management/product-details.html'
    social = SocialIcon.objects.all()
    products = Product.objects.get(id=id)
    product_images = ProductImages.objects.get(product_id=id)
    request.session['goal_as'] = 'productview'
    request.session.modified = True
    return render(request, template_name, {'social':social, 'products':products, 'product_images':product_images, 'product_order':'product_order'})

@login_required
def vendorSubscriptionPlan(request):
    template_name = 'app/partner/subscription_plan/partner-subscription-plan.html'
    social = SocialIcon.objects.all()
    subscription_plan=SubscriptionPlan.objects.all()
    for i in subscription_plan:
        subscription_plans=i.price
    if VendorSubscription.objects.filter(vendor_id=request.user.id):     
        vendor_data = VendorSubscription.objects.get(vendor_id=request.user.id)
        product_count = User.objects.get(id=request.user.id)
        product_count1 = Product.objects.filter(user=product_count).count()

        if not product_count1 <= int(vendor_data.plan.product_count):
            messages.error(request, 'your subscrition plan has expired')
        else:
            SubscriptionPlan.objects.all()
    
    
        return render(request, template_name, {'social':social, 'subscription_plan':subscription_plan, 'product_count1':product_count1, 'vendor_data':vendor_data, 'STRIPE_PUBLIC_KEY': settings.STRIPE_PUBLIC_KEY})
    
    
    else:
        SubscriptionPlan.objects.all()
    return render(request, template_name, {'social':social, 'subscription_plan':subscription_plan, 'STRIPE_PUBLIC_KEY': settings.STRIPE_PUBLIC_KEY})

@login_required
def deleteSubscription(request):
    if request.method == "POST":
        data=request.POST
        reaccept=request.POST.get('vendor_id')
        req_accept = VendorSubscription.objects.get(vendor_id=reaccept)
        req_accept.delete()
        return JsonResponse({'status':'success','message':'delete successfully'})

@login_required
def vendorSubscriptionStripe(request, plan_type):
    body_unicode = request.body.decode('utf-8')
    body = json.loads(body_unicode)
    domain = body['domain']
    stripe.api_key = settings.STRIPE_SECRET_KEY
    payment_plan = SubscriptionPlan.objects.get(plan_type=plan_type)
    user = request.user
    if user.user_type == 'VENDOR' and user.is_active == True:
        if not VendorSubscription.objects.filter(vendor_id=request.user.id).exists():
            if payment_plan.free_trail == 0: 
                checkout_session = stripe.checkout.Session.create(
                    client_reference_id=user.id,
                    payment_method_types=["card"],
                    mode = 'subscription',
                    customer = user.customer_id,
                    success_url = settings.SITE_URL + 'vendor-subscription-stripe-success/',
                    cancel_url = settings.CANCEL_URL,
                    line_items=[
                        {
                            'price': payment_plan.subscription_price_id,
                            'quantity': 1, 
                        }
                    ]
                )
                request.session['checkout_session_id'] = checkout_session['id']        
                request.session.modified = True
                return JsonResponse({'status': True,'sessionId': checkout_session['id']})

            if not SubscriptionUsed.objects.filter(user_id=user.id).exists():
                newdate = datetime.date().today() + timedelta(days=int(payment_plan.days))
                vendor_subscription = VendorSubscription.objects.create(customer_id=user.customer_id, vendor_id=user.id, 
                plan_id=payment_plan.id, start_at=datetime.today(), expire_at=newdate)
                vendor_subscription.save()
                vendor_used=SubscriptionUsed.objects.create(subscription_plan_id=payment_plan.id, used=True, user_id=user.id)
                vendor_used.save()
                return JsonResponse({
                    'status': True, 
                    'message': "Your Free Trail is Active."
                    })
            return JsonResponse({
                'status': False, 
                'message': "You have already used free trail."
                })
        else:
            return JsonResponse({
                'status': False, 
                'message': "You have already selected plan."
                })
    if user.user_type == 'USER':
        return JsonResponse({
            'status': False, 
            'message': "You have no permission to visit Goal."
        })
    else:
        return JsonResponse({
            'status': False, 
            'message': "Unauthenticated User."
        })

#-------------------------------------Vendor START--------------------------------------
@login_required
def vendorDashboardView(request):
    template_name = 'app/partner/dashboard/partner-dashboard.html'
    social = SocialIcon.objects.all()
    sold_product = Product.objects.filter(user=request.user.email)
    total_product = UserGoal.objects.filter(product_id__in=sold_product.values_list('id')).order_by('id').count()
    return render(request, template_name, {'social':social, 'total_product':total_product})

@login_required
def vendorProductListView(request):
    template_name = 'app/partner/product/partner-product-listing.html'
    social = SocialIcon.objects.all()
    if VendorSubscription.objects.filter(vendor_id=request.user.id):

        products = Product.objects.filter(user=request.user.email).order_by('-id')
        vendor_data = VendorSubscription.objects.get(vendor_id=request.user.id)
        vendor_data_plan_product_count = int(vendor_data.plan.product_count)
        product_count = User.objects.get(id=request.user.id)
        product_count1 = Product.objects.filter(user=product_count).count()
        p = Paginator(products, 6)
        page_number = request.GET.get('page')
        try:
            page_obj = p.get_page(page_number) 
        except PageNotAnInteger:
            page_obj = p.page(1)
        except EmptyPage:
            page_obj = p.page(p.num_pages)
        product_images = ProductImages.objects.filter(product_id__in=products.values_list('id'))
        product_order = GoalOrder.objects.filter(product_id__in=products.values_list('id')).order_by('id')
        return render(request, template_name, {'social':social, 'products':page_obj, 'product_images':product_images, 'product_order':product_order, 'vendor_data_plan_product_count':vendor_data_plan_product_count, 'product_count1':product_count1})
    else:
        products = Product.objects.filter(user=request.user.email).order_by('-id')
        product_images = ProductImages.objects.filter(product_id__in=products.values_list('id'))
        product_order = GoalOrder.objects.filter(product_id__in=products.values_list('id')).order_by('id')
        messages.error(request, 'Please select subscrition plan.')
        p = Paginator(products, 6)
        page_number = request.GET.get('page')
        try:
            page_obj = p.get_page(page_number) 
        except PageNotAnInteger:
            page_obj = p.page(1)
        except EmptyPage:
            page_obj = p.page(p.num_pages)
        return render(request, template_name, {'social':social, 'products':page_obj, 'product_images':product_images, 'product_order':product_order})
        

@login_required
def vendorProductView(request):
    template_name = 'app/partner/product/partner-product-details.html'
    social = SocialIcon.objects.all()
    products = None
    if request.method == 'POST':
        product_id = request.POST.get('id')
        products = Product.objects.get(id=product_id)
    product_images = ProductImages.objects.get(product_id=products)
    return render(request, template_name, {'social':social, 'products':products, 'product_images':product_images, 'product_order':'product_order'})

@login_required
def vendorInvoice(request):
    template_name='app/partner/invoice/partner-invoice.html'
    user_data = User.objects.get(id = request.user.id)
    if user_data.user_type == 'VENDOR' and user_data.is_active == True:
        product_id=Product.objects.filter(user=user_data)
        create_vendor_invoice = GoalOrder.objects.filter(product_id__in=product_id, status="COMPLETED" )
        vendor_invoice = VendorInvoice.objects.filter(vendor_id=user_data.id)
        return render(request, template_name,{'vendor_invoice':vendor_invoice, 'create_vendor_invoice':create_vendor_invoice})
    if user_data.user_type == 'USER':
        messages.error(request, "You have no permission to see Invoice.")
        return render(request, template_name)
    else:
        messages.error(request, "Unauthenticated User.")
        return render(request, template_name)

@login_required    
def invoiceList(request):
    if request.method == 'POST':
        invoice_id = request.POST.get('invoice_id')
        invoice_list = VendorInvoice.objects.get(id=invoice_id)
        return JsonResponse({'status': 'success', 'message' :"doneeeee" ,'invoice_id':invoice_list.order_id, 'transaction_id':invoice_list.transaction_id, 'total':invoice_list.amount, 'inv_number':invoice_list.id, 'inv_date':invoice_list.created})
    return redirect('vendor_invoice')
@login_required
def vendorOrderDetail(request):
    if request.method == 'POST':
        product_id = request.POST.get('id')
        products = GoalOrder.objects.get(id=product_id)
        user_data = User.objects.get(id = request.user.id)
        if user_data.user_type == 'VENDOR' and user_data.is_active == True:
            amount=UserGoal.objects.get(id=products.goal_id)
            goal_order = products.order_id
            if goal_order and not VendorInvoice.objects.filter(order_id=goal_order).exists():               
                invoice_request = GoalOrder.objects.get(order_id=goal_order)
                invoice_request.invoice_request = 1
                invoice_request.save()
                vendor_invoice = VendorInvoice.objects.create(vendor_id=user_data.id, amount=amount.goal_amount, goal_id=amount.id, order_id=goal_order)
                messages.success(request, "Invoice created.")
                return redirect('vendor_invoice')
                
            else:
                messages.error(request, "Already created invoice with order ID or invalid order ID.")
                return redirect('vendor_invoice')
                    
        else:
            messages.error(request, "Invalid user type!")
            return redirect('vendor_invoice')
            
    return redirect('vendor_invoice')

@login_required    
def vendorSubscriptionStripeSuccess(request):
    if request.session.has_key('checkout_session_id'):
        checkout_session_id = request.session['checkout_session_id']
        user_data = request.user
        if user_data.user_type == 'VENDOR' and user_data.is_active == True:
            payment_checkout = stripe.checkout.Session.retrieve(
                    checkout_session_id
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
                
                messages.success(request, "Your subscription plan successfully activated.")
                return redirect('vendor_subscription_plan')
            
            vendor_data = VendorSubscription.objects.get(subscription_id=vendor_subscription_details['id'])
            messages.success(request, "Your subscription plan successfully activated.")
            return redirect('vendor_subscription_plan')
            
                
        if user_data.user_type == 'USER':
            messages.success(request, "You have no permission to see payment Plan.")
            return redirect('vendor_subscription_plan')
        else:
            messages.success(request, "Unauthenticated User.")
            return redirect('vendor_subscription_plan')
    else:
        messages.error(request, "Please provide stripe ID.")
        return redirect('vendor_subscription_plan')

@login_required
def vendorProductCreate(request):
    template_name='app/partner/product/create-product.html'
    social =SocialIcon.objects.all()
    if request.method == 'POST':
        data=request.POST
        product_category = request.POST.get('product_category')
        product_image = request.FILES.get('product_image')
        product_name = request.POST.get('product_name')
        product_price = request.POST.get('product_price')
        product_desc = request.POST.get('product_desc')
        product_period = request.POST.get('product_period')
        product_time_from = request.POST.get('product_time_from')
        product_time_to = request.POST.get('product_time_to')
        if product_image == '':
            messages.error(request, 'Goal name not be blank.')
            return render(request, template_name, {'data':data})
        if product_name == '':
            messages.error(request, 'Shortdescription not be blank.')
            return render(request, template_name, {'data':data})
        if product_desc == '':
            messages.error(request, 'Priority not be blank.')
            return render(request, template_name, {'data':data})
        if product_period == '':
            messages.error(request, 'Goal type not be blank.')
            return render(request, template_name, {'data':data})
        if product_time_from == '':
            messages.error(request, 'Start date not be blank.')
            return render(request, template_name, {'data':data})
        if product_time_to == '':
            messages.error(request, 'Amount not be blank.')
            return render(request, template_name, {'data':data})
        user=User.objects.get(id=request.user.id)
        productcreate=Product.objects.create(user=user.email, category=product_category, name=product_name, price=product_price, desc=product_desc, return_period=product_period, return_time_from=product_time_from, return_time_to=product_time_to)
        productcreate.save()
        productimage=ProductImages.objects.create(product_id=productcreate.id, image=product_image)
        productimage.save()
        return redirect('vendor_products')
    return render(request, template_name,{'social':social})

@login_required
def deleteProduct(request, id):
    products=Product.objects.get(id=id)
    products.delete()
    return redirect('vendor_products')

@login_required
def editProduct(request, id):
    template_name='app/partner/product/edit-product.html'
    social =SocialIcon.objects.all()
    products=Product.objects.get(id=id)
    productimage=ProductImages.objects.get(product_id=products.id)
    if request.method == 'POST':
        product_category = request.POST.get('product_category')
        product_image = request.FILES.get('product_image')
        product_name = request.POST.get('product_name')
        product_desc = request.POST.get('product_desc')
        if product_image == '':
            messages.error(request, 'Goal name not be blank.')
            return render(request, template_name, {'products':products})
        if product_name == '':
            messages.error(request, 'Shortdescription not be blank.')
            return render(request, template_name, {'products':products})
        if product_desc == '':
            messages.error(request, 'Priority not be blank.')
            return render(request, template_name, {'products':products})
        products.name=product_name
        products.desc=product_desc        
        products.save()
        productimage.image=product_image
        productimage.save()
        
        return redirect('vendor_products')
    return render(request, template_name,{'social':social, 'products':products, 'productimage':productimage})


    
@login_required
def deleteVendorProduct(request):
    if request.method == 'POST':
            user_id = request.POST.get('user_id')
            if user_id :
                data = Product.objects.get(id=user_id)
                data.delete()
    return redirect('vendor_products')

#---------------------------------------Vendor END-------------------------------------

@login_required
def userPayment(request):
    template_name ='app/user-payment/payment-management.html'
    social =SocialIcon.objects.all()
    try:
        user_cards = stripe.Customer.list_sources(
                        request.user.customer_id,
                        object="card",
                    )
        user_payment=PaymentToken.objects.filter(user_id=request.user.id)
        return render(request, template_name, {'social':social, 'user_payment':user_payment, 'user_cards': user_cards})
    except:
        user_payment=PaymentToken.objects.filter(user_id=request.user.id)
        return render(request, template_name, {'social':social, 'user_payment':user_payment})

@login_required
def userPaymentCard(request):
    template_name ='app/user-payment/payment-management-add-new-card.html'
    social =SocialIcon.objects.all()
    if request.method == 'POST':
        data=request.POST
        if data:
            card_holder_name = data.get('card_holder_name')
            card_number = data.get('card_number')
            month = data.get('month')
            year = data.get('year')
            cvv_number = data.get('cvv_number')
            if card_holder_name == '':
                messages.error(request, 'Card holder name must be valid not be blank.')
                return render(request, template_name, {'data':data})
            if card_number == '' and len(cvv_number) <= 16:
                messages.error(request, 'Card number must be valid not be blank.')
                return render(request, template_name, {'data':data})
            if month == '':
                messages.error(request, 'Month must be valid not be blank.')
                return render(request, template_name, {'data':data})
            if year == '':
                messages.error(request, 'Year must be valid not be blank.')
                return render(request, template_name, {'data':data})    
            if cvv_number == '':
                messages.error(request, 'cvv number must be valid not be blank.')
                return render(request, template_name, {'data':data})        
            stripe.api_key = settings.STRIPE_SECRET_KEY
            user = request.user
            try:
                token = stripe.Token.create(
                    card={
                        "name": card_holder_name,
                        "number": card_number,
                        "exp_month": int(month),
                        "exp_year": int(year),
                        "cvc": cvv_number,
                    },
                )

                stripe.Customer.create_source(
                    user.customer_id,
                    source=token['id']
                )
            except TypeError as e:
                messages.error(request, e)
                return render(request, template_name, {'data':data})
            except ValueError as e:
                messages.error(request, e)
                return render(request, template_name, {'data':data})
            except stripe.error.CardError as e:
                messages.error(request, e.user_message)
                return render(request, template_name, {'data':data})
            except Exception as e:
                messages.error(request, e.user_message)
                return render(request, template_name, {'data':data})
            if PaymentToken.objects.filter(user_id=user.id, token=token['id']).exists():
                messages.error(request, 'This Card already added.')
                return render(request, template_name, {'data':data})
            if not PaymentToken.objects.filter(user_id=user.id, default_payment=1).exists():
                PaymentToken.objects.create(user_id=user.id, token=token['id'], card_id=token['card']['id'],default_payment=1)
            else:
                PaymentToken.objects.create(user_id=user.id, token=token['id'], card_id=token['card']['id'])
            return redirect('user_payment')
        else:
            messages.error(request, 'Please enter valid details.')
            return render(request, template_name)
    return render(request, template_name, {'social':social})


@login_required
def cardDelete(request, id):
    user=PaymentToken.objects.filter(user_id=request.user.id, card_id=id)
    for i in user:
        if i.default_payment == True:
            if not GoalMember.objects.filter(members_id=request.user.id).exists():
                card=PaymentToken.objects.get(user_id=request.user.id, card_id=id)
                stripe.Customer.delete_source(
                        request.user.customer_id,
                        id,
                )
                card.delete()
        else:
            messages.error(request, 'You can not delete Default card. ')
            return redirect('user_payment')    
    return redirect('user_payment')


@login_required
def cardSetDefault(request, id):
    card=PaymentToken.objects.filter(user_id=request.user.id, default_payment=1).exclude(card_id=id)
    
    if PaymentToken.objects.filter(user_id=request.user.id, card_id=id, default_payment=0):
        PaymentToken.objects.filter(user_id=request.user.id, card_id=id).update(default_payment=1)
        for i in card:
            i.default_payment=0
            i.save()
    return redirect('user_payment')


@login_required
def goalAmountDetail(request, slug):
    data1=UserGoal.objects.get(slug=slug)
    user_data = User.objects.get(id = data1.user_id) 
    if request.method == "POST":
        goal_id=request.POST.get('goal_id')       
        if user_data.user_type == 'USER' and user_data.is_active == True:
            if UserGoal.objects.filter(id=data1.id).exists():
                if GoalMember.objects.filter(goal_id=data1.id, members_id=user_data.id, owner_id=user_data.id).exists():
                    try:
                        goal_amount = GoalAmountPlan.objects.get(goal_id=goal_id)
                        
                    except:
                        goal_amount = None
                    if goal_amount:
                        if goal_amount.members == GoalMember.objects.filter(goal_id=goal_id, approve=1).count():
                            goal_member = GoalMember.objects.filter(goal_id=goal_id, approve=1).count()
                            total_months_emi = goal_amount.amount / goal_member
                            
                            return JsonResponse({"status":"success",'amount':goal_amount.amount,'member':goal_amount.members, 'goal_id':goal_amount.goal_id, 'amount1':total_months_emi, 'message': "Goal Payment Plan successfully fetched." })
                            
                        else:
                            members = GoalMember.objects.filter(goal_id=goal_id, approve=1).count()
                            goal_amount = GoalAmountPlan.objects.get(goal_id=goal_id)
                            goal_amount.members = members
                            goal_amount.save()
                            goal_member = GoalMember.objects.filter(goal_id=goal_id, approve=1).count()
                            total_months_emi = goal_amount.amount / goal_member
                            
                            return JsonResponse({"status":"success",'amount':goal_amount.amount,'member':goal_amount.members, 'goal_id':goal_amount.goal_id, 'amount1':total_months_emi, 'message': "Goal Payment Plan successfully fetched." })
                                
                    else:
                        goal = UserGoal.objects.get(id=data1.id)
                        goal_members = GoalMember.objects.filter(goal_id=data1.id, approve=1).count()
                        goal_payment = GoalAmountPlan.objects.create(amount=goal.goal_amount, goal_id=goal.id, members=goal_members)
                        goal_payment.save()
                        goal_amount = GoalAmountPlan.objects.get(goal_id=data1.id)
                        goal_member = GoalMember.objects.filter(goal_id=goal_id, approve=1).count()
                        total_months_emi = goal_amount.amount / goal_member
                        # goal_amount_serializer = GoalPaymentPlanSerializer(goal_amount)

                        return JsonResponse({"status":"success",'amount':goal_amount.amount,'member':goal_amount.members, 'goal_id':goal_amount.goal_id, 'amount1':total_months_emi, 'message': "Goal Payment Plan successfully fetched." })
                else:
                    
                    return JsonResponse({
                            'status': "error", 
                            'message': "You are not a Admin of current Goal."
                            })
            else:
                
                return JsonResponse({
                        'status': "error", 
                        'message': "Please provide Valid Goal ID."
                        })
        if user_data.user_type == 'VENDOR':
            
            return JsonResponse({
                    'status': "success", 
                    'message': "You have no permission to see payment Plan."
                    })
        else:
            
            return JsonResponse({
                    'status': "error", 
                    'message': "Unauthenticated User."
                    })


@login_required
def goalStart(request, slug):
    if request.method == 'POST':
        data=request.POST
        amount = request.POST.get('amount')
        
        if amount == '':
            messages.error(request, 'Goal name not be blank.')
            return render(request, {'data':data})
        data1=UserGoal.objects.get(slug=slug)
        user_data = User.objects.get(id = data1.user_id)
        if user_data.user_type == 'USER' and user_data.is_active == True:
            if UserGoal.objects.filter(id=data1.id).exists():
                if GoalMember.objects.filter(goal_id=data1.id, owner=user_data.id).exists():                    
                    try:
                        goal_plan = GoalAmountPlan.objects.get(goal_id=data1.id)
                    except:
                        goal_plan = None
                    goal_name = UserGoal.objects.get(id=data1.id)
                    goal_product = stripe.Product.create(
                        name = goal_name.goal_name
                    )
                    goal_plan.product_id = goal_product['id']
                    goal_plan.save()
                    goal_data = UserGoal.objects.get(id=data1.id)
                    goal_duration_check = {1:1, 2:6, 3:12}
                    commission = AdminCommission.objects.get(id=1)
                    goal_price = stripe.Price.create(
                        unit_amount=int(int(amount) + ((int(amount)*int(commission.amount_percentage))/100)),
                        currency="usd",
                        recurring={"interval": "month", "interval_count":goal_duration_check.get(goal_data.payment_plan_id)},
                        product=goal_product['id'],
                        )
                    goal_plan.price_id = goal_price['id']
                    goal_plan.save()
                    members = []
                    members_email = []
                    goal_members = GoalMember.objects.filter(goal_id=data1.id, approve=1)

                    for i in goal_members:
                        members_email.append(i.members.email)
                        members.append(i.members_id)
                    user_customer = User.objects.filter(id__in=members)
                    PaymentToken.objects.filter(user_id__in=members)
                    user_cards =  PaymentToken.objects.values_list('user_id', flat=True).filter(user_id__in=members, default_payment=1)
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
                            
                            user_subscription_data = UserSubscription.objects.create(user_id=i.id, plan=goal_plan_duration.get(payment_date), customer_id=i.customer_id, subscription_id=user_subscription['id'], price_id=user_subscription['items']['data'][0]['price']['id'], start_at=plan_start_date, next_billing_date=plan_end_date, goal_id=data1.id)
                            user_subscription_data.save()
                        sendSubscriptionMail(plan_end_date, goal_name.goal_name, members_email, data['amount'])
                        goal_plan.amount = data['amount']
                        goal_plan.start_at = data1.start_date
                        goal_plan.save()
                        messages.success(request, "Your have successfully set payment plan.")
                        return redirect('goal_details', slug)
                    else:
                        missing_card_users = User.objects.values_list('first_name', flat=True).filter(id__in=check_list)
                        names = ', '.join(missing_card_users)
                        messages.success(request, f"{names} has not set card yet. Please add card first.")
                        return redirect('goal_details', slug)
                        
                if user_data.user_type == 'VENDOR':
                    messages.success(request, "You have no permission to a proceed payment.")
                    return redirect('goal_details', slug)
                                
                else:
                    messages.success(request, "Unauthenticated User.")
                    return redirect('goal_details', slug)
    return redirect('goal_details', slug)



