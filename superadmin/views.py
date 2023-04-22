from operator import contains
from django.shortcuts import render,redirect
from django.contrib.auth.models import User, auth
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import connection
from django.contrib.auth import get_user_model
from .choices import *
from django.http import JsonResponse
from django.db.models import Q
from .email import *
from datetime import datetime
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import calendar
from django.core.paginator import Paginator
from django.db.models.functions import TruncMonth
from django.db.models import Count
import re
from django.db.models import Count, Sum
from superadmin.models import *
import stripe
from api.utils import *
from datetime import date
User = get_user_model()

def error_404(request, exception):
    return render(request,'404.html')

#fetch all the tables from the database
def tables():
    table = []
    tables = connection.introspection.table_names()
    seen_models = connection.introspection.installed_models(tables)
    for i in seen_models:
        table.append(i)
    return table

def getData():
    C = []
    V = []
    vendor_month = []
    vendor_data = []
    year = 2021
    month = 12
    cyear = datetime.date.today().year
    cmonth = datetime.date.today().month
    while year <= cyear:
        while (year < cyear and month <= 12) or (year == cyear and month <= cmonth):
            customer = User.objects.filter(created__year=year, created__month=month, user_type='USER').aggregate(Count('id'), Sum('id'))
            C.append({
                'year': year,
                'month': month,
                'id': customer['id__count'] or 0,
            })
            vendor = User.objects.filter(created__year=year, created__month=month, user_type='VENDOR').aggregate(Count('id'), Sum('id'))
            V.append({
                'year': year,
                'month': month,
                'id': vendor['id__count'] or 0,
            })
            month += 1
        month = 1
        year += 1
        cust_month = [i['month'] for i in V]
        cust_total = [i['id'] for i in V]
        for i in range(1, len(cust_month)):
            vendor_month.append(i)
        for i in cust_total:
            vendor_data.append(i)
    return cust_total

#homepage function where admin can see all details and graphs.
@login_required
def homepage(request):
    if not request.user.is_superuser:
        return redirect('/')
    template_name = 'index.html'
    table = ['User', 'Goal']
    user_query = f""" select id, count(*)as total,strftime("%%m",created) as month 
                from superadmin_user where user_type="USER" group by strftime("%%m",created);"""
    vendor_query = f""" select id, count(*)as total,strftime("%%m",created) as month 
                from superadmin_user where user_type="VENDOR" group by strftime("%%m",created);"""
    ind_goal_query = f""" select id, count(*)as total,strftime("%%m",created) as month 
                from superadmin_usergoal where goal_type="INDIVIDUAL" group by strftime("%%m",created);"""
    grp_goal_query = f""" select id, count(*)as total,strftime("%%m",created) as month 
                from superadmin_usergoal where goal_type="GROUP" group by strftime("%%m",created);"""
    user_count = User.objects.raw(user_query)
    vendor_count = User.objects.raw(vendor_query)
    ind_goal_count = UserGoal.objects.raw(ind_goal_query)
    grp_goal_count = UserGoal.objects.raw(grp_goal_query)
    i = 0
    j = 0
    append_in_month_name = []
    user_data = []
    vendor_data = []
    ind_goal_data = []
    grp_goal_data = []
    while (i <= 11):
        i += 1
        obj = dict()
        obj.update(
            {'USER': 0, 'month': calendar.month_name[i]})
        convert_in_month_name = calendar.month_name[i]
        user_data.append(obj)
        obj.update(
            {'VENDOR': 0, 'month': calendar.month_name[i]})
        convert_in_month_name = calendar.month_name[i]
        vendor_data.append(obj)
    while (j <= 11):
        j += 1
        obj1 = dict()
        obj1.update(
            {'INDIVIDUAL': 0, 'month': calendar.month_name[j]})
        convert_in_month_name = calendar.month_name[j]
        ind_goal_data.append(obj1)

        obj1.update(
            {'GROUP': 0, 'month': calendar.month_name[j]})
        convert_in_month_name = calendar.month_name[j]
        grp_goal_data.append(obj1)

    for goal in ind_goal_count:
        ind_goal_data[int(goal.month) - 1]['INDIVIDUAL'] = goal.total

    for grp_goal in grp_goal_count:
        grp_goal_data[int(grp_goal.month) - 1]['GROUP'] = grp_goal.total

    for user in user_count:
        user_data[int(user.month) - 1]['USER'] = user.total

    for vendor in vendor_count:
        vendor_data[int(vendor.month) - 1]['VENDOR'] = vendor.total
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    # goal = UserGoal.objects.filter().count()
    user = User.objects.filter(user_type='USER').count()
    vendor = User.objects.filter(user_type='VENDOR', is_active=True).count()
    pending = User.objects.filter(user_type='VENDOR', is_active=False).count()
    goal_count = UserGoal.objects.all().count()
    return render(request, template_name, {'table':table, 'goal_count':goal_count, 'user':user, 'vendor':vendor, "pending":pending, "admin":admin, 'user_data':user_data, 'vendor_data':vendor_data, 'ind_goal_data':ind_goal_data, 'grp_goal_data':grp_goal_data, 'goal_individual_data':'goal_individual_data'})

#logout superAdmin view function
@login_required
def logout(request):
    auth.logout(request)
    messages.success(request, "You have Successfully Logout")
    return redirect('dashboard')

def resendEmailOTP(request, slug):
    user = User.objects.get(slug=slug)
    if user:
        resendOTP(user)
        messages.success(request, "Resend OTP has been sent on registerd email address.")
        return redirect('verify-otp')
    else:
        messages.error(request, "Something went wrong!")
        return redirect('verify-otp')

#superAdmin profile view
@login_required
def superAdminProfile(request, slug):
    template_name = 'superadmin/superadmin-profile.html'
    admin = User.objects.get(slug=slug)
    if request.method=="POST" and 'form1' in request.POST:
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        mobile = request.POST.get('mobile')
        admin1 = User.objects.get(slug=slug, is_superuser = True)
        if admin1:
            if not first_name:
                messages.error(request, "First Name field must be entered.")
                return redirect('/admin/superAdmin-Profile/'+str(admin1.slug)+'/')
            if first_name.isspace():
                messages.error(request, "First Name field must be entered.")
                return redirect('/admin/superAdmin-Profile/'+str(admin1.slug)+'/')
            if not last_name:
                messages.error(request, "Last Name field must be entered.")
                return redirect('/admin/superAdmin-Profile/'+str(admin1.slug)+'/')
            if last_name.isspace():
                messages.error(request, "Last Name field must be entered.")
                return redirect('/admin/superAdmin-Profile/'+str(admin1.slug)+'/')
            if mobile.startswith('-', 0):
                messages.error(request, "Mobile Number field must be valid.")
                return redirect('/admin/superAdmin-Profile/'+str(admin1.slug)+'/')
            if not (len(mobile) >= 10 and len(mobile) <= 12):
                messages.error(request, "Mobile Number field must be valid.")
                return redirect('/admin/superAdmin-Profile/'+str(admin1.slug)+'/')
            admin.first_name=first_name
            admin.last_name=last_name
            admin.mobile=mobile
            admin.save()
            messages.success(request, f"{first_name} is successfully updated!")
            return redirect('/admin/superAdmin-Profile/'+str(admin1.slug)+'/')
        else:
            messages.error(request, "Something went wrong!")
            return redirect('dashboard')
    if request.method == 'POST' and 'form2' in request.POST:
        admin = User.objects.get(slug=slug)
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        if not current_password:
            messages.error(request, 'Please entered current password!')
            return redirect('/admin/superAdmin-Profile/'+str(admin.slug)+'/')
        if not admin.check_password(current_password):
            messages.error(request, 'Current password does matched.')
            return redirect('/admin/superAdmin-Profile/'+str(admin.slug)+'/')
        if not new_password:
            messages.error(request, 'Please entered new password!')
            return redirect('/admin/superAdmin-Profile/'+str(admin.slug)+'/')
        else:
            admin.set_password(new_password)
            admin.save()
            messages.success(request, 'Your Password Successfully Changed!')
            return render(request, template_name, {'admin':admin}) 
    return render(request, template_name, {'admin':admin})

def loginSuperAdmin(request):
    template_name = 'login.html'
    if request.user.is_authenticated and request.user.user_type in ['VENDOR', 'USER']:
        return redirect('/')
    return render(request, template_name)

#superAdmin login view
def loginSuperAdminAjax(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    template_name = 'login.html'
    try:
        if request.method == 'POST':
            email = request.POST.get('email')
            password = request.POST.get('password')
            admin = auth.authenticate(email=email,  password=password)
            if not email:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "Please Enter Valid Email Address.",
                    },
                    status=404,
                )
            if not password:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "Please Enter Password",
                    },
                    status=404,
                )
            if admin is None:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "Invalid username or password.",
                    },
                    status=404,
                )
            elif admin.is_superuser == True:
                auth.login(request, admin)
                return JsonResponse(
                    {
                        "status": "sucsess",
                        "message": "You have successfully Login.",
                    },
                    status=200,
                )

        else:
            return render(request, template_name)
    except:
        messages.error(request, "Something went wrong!")
        return render(request, template_name)

#superAdmin forgetPassword view
def forgetPasswordSuperAdmin(request):
    template_name = 'superadmin/forget-password.html'
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            admin = User.objects.get(email=email)
            if admin:
                if admin.is_superuser:
                    # sendOTP(admin)
                    sendForgetPassOTP(admin)
                    messages.success(request, "Please Check registerd Email Address!")
                    return redirect('/admin/verify-admin/'+str(admin.slug)+'/')
                else:
                    messages.error(request, "This email address does not registerd with Super Admin.")
                    return redirect('admin_forget_password')
            if not admin:
                messages.error(request, "This Email address not found in uor system.")
                return redirect('admin_forget_password')
        except:
            messages.error(request, "This Email address not found in uor system.")
            return redirect('admin_forget_password')
    else:
        return render(request, template_name)
            
#superAdmin OTP verify view
def verifySuperAdmin(request, slug):
    template_name = 'verify-otp.html'
    user = request.user
    try:
        if request.method == 'POST':
            otp = request.POST.get('otp')
            admin = User.objects.get(slug=slug)
            if admin:
                if admin.otp != otp:
                    messages.error(request, 'OTP does not match!')
                    return render(request, template_name)
                else:
                    messages.success(request, "OTP successfully matched!")
                    return redirect('/admin/change-password/'+str(admin.slug)+'/')
            else:
                messages.error(request, "This email address does not registerd with Super Admin.")
                return render(request, template_name)
        else:
            return render(request, template_name)
    except:
        messages.error(request, 'Something Went wrong!')
        return render(request, template_name, {'user':user})

#superAdmin change password view
def changePassword(request, slug):
    template_name = 'superadmin/changepassword.html'
    if request.method == 'POST':
        password = request.POST.get('password')
        confirmpassword = request.POST.get('confirmpassword')
        try:
            admin = User.objects.get(slug=slug)
            if admin:
                if password == confirmpassword:  
                    admin.set_password(confirmpassword)
                    admin.save()
                    messages.success(request,  "Password is successfully changed.!")
                    return redirect('login')
                else:
                    messages.error(request, 'password does matched.')
                    return render(request, template_name)
            else:
                messages.error(request, "Permission Denied!")
                return render(request, template_name)
        except:
            messages.error(request, "Something went wrong!")
            return render(request, template_name)
    else:
        return render(request, template_name)

#registered customers views
@login_required
def tables(request):
    template_name = 'user-management/users.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    user = User.objects.filter(user_type='USER').order_by('-created')
    p = Paginator(user, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'user': user, 'admin':admin, 'page_obj': page_obj, 'show_button': False})

@login_required
def searchUser(request):
    template_name = 'user-management/users.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'GET':
        query = request.GET.get('search_box')
        if query:
            user_search = User.objects.filter(Q(first_name__icontains=query) | Q(email__icontains=query) | Q(last_name__icontains=query) | Q(mobile__icontains=query), user_type='USER')
        else:
            user_search = None
    return render(request, template_name, {'user_search': user_search, 'admin':admin, 'show_button':True})


#add customers view function
@login_required
def addUser(request):
    template_name = 'user-management/add-user.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    return render(request, template_name,{'roll':USER_TYPE, 'admin':admin})

def add_user_ajax(request):
    template_name = 'user-management/add-user.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        mobile = request.POST.get('mobile')
        user_type = request.POST.get('user_type')
        data = User.objects.filter(email = request.POST.get('email'))
        data1 = User.objects.filter(mobile = request.POST.get('mobile'))
        if not first_name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": " First Name field must be entered.",
                },
                status=404,
            )
        if first_name.isspace():
            return JsonResponse(
                {
                    "status": "error",
                    "message": " First Name field must be entered.",
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
        if last_name.isspace():
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Last Name field must be entered.",
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
                    "message": "Mobile number is already present.",
                },
                status=404,
            )
        if not email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Email Address field must be entered.",
                },
                status=404,
            )
        if '@' and '.' not in email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Please enter valid Email Address.",
                },
                status=404,
            )
        if not password:
            return JsonResponse(
                {
                    "status": "error",
                    "message": 'Password field must be entered.'
                },
                status=404,
            )
        if not len(password) >= 5:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Password length must be min 5 character.",
                },
                status=404,
            )
        if not data:
            user, created = User.objects.get_or_create(email=email, password=password, first_name=first_name, last_name=last_name, mobile=mobile, user_type=user_type)
            user.set_password(user.password)
            user.save()
            return JsonResponse(
                {
                    "status": "success",
                    "message": "Successfully Addedd!",
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
    return render(request, template_name,{'roll':USER_TYPE, 'admin':admin})

#customer detail view function
@login_required
def userView(request, id):
    template_name = 'user-management/user-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    user = User.objects.get(id=id)
    return render(request, template_name, {'user': user, 'admin':admin})

#customer update view function
@login_required
def userUpdate(request, id):
    template_name = 'user-management/user-edit.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method=="POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        mobile = request.POST.get('mobile')
        status = request.POST.get('status')
        user = User.objects.filter(id=id, user_type='USER')
        mobile_filter = User.objects.filter(mobile = request.POST.get('mobile'))
        if user:
            if not first_name:
                messages.error(request, "First Name field must be entered.")
                return redirect('/admin/user-edit/'+str(id)+'/')
            if first_name.isspace():
                messages.error(request, "First Name field must be entered.")
                return redirect('/admin/user-edit/'+str(id)+'/')
            if not last_name:
                messages.error(request, "Last Name field must be entered.")
                return redirect('/admin/user-edit/'+str(id)+'/')
            if last_name.isspace():
                messages.error(request, "Last Name field must be entered.")
                return redirect('/admin/user-edit/'+str(id)+'/')
            if mobile.startswith('-', 0):
                messages.error(request, "Mobile field must be only number.")
                return redirect('/admin/user-edit/'+str(id)+'/')
            if not (len(mobile) >= 10 and len(mobile) <= 12):
                messages.error(request, "Mobile field must be 10-12 number.")
                return redirect('/admin/user-edit/'+str(id)+'/')
            if status == '0':
                user.update(first_name=first_name, last_name=last_name, mobile=mobile, is_active=False)
                messages.success(request, f"{first_name} is successfully updated!")
                return redirect('tables')
            if status == '1':
                user.update(first_name=first_name, last_name=last_name, mobile=mobile, is_active=True)
                messages.success(request, f"{first_name} is successfully updated!")
                return redirect('tables')
            user.update(first_name=first_name, last_name=last_name, mobile=mobile)
            messages.success(request, f"{first_name} is successfully updated!")
            return redirect('tables')
        else:
            messages.error(request, "Something went wrong!")
            return redirect('user_edit')
    else:
        user = User.objects.get(id=id)
        return render(request, template_name, {'user': user, 'admin':admin})

#customer delete view function
@login_required
def userDelete(request, id):
    user = User.objects.get(id=id)
    name = user.first_name
    user.delete()
    messages.success(request, f"{name} is deleted!")
    return redirect('tables')

#registerd vendor view function
@login_required
def vendor(request):
    template_name = 'vendor-management/vendors.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    vendor = User.objects.filter(user_type='VENDOR', is_active=True).order_by('-created')
    p = Paginator(vendor, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'vendor': vendor, 'admin':admin, 'page_obj': page_obj, 'show_button': False})

@login_required
def searchVendor(request):
    template_name = 'vendor-management/vendors.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'GET':
        query = request.GET.get('search_box')
        # | 
        if query:
            vendor_search = User.objects.filter(Q(company_name__icontains=query) | Q(email__icontains=query) | Q(company_username__icontains=query) |Q(mobile__icontains=query) | Q(company_regisration_number__icontains=query), user_type='VENDOR')
        else:
            vendor_search = None
    return render(request, template_name, {'vendor_search': vendor_search, 'admin':admin, 'show_button': True})

@login_required
def searchPendingVendor(request):
    template_name = 'vendor-management/pending-users.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'GET':
        query = request.GET.get('search_box')
        if query:
            vendor_search = User.objects.filter(Q(company_name__icontains=query) | Q(email__icontains=query) | Q(company_username__icontains=query) |Q(mobile__icontains=query) | Q(company_regisration_number__icontains=query), user_type='VENDOR', is_active=False)
        else:
            vendor_search = None
    return render(request, template_name, {'vendor_search': vendor_search, 'admin':admin, 'show_button': True})

#pending vendor detail view function
@login_required
def pendingVendorView(request, slug):
    template_name = 'vendor-management/vendor-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    vendor = User.objects.get(slug=slug)
    return render(request, template_name, {'vendor': vendor, 'admin':admin})

#vendor detail view function
@login_required
def vendorView(request, id):
    template_name = 'vendor-management/vendor-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    vendor = User.objects.get(id=id)
    return render(request, template_name, {'vendor': vendor, 'admin':admin})

#add vendor view function
@login_required
def addVendor(request):
    template_name = 'vendor-management/add-vendor.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        company_username = request.POST.get('company_username')
        mobile = request.POST.get('mobile')
        email = request.POST.get('email')
        company_name = request.POST.get('company_name')
        company_regisration_number = request.POST.get('company_regisration_number')
        company_document = request.FILES.get('company_document')
        password = request.POST.get('password')
        user_type = request.POST.get('user_type')
        data = User.objects.filter(email = request.POST.get('email'))
        data1 = User.objects.filter(mobile = request.POST.get('mobile'))
    return render(request, template_name,{'roll':USER_TYPE, 'admin':admin})

def add_vendor_ajax(request):
    template_name = 'vendor-management/add-vendor.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        company_username = request.POST.get('company_username')
        mobile = request.POST.get('mobile')
        email = request.POST.get('email')
        company_name = request.POST.get('company_name')
        company_regisration_number = request.POST.get('company_regisration_number')
        company_document = request.FILES.get('company_document')
        password = request.POST.get('password')
        user_type = request.POST.get('user_type')
        data = User.objects.filter(email = request.POST.get('email'))
        data1 = User.objects.filter(mobile = request.POST.get('mobile'))
        if not company_username:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Company Username field must be entered.",
                },
                status=404,
            )
        if company_username.isspace():
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Company Username field must be entered.",
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
                    "message": "Mobile number is already present.",
                },
                status=404,
            )
        if not email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Email Address field must be entered.",
                },
                status=404,
            )
        if '@' and '.' not in email:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Please enter valid Email Address.",
                },
                status=404,
            )
        if not company_name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Company Name field must be entered.",
                },
                status=404,
            )
        if company_name.isspace():
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
        if company_regisration_number.isspace():
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Registration Number field must be entered.",
                },
                status=404,
            )
        if not company_document:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Company Document field must be entered.",
                },
                status=404,
            )
        if not password:
            return JsonResponse(
                {
                    "status": "error",
                    "message": 'Password field must be entered.'
                },
                status=404,
            )
        if not data:
            if get_size(company_document):
                vendor, created = User.objects.get_or_create(email=email, password=password, company_name=company_name, company_document=company_document, mobile=mobile, company_regisration_number= company_regisration_number, company_username=company_username, user_type=user_type)
                vendor.set_password(vendor.password)
                vendor.save()
                return JsonResponse(
                    {
                        "status": "success",
                        "message": "Successfully Addedd!",
                    },
                    status=200,
                )
            else:
                return JsonResponse(
                    {
                        "status": "error",
                        "message": "Document size must be less then or equal 1 MB.",
                    },
                    status=404,
                )
        else:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "This email address is already exists!",
                },
                status=404,
            )
    return render(request, template_name,{'roll':USER_TYPE, 'admin':admin})

#vendor update detail view function
@login_required
def vendorUpdate(request, id):
    template_name = 'vendor-management/vendor-edit.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method=="POST":
        company_name = request.POST.get('company_name')
        company_username = request.POST.get('company_username')
        company_regisration_number = request.POST.get('company_regisration_number')
        company_document = request.FILES.get('company_document')
        status = request.POST.get('status')
        vendor = User.objects.get(id=id, user_type='VENDOR')
        if vendor:
            if not company_document:
                company_document = vendor.company_document
            if not company_name:
                messages.error(request, "Company Name field must be entered.")
                return redirect('/admin/vendor-edit/'+str(id)+'/')
            if company_name.isspace():
                messages.error(request, "Company Name field must be entered.")
                return redirect('/admin/vendor-edit/'+str(id)+'/')
            if not company_username:
                messages.error(request, "Company Username field must be entered.")
                return redirect('/admin/vendor-edit/'+str(id)+'/')
            if company_username.isspace():
                messages.error(request, "Company Username field must be entered.")
                return redirect('/admin/vendor-edit/'+str(id)+'/')
            if not company_regisration_number:
                messages.error(request, "Company Regisration field must be entered.")
                return redirect('/admin/vendor-edit/'+str(id)+'/')
            if company_regisration_number.isspace():
                messages.error(request, "Company Regisration field must be entered.")
                return redirect('/admin/vendor-edit/'+str(id)+'/')
            if status == '0':
                vendor.company_name=company_name
                vendor.company_document=company_document
                vendor.company_username = company_username
                vendor.company_regisration_number = company_regisration_number
                vendor.is_active = False
                vendor.save()
                messages.success(request, f"{company_username} is successfully updated!")
                return redirect('vendors')
            if status == '1':
                vendor.company_name=company_name
                vendor.company_username = company_username
                vendor.company_document = company_document
                vendor.company_regisration_number = company_regisration_number
                vendor.is_active = True
                vendor.save()
                messages.success(request, f"{company_username} is successfully updated!")
                return redirect('vendors')
            vendor.company_name=company_name
            vendor.company_username = company_username
            vendor.company_regisration_number = company_regisration_number
            vendor.company_document = company_document
            vendor.save()
            messages.success(request, f"{company_username} is successfully updated!")
            return redirect('vendors')
        else:
            messages.error(request, "Something went wrong!")
            return redirect('vendor_edit')
    else:
        vendor = User.objects.get(id=id)
        return render(request, template_name, {'vendor': vendor, 'admin':admin})

#vendor delete function
@login_required
def vendorDelete(request, id):
    user = User.objects.get(id=id)
    name = user.first_name
    user.delete()
    messages.success(request, f"{name} is deleted")
    return redirect('vendors')

#all listed goals view function
@login_required
def goalList(request):
    template_name = 'goal-management/goal.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    goal = UserGoal.objects.all().order_by('-created')
    p = Paginator(goal, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'data': goal,'page_obj':page_obj, 'admin':admin})

#goal detail view function
@login_required
def goalView(request, id):
    template_name = 'goal-management/goal-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    try:
        goal = UserGoal.objects.get(id=id)
    except:
        goal = None
    try:
        sub_goal = SubGoal.objects.filter(sub_goal_id=id)
    except:
        sub_goal = None
    try:
        goal_member = GoalMember.objects.filter(goal_id=id)
    except:
        goal_member = None
    try:
        goal_admin = GoalGroupAdmin.objects.filter(group_goal_id=id)
    except:
        goal_admin = None
    return render(request, template_name, {'data': goal, 'admin':admin, 'sub_goal':sub_goal, 'goal_member':goal_member, 'goal_admin':goal_admin})

#social account view function
@login_required
def socialList(request):
    template_name = 'social-management/social.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    try:
        social = SocialIcon.objects.all().order_by('-created')
    except:
        social: None
    return render(request, template_name, {'social': social, 'admin':admin})

#social account detail page view function
@login_required
def socialView(request, id):
    template_name = 'social-management/social-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    social = SocialIcon.objects.get(id=id)
    return render(request, template_name, {'social': social, 'admin':admin})

#add social account view function
def addSocialLinkAjax(request):
    template_name = 'social-management/add-social.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        name = request.POST.get('name')
        icon = request.FILES.get('icon')
        link = request.POST.get('link')
        if not name:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Account Name field must be entered.",
                },
                status=404,
            )
        if name.isspace():
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Account Name field must be entered.",
                },
                status=404,
            )
        if not icon:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Account Logo field must be entered.",
                },
                status=404,
            )
        if not link:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Account URL field must be entered.",
                },
                status=404,
            )
        if link.isspace():
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Account URL field must be entered.",
                },
                status=404,
            )
        try:
            valid = URLValidator()
            valid(link)
        except:
            return JsonResponse(
                    {
                        "status": "error",
                        "message": "Account URL field must be entered.",
                    },
                    status=404,
                )
        social, created = SocialIcon.objects.get_or_create(name=name, icon=icon, link=link)
        social.save()
        messages.success(request, f"{name} is successfully added!")
        return JsonResponse(
                {
                    "status": "success",
                    "message": "Successfully added!",
                },
                status=200,
            )
    return render(request, template_name, {'admin':admin})

@login_required
def addSocialLink(request):
    template_name = 'social-management/add-social.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    return render(request, template_name, {'admin':admin})

#update or modify social account detail page view function
@login_required
def socialUpdate(request, id):
    template_name = 'social-management/soical-edit.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    social = SocialIcon.objects.get(id=id)
    try:
        if request.method=="POST":
            icon = request.FILES.get('icon') 
            name = request.POST.get('name')
            link = request.POST.get('link')
            if social:
                if not icon:
                    icon = social.icon
                if not name:
                    messages.error(request, "Account Name field must be entered.")
                    return redirect('/admin/social-edit/'+str(id)+'/')
                if name.isspace():
                    messages.error(request, "Account Name field must be entered.")
                    return redirect('/admin/social-edit/'+str(id)+'/')
                if not link:
                    messages.error(request, "Account URL field must be entered.")
                    return redirect('/admin/social-edit/'+str(id)+'/')
                if link.isspace():
                    messages.error(request, "Account URL field must be entered.")
                    return redirect('/admin/social-edit/'+str(id)+'/')
                social.name=name
                social.icon=icon
                social.link=link
                social.save()
                messages.success(request, f"{name} is updated!")
                return redirect('social')
            else:
                messages.error(request, "Something went wrong!")
                return redirect('social_edit')
        else:
            social = SocialIcon.objects.get(id=id)
            return render(request, template_name, {'social': social, 'admin':admin})
    except:
        messages.error(request, "Something went wrong!")
        return redirect('social')

#delete social account view function
@login_required
def socialDelete(request, id):
    social = SocialIcon.objects.get(id=id)
    account = social.name
    social.delete()
    messages.success(request, f"{account} is deleted")
    return redirect('social')

def register(request):
    template_name = 'register.html'
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        mobile = request.POST.get('mobile')
        data = Customer.objects.filter(email = request.POST.get('email'))
        if data:
            messages.error(request, "This email address is already exists!")
        else:
            user, created = Customer.objects.get_or_create(email=email, password=password, first_name=first_name, last_name=last_name, mobile=mobile)
            user.save()
            messages.success(request, "You have Successfully Registerd!")
    return render(request, template_name)

#add user and vendor view function
def registerUser(request):
    template_name = 'frontend/auth/signup.html'
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
            user.set_password(user.password)
            user.save()
            sendOTP(user)
            messages.success(request, "You have Successfully Registerd!")
            return redirect('/admin/verify/'+str(user.slug)+'/')
        else:
            messages.error(request, "This email address is already exists!")
    return render(request, template_name,{'roll':USER_TYPE})

#users login view function and need to modify when UI is avialable
def loginUser(request):
    template_name = 'user-login.html'
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
    return render(request, template_name)

def verifyUser(request, slug):
    template_name = 'frontend/auth/verification.html'
    if request.method == 'POST':
        otp1 = request.POST.get('otp1')
        otp2 = request.POST.get('otp2')
        otp3 = request.POST.get('otp3')
        otp4 = request.POST.get('otp4')
        otp = otp1 + otp2 + otp3 + otp4
        user = User.objects.get(slug=slug)
        if user.otp == otp:
            user.is_verified = True
            user.is_active = False
            user.save()
            messages.success(request, 'Email Verification Complete.')
            return redirect('dashboard')
        else:
            messages.error(request, 'OTP does not match!')
    else:
        messages.error(request, 'Something Went wrong!')
    return render(request, template_name)

#pending vendors view function
@login_required
def pendingVendor(request):
    template_name = 'vendor-management/pending-users.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    pending = User.objects.filter(user_type='VENDOR', is_active=False).order_by('-created')
    p = Paginator(pending, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'pending': pending, 'admin':admin, 'page_obj':page_obj})

#change vendors status view function
@login_required
def changeVendorStatus(request, slug):
    vendor = User.objects.get(slug=slug)
    try:
        if vendor:  
            vendor.is_active = True
            vendor.save()
            accountApproved(vendor)
            messages.success(request, "Approved Successfully!")
            return redirect('pending')
        else:
            messages.error(request, "Vendor not found!")
            return redirect('pending')
    except:
        messages.error(request, "Something went wrong!")
        return redirect('pending')

#email template view function
@login_required
def emailTemplate(request):
    template_name = 'email-management/email.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    email = EmailTemplate.objects.all().order_by('-id')
    return render(request, template_name, {'email': email, 'admin':admin})

#add email template view function
@login_required
def addEmailTemplate(request):
    template_name = 'email-management/add-email.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        name = request.POST.get('name')
        editor = request.POST.get('editor')
        if not name:
            messages.error(request, "Title field must be entered.")
            return redirect('add_email')
        if name.isspace():
            messages.error(request, "Title field must be entered.")
            return redirect('add_email')
        if not editor:
            messages.error(request, "Emial Content field must be entered.")
            return redirect('add_email')
        emailTemplate, created = EmailTemplate.objects.get_or_create(name=name, editor=editor)
        emailTemplate.save()
        messages.success(request, f"{name} is successfully added!")
        return redirect('email')
    return render(request, template_name, {'admin':admin})
    
#delete email template view function
@login_required 
def emailDelete(request, id):
    email = EmailTemplate.objects.get(id=id)
    name = email.name
    email.delete()
    messages.success(request, f"{name} is deleted")
    return redirect('email')

#update email template view function
@login_required
def emailUpdate(request, id):
    template_name = 'email-management/edit-email.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method=="POST":
        name = request.POST.get('name')
        editor = request.POST.get('editor')
        email = EmailTemplate.objects.filter(id=id)
        if email:
            if not name:
                messages.error(request, "Title field must be entered.")
                return redirect('/admin/email-edit/'+str(id)+'/')
            if not editor:
                messages.error(request, "Email content field must be entered.")
                return redirect('/admin/email-edit/'+str(id)+'/')
            email.update(name=name, editor=editor)
            messages.success(request, f"{name} is updated!")
            return redirect('email')
        else:
            messages.error(request, "Something went wrong!")
            return redirect('email_edit')
    else:
        email = EmailTemplate.objects.get(id=id)
        return render(request, template_name, {'email': email, 'admin':admin})

#email detail view function
@login_required
def emailView(request, id):
    template_name = 'email-management/email-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    email = EmailTemplate.objects.get(id=id)
    return render(request, template_name, {'email': email, 'admin':admin})

#app slider listing view function
@login_required
def slider(request):
    template_name = 'slider-management/slider.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    slider = AppSlider.objects.all()
    return render(request, template_name, {'slider': slider, 'admin':admin})

#add app slider view function
@login_required
def addAppSlider(request):
    template_name = 'slider-management/add-slider.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        title = request.POST.get('title')
        image = request.FILES.get('image')
        desc = request.POST.get('desc')
        slider, created = AppSlider.objects.get_or_create(title=title, image=image, desc=desc)
        slider.save()
        messages.success(request, f"{title} is successfully added!")
        return redirect('slider')
    return render(request, template_name, {'admin':admin})

#update or modify allSlider view function
@login_required
def sliderUpdate(request, id):
    template_name = 'slider-management/slider-edit.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    slider = AppSlider.objects.get(id=id)
    try:
        if request.method=="POST":
            image = request.FILES.get('image') 
            title = request.POST.get('title')
            desc = request.POST.get('desc')
            if slider:
                if not image:
                    image = slider.image
                if not title:
                    messages.error(request, "Title field must be entered.")
                    return redirect('/admin/slider-edit/'+str(id)+'/')
                if not desc:
                    messages.error(request, "Description field must be entered.")
                    return redirect('/admin/slider-edit/'+str(id)+'/')
                slider.title=title
                slider.image=image
                slider.desc=desc
                slider.save()
                messages.success(request, f"{title} is updated!")
                return redirect('slider')
            else:
                messages.error(request, "Something went wrong!")
                return redirect('slider_edit')
        else:
            slider = AppSlider.objects.get(id=id)
            return render(request, template_name, {'slider': slider, 'admin':admin})
    except:
        messages.error(request, "Something went wrong!")
        return redirect('slider')

#posts listing view function
@login_required
def posts(request):
    template_name = 'post-management/posts.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    post = PostUser.objects.all().order_by('-id')
    p = Paginator(post, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'post': post, 'page_obj':page_obj, 'admin':admin})

@login_required
def postView(request, id):
    template_name = 'post-management/post-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    try:
        post = PostUser.objects.get(id=id)
    except:
        post = None
    return render(request, template_name, {'post': post, 'admin':admin})

#testimonial listing view function
@login_required
def testimonial(request):
    template_name = 'testimonial-management/testi-list.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    feedback = TestimonialManagement.objects.all()
    return render(request, template_name, {'feedback': feedback, 'admin':admin})

#add testimonial view function
@login_required
def addTestimonial(request):
    template_name = 'testimonial-management/add-testi.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        name = request.POST.get('name')
        image = request.FILES.get('image')
        desc = request.POST.get('desc')
        if not name:
            messages.error(request, "Name field must be entered.")
            return redirect('add_testimonial')
        if name.isspace():
            messages.error(request, "Name field must be entered.")
            return redirect('add_testimonial')
        if not desc:
            messages.error(request, "Description field must be entered.")
            return redirect('add_testimonial')
        testimonial, created = TestimonialManagement.objects.get_or_create(name=name, image=image, desc=desc)
        testimonial.save()
        messages.success(request, f"{name} is successfully added!")
        return redirect('testimonial')
    return render(request, template_name, {'admin':admin})

#update testimonial view function
@login_required
def testimonialUpdate(request, id):
    template_name = 'testimonial-management/edit-testi.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    feedback = TestimonialManagement.objects.get(id=id)
    try:
        if request.method=="POST":
            image = request.FILES.get('image') 
            name = request.POST.get('name')
            desc = request.POST.get('desc')
            if feedback:
                if not image:
                    image = feedback.image
                if not name:
                    messages.error(request, "Name field must be entered.")
                    return redirect('/admin/testimonial-edit/'+str(id)+'/')
                if name.isspace():
                    messages.error(request, "Name field must be entered.")
                    return redirect('/admin/testimonial-edit/'+str(id)+'/')
                if not desc:
                    messages.error(request, "Description field must be entered.")
                    return redirect('/admin/testimonial-edit/'+str(id)+'/')
                feedback.name=name
                feedback.image=image
                feedback.desc=desc
                feedback.save()
                messages.success(request, f"{name} is updated!")
                return redirect('testimonial')
            else:
                messages.error(request, "Something went wrong!")
                return redirect('testimonial_edit')
        else:
            feedback = TestimonialManagement.objects.get(id=id)
            return render(request, template_name, {'feedback': feedback, 'admin':admin})
    except:
        messages.error(request, "Something went wrong!")
        return redirect('testimonial')

#delete testimonial view function
@login_required 
def testimonialDelete(request, id):
    feedback = TestimonialManagement.objects.get(id=id)
    name = feedback.name
    feedback.delete()
    messages.success(request, f"{name} is deleted")
    return redirect('testimonial')

#testimonial detail view function
@login_required
def testimonialView(request, id):
    template_name = 'testimonial-management/testi-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    feedback = TestimonialManagement.objects.get(id=id)
    return render(request, template_name, {'feedback': feedback, 'admin':admin})

@login_required
def contactUsView(request):
    template_name = 'contact-us/contact-us.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    data = ContactUs.objects.filter(status='PENDING').order_by('-id')
    p = Paginator(data, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'data': data, 'admin':admin, 'page_obj':page_obj})

@login_required
def resolvedView(request):
    template_name = 'contact-us/resolved.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    data = ContactUs.objects.filter(status='RESOLVED').order_by('-id')
    p = Paginator(data, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'data': data, 'admin':admin, 'page_obj':page_obj})

@login_required 
def resolvedDelete(request, id):
    contact = ContactUs.objects.get(id=id)
    name = contact.name
    contact.delete()
    messages.success(request, f"{name} is deleted")
    return redirect('resolved_contact')

@login_required
def replyContactUs(request, id):
    template_name = 'contact-us/reply.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    try:
        data = ContactUs.objects.get(id=id, status='PENDING')
    except:
        data = None
    if data:
        if request.method == 'POST':
            subject = request.POST.get('subject')
            answer = request.POST.get('answer')
            if not answer:
                messages.error(request, "Answer field not be blank.")
                return redirect('/admin/reply-contact/'+str(id))
            email_from = settings.EMAIL_HOST_USER
            mail_sent = send_mail(subject, answer, email_from, [data.email], fail_silently=False)
            if mail_sent:
                data.status = 'RESOLVED'
                data.save()
                messages.success(request, "Mail successfully send.")
                return redirect('contact')
    return render(request, template_name, {'data': data, 'admin':admin})

@login_required
def addAboutUs(request):
    template_name = 'about-us/add-about.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    return render(request, template_name, {'admin':admin})

@login_required
def aboutUs(request):
    template_name = 'about-us/about.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    about = AboutUs.objects.all()
    return render(request, template_name, {'about':about, 'admin':admin})

@login_required
def privacypolicy(request):
    template_name = 'cms-management/privacy-policy/privacy-policy.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    privacy = PrivacyPolicyWeb.objects.all()
    return render(request, template_name, {'privacy':privacy, 'admin':admin})

@login_required
def updatePrivacyPolicy(request, id):
    template_name = 'cms-management/privacy-policy/edit-privacy-policy.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    privacy = PrivacyPolicyWeb.objects.get(id=id)
    if request.method == 'POST':
        desc = request.POST.get('desc')
        if not desc:
            messages.error(request, "Editor field must be entered.")
            return redirect('edit_privacy_policy')
        if desc.isspace():
            messages.error(request, "Editor field must be entered.")
            return redirect('edit_privacy_policy')
        privacy.desc = desc
        privacy.save()
        messages.success(request, "Successfully updated!")
        return redirect('admin_privacy_policy')
    return render(request, template_name, {'privacy':privacy, 'admin':admin})

@login_required
def termsandcondition(request):
    template_name = 'cms-management/terms-condition/terms-condition.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    terms_condition = TermsConditionWeb.objects.all()
    return render(request, template_name, {'terms_condition':terms_condition, 'admin':admin})

@login_required
def updateTermsCondition(request, id):
    template_name = 'cms-management/terms-condition/edit-terms-condition.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    terms_condition = TermsConditionWeb.objects.get(id=id)
    if request.method == 'POST':
        desc = request.POST.get('desc')
        if not desc:
            messages.error(request, "Editor field must be entered.")
            return redirect('edit_terms_condition')
        if desc.isspace():
            messages.error(request, "Editor field must be entered.")
            return redirect('edit_terms_condition')
        terms_condition.desc = desc
        terms_condition.save()
        messages.success(request, "Successfully updated!")
        return redirect('admin_terms_condition')
    return render(request, template_name, {'terms_condition':terms_condition, 'admin':admin})

@login_required
def ViewAboutUs(request, id):
    template_name = 'about-us/about-us-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    try:
        about = AboutUs.objects.get(id=id)
    except:
        about = None
    return render(request, template_name, {'about':about, 'admin':admin})

@login_required
def getInTouch(request):
    template_name = 'getintouch/get-in-touch.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    touch = GetInTouch.objects.get()
    if request.method=="POST":
        mobile = request.POST.get('mobile')
        email = request.POST.get('email')
        location = request.POST.get('location')
        if not mobile:
            messages.error(request, "Mobile Field is Must")
            return redirect('/admin/get-in-touch/')
        if mobile.isspace():
            messages.error(request, "Mobile Field is Must")
            return redirect('/admin/get-in-touch/')
        if not email:
            messages.error(request, "Email Field is Must")
            return redirect('/admin/get-in-touch/')
        if email.isspace():
            messages.error(request, "Email Field is Must")
            return redirect('/admin/get-in-touch/')
        if not location:
            messages.error(request, "Location Field is Must")
            return redirect('/admin/get-in-touch/')
        if location.isspace():
            messages.error(request, "Location Field is Must")
            return redirect('/admin/get-in-touch/')
        touch.mobile = mobile
        touch.email = email
        touch.location = location
        touch.save()
        messages.success(request, "Your changes successfully saved.")
        return redirect('/admin/get-in-touch/')
    return render(request, template_name, {'touch':touch, 'admin':admin})

@login_required
def addAboutusAjax(request):
    template_name = 'about-us/add-about.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        title = request.POST.get('title')
        image1 = request.FILES.get('image1')
        image2 = request.FILES.get('image2')
        image3 = request.FILES.get('image3')
        desc1 = request.POST.get('desc1')
        desc2 = request.POST.get('desc2')
        desc3 = request.POST.get('desc3')
        desc4 = request.POST.get('desc4')
        if not title:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Title field must be entered.",
                },
                status=404,
            )
        if title.isspace():
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Title field must be entered.",
                },
                status=404,
            )
        if not image1:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Image1 field must be entered.",
                },
                status=404,
            )
        if not image2:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Image2 field must be entered.",
                },
                status=404,
            )
        if not image3:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Image3 Logo field must be entered.",
                },
                status=404,
            )
        if not desc1:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Description1 field must be entered.",
                },
                status=404,
            )
        if not desc2:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Description2 field must be entered.",
                },
                status=404,
            )
        if not desc3:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Description3 field must be entered.",
                },
                status=404,
            )
        if not desc4:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Description4 field must be entered.",
                },
                status=404,
            )
        about, created = AboutUs.objects.get_or_create(title=title, image1=image1, image2=image2, image3=image3, desc1=desc1, desc2=desc2, desc3=desc3, desc4=desc4)
        about.save()
        messages.success(request, f"{title} is successfully added!")
        return JsonResponse(
                {
                    "status": "success",
                    "message": "Successfully added!",
                },
                status=200,
            )
    return render(request, template_name, {'admin':admin})

@login_required
def aboutUsUpdate(request, id):
    template_name = 'about-us/about-edit.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    about = AboutUs.objects.get(id=id)
    try:
        if request.method=="POST":
            image1 = request.FILES.get('image1') 
            image2 = request.FILES.get('image2') 
            image3 = request.FILES.get('image3') 
            title = request.POST.get('title')
            desc1 = request.POST.get('desc1')
            desc2 = request.POST.get('desc2')
            desc3 = request.POST.get('desc3')
            desc4 = request.POST.get('desc4')
            if about:
                if not image1:
                    image1 = about.image1
                if not image2:
                    image2 = about.image2
                if not image3:
                    image3 = about.image3
                if not title:
                    messages.error(request, "Title field must be entered.")
                    return redirect('/admin/edit-about/'+str(id)+'/')
                if title.isspace():
                    messages.error(request, "Title field must be entered.")
                    return redirect('/admin/edit-about/'+str(id)+'/')
                if not desc1:
                    messages.error(request, "Description1 field must be entered.")
                    return redirect('/admin/edit-about/'+str(id)+'/')
                if not desc2:
                    messages.error(request, "Description2 field must be entered.")
                    return redirect('/admin/edit-about/'+str(id)+'/')
                if not desc3:
                    messages.error(request, "Description3 field must be entered.")
                    return redirect('/admin/edit-about/'+str(id)+'/')
                if not desc4:
                    messages.error(request, "Description4 field must be entered.")
                    return redirect('/admin/edit-about/'+str(id)+'/')
                about.title=title
                about.image1=image1
                about.image2=image2
                about.image3=image3
                about.desc1=desc1
                about.desc2=desc2
                about.desc3=desc3
                about.desc4=desc4
                about.save()
                messages.success(request, f"{title} is updated!")
                return redirect('about')
            else:
                messages.error(request, "Something went wrong!")
                return redirect('/admin/edit-about/'+str(id)+'/')
        else:
            about = AboutUs.objects.get(id=id)
            return render(request, template_name, {'about': about, 'admin':admin})
    except:
        messages.error(request, "Something went wrong!")
        return redirect('about')

@login_required
def aboutusApp(request):
    template_name = 'app-about-us/aboutus-app.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    about_us = AboutUsApp.objects.all()
    return render(request, template_name, {'about_us':about_us, 'admin':admin})

@login_required
def addAboutUsApp(request):
    template_name = 'app-about-us/add-about.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        editor = request.POST.get('editor')
        if not editor:
            messages.error(request, "Data field must be entered.")
            return redirect('add_testimonial')
        about_us, created = AboutUsApp.objects.get_or_create(editor=editor)
        about_us.save()
        messages.success(request, "Successfully added!")
        return redirect('about_us_app')
    return render(request, template_name, {'admin':admin})

#app about us update function
@login_required
def appAboutUsUpdate(request, id):
    template_name = 'app-about-us/edit-about.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    about = AboutUsApp.objects.get(id=id)
    try:
        if request.method=="POST":
            editor = request.POST.get('editor')
            if about:
                if editor.isspace():
                    messages.error(request, "Description field must be entered.")
                    return redirect('/admin/edit-about-us-app/'+str(id)+'/')
                if not editor:
                    messages.error(request, "Description field must be entered.")
                    return redirect('/admin/edit-about-us-app/'+str(id)+'/')
                about.editor=editor
                about.save()
                messages.success(request, "Updated Successfully.")
                return redirect('about_us_app')
            else:
                messages.error(request, "Something went wrong!")
                return redirect('/admin/edit-about-us-app/'+str(id)+'/')
        else:
            about = AboutUsApp.objects.get(id=id)
            return render(request, template_name, {'about': about, 'admin':admin})
    except:
        messages.error(request, "Something went wrong!")
        return redirect('about_us_app')

#view app about us
@login_required
def viewAppAboutUs(request, id):
    template_name = 'app-about-us/view-aboutus.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    try:
        about = AboutUsApp.objects.get(id=id)
    except:
        about = None
    return render(request, template_name, {'about':about, 'admin':admin})

#app testimonials
@login_required
def appTestimonialList(request):
    template_name = 'app-testimonial/testi-list.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    testimonial = HomeTestimonial.objects.all().order_by('-id')
    return render(request, template_name, {'testimonial': testimonial, 'admin':admin})

@login_required
def appTestimonialAdd(request):
    template_name = 'app-testimonial/add-testi.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
        name = request.POST.get('name')
        designation = request.POST.get('designation')
        text = request.POST.get('text')
        images = request.FILES.get('images')
        if not name:
            messages.error(request, "Name field must be entered.")
            return redirect('app_testimonial_add')
        if name.isspace():
            messages.error(request, "Name field must be entered.")
            return redirect('app_testimonial_add')
        if not designation:
            messages.error(request, "Designation field must be entered.")
            return redirect('app_testimonial_add')
        if designation.isspace():
            messages.error(request, "Designation field must be entered.")
            return redirect('app_testimonial_add')
        if not text:
            messages.error(request, "Description field must be entered.")
            return redirect('app_testimonial_add')
        if text.isspace():
            messages.error(request, "Description field must be entered.")
            return redirect('app_testimonial_add')
        if not images:
            messages.error(request, "images field must be entered.")
            return redirect('app_testimonial_add')
        clear = re.compile('<.*?>') 
        message = re.sub(clear, '', text)
        testimonial, created = HomeTestimonial.objects.get_or_create(home_api_id=1, name=name, designation=designation, text=message, images=images)
        testimonial.save()
        messages.success(request, "Successfully added!")
        return redirect('app_testimonial')
    return render(request, template_name, {'admin':admin})

@login_required
def appTestimonialView(request, id):
    template_name = 'app-testimonial/testi-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    testimonial = HomeTestimonial.objects.get(id=id)
    return render(request, template_name, {'testimonial': testimonial, 'admin':admin})

@login_required
def appTestimonialUpdate(request, id):
    template_name = 'app-testimonial/edit-testi.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    testimonial = HomeTestimonial.objects.get(id=id)
    try:
        if request.method=="POST":
            images = request.FILES.get('images') 
            name = request.POST.get('name')
            text = request.POST.get('text')
            designation = request.POST.get('designation')
            if testimonial:
                if not images:
                    images = testimonial.images
                if not name:
                    messages.error(request, "Name field must be entered.")
                    return redirect('/admin/app-testimonial-edit/'+str(id)+'/')
                if name.isspace():
                    messages.error(request, "Name field must be entered.")
                    return redirect('/admin/app-testimonial-edit/'+str(id)+'/')
                if not text:
                    messages.error(request, "Description field must be entered.")
                    return redirect('/admin/app-testimonial-edit/'+str(id)+'/')
                if text.isspace():
                    messages.error(request, "Description field must be entered.")
                    return redirect('/admin/app-testimonial-edit/'+str(id)+'/')
                if not designation:
                    messages.error(request, "Designation field must be entered.")
                    return redirect('/admin/app-testimonial-edit/'+str(id)+'/')
                if designation.isspace():
                    messages.error(request, "Designation field must be entered.")
                    return redirect('/admin/app-testimonial-edit/'+str(id)+'/')
                clear = re.compile('<.*?>') 
                message = re.sub(clear, '', text)
                testimonial.name=name
                testimonial.images=images
                testimonial.designation=designation
                testimonial.text=message
                testimonial.save()
                messages.success(request, f"{name} is updated!")
                return redirect('app_testimonial')
            else:
                messages.error(request, "Something went wrong!")
                return redirect('/admin/app-testimonial-edit/'+str(id)+'/')
        else:
            testimonial = HomeTestimonial.objects.get(id=id)
            return render(request, template_name, {'testimonial': testimonial, 'admin':admin})
    except:
        messages.error(request, "Something went wrong!")
        return redirect('testimonial')

@login_required 
def appTestimonialDelete(request, id):
    testimonial = HomeTestimonial.objects.get(id=id)
    name = testimonial.name
    testimonial.delete()
    messages.success(request, f"{name} is deleted")
    return redirect('app_testimonial')

@login_required
def ticketView(request):
    template_name = 'ticket-management/tickets.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    tickets = RaiseTicket.objects.filter(status='PENDING').order_by('-id')
    p = Paginator(tickets, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'tickets': tickets, 'admin':admin, 'page_obj':page_obj})

@login_required
def ticketResolvedView(request):
    template_name = 'ticket-management/resolved.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    tickets = RaiseTicket.objects.filter(status='RESOLVED').order_by('-id')
    p = Paginator(tickets, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'tickets': tickets, 'admin':admin, 'page_obj':page_obj})

@login_required 
def resolveTicketdDelete(request, id):
    ticket = RaiseTicket.objects.get(id=id)
    num = ticket.ticket_num
    ticket.delete()
    messages.success(request, f"{num} is deleted")
    return redirect('resolved_tickets')

@login_required
def replyTicket(request, id):
    template_name = 'ticket-management/reply.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    try:
        data = RaiseTicket.objects.get(id=id, status='PENDING')
        user_data =  User.objects.get(email=data.user)
    except:
        data = None
        user_data = None
    if data:
        if request.method == 'POST':
            subject = 'Ticket Query Reply'
            answer = request.POST.get('answer')
            body = f'Hii {user_data.first_name}, \nYour Ticket Number: {data.ticket_num} \n{answer} \nThanks & Regards \nSeedesta Teams'
            if not answer:
                messages.error(request, "Answer field not be blank.")
                return redirect('/admin/reply-contact/'+str(id))
            email_from = settings.EMAIL_HOST_USER
            mail_sent = send_mail(subject, body, email_from, [data.user], fail_silently=False)
            if mail_sent:
                data.status = 'RESOLVED'
                data.save()
                messages.success(request, "Mail successfully send.")
                return redirect('tickets')
    else:
        messages.error(request, "Something went wrong!")
        return redirect('tickets')
    return render(request, template_name, {'data': data, 'admin':admin})

@login_required
def questionView(request):
    template_name = 'ticket-management/questions.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    questions = Ticket.objects.all().order_by('-id')
    p = Paginator(questions, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'questions': questions, 'admin':admin, 'page_obj':page_obj})

@login_required
def addQuestionView(request):
    template_name = 'ticket-management/add-question.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
            question = request.POST.get('question')
            if not question:
                messages.error(request, "Question field not be blank.")
                return redirect('add_questions')
            if question.isspace():
                messages.error(request, "Question field not be blank.")
                return redirect('add_questions')
            questions , created = Ticket.objects.get_or_create(question=question)
            questions.save()
            messages.success(request, "Successfully Created.")
            return redirect('questions')
    return render(request, template_name, {'admin':admin})

@login_required
def updateQuestionView(request, id):
    template_name = 'ticket-management/edit-question.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    questions = Ticket.objects.get(id=id)
    if request.method == 'POST':
            ques = request.POST.get('question')
            if not ques:
                messages.error(request, "Question field not be blank.")
                return redirect('/admin/edit-questions/'+str(id)+'/')
            if ques.isspace():
                messages.error(request, "Question field not be blank.")
                return redirect('/admin/edit-questions/'+str(id)+'/')
            questions.question = ques
            questions.save()
            messages.success(request, "Successfully Updated.")
            return redirect('questions')
    return render(request, template_name, {'questions':questions,'admin':admin})

@login_required 
def questionDelete(request, id):
    question = Ticket.objects.get(id=id)
    question.delete()
    messages.success(request, "Successfully deleted")
    return redirect('questions')

@login_required
def vendorSubscriptionList(request):
    template_name = 'payment-management/vendor-subscription.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    subscription = SubscriptionPlan.objects.all()
    return render(request, template_name, {'subscription': subscription, 'admin':admin})

@login_required
def VendorSubscriptionView(request, id):
    template_name = 'payment-management/view-vendor-subscription.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    subscription = SubscriptionPlan.objects.get(id=id)
    return render(request, template_name, {'subscription': subscription, 'admin':admin})

@login_required
def CommissionView(request):
    template_name = 'commission/commission.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    commission = AdminCommission.objects.get(id=1)
    if request.method == 'POST':
        commision_percentage = request.POST.get('percentage')
        if commision_percentage.isspace() or not commision_percentage:
            messages.error(request, "Percentage not be blank.")
            return redirect('commission')
        commission.amount_percentage = commision_percentage
        commission.save()
        if commision_percentage.isspace() or not commision_percentage:
            messages.success(request, "Updated successfully.")
            return redirect('commission')
    return render(request, template_name, {'commission': commission, 'admin':admin})

@login_required 
def VendorSubscriptionDelete(request, id):
    try:
        subscription = SubscriptionPlan.objects.get(id=id)
        if not VendorSubscription.objects.filter(plan_id=subscription.id).exists():
            SubscriptionPlan.objects.filter(plan_id=subscription.plan_id).delete()
            messages.success(request, "Successfully deleted")
            return redirect('vendor_subscription')
        else:
            messages.error(request, "Vendors bind with this plan. You can't be change or delete.")
            return redirect('vendor_subscription')
    except:
        messages.error(request, "Something went wrong!")
        return redirect('vendor_subscription')

@login_required
def addVendorSubscription(request):
    template_name = 'payment-management/add-vendor-subscription.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
            plan_name = request.POST.get('plan_name')
            price = request.POST.get('price')
            product_count = request.POST.get('product_count')
            validity = request.POST.get('validity')
            desc = request.POST.get('desc')
            if plan_name.isspace() or not plan_name:
                messages.error(request, "Plan Name field not be blank.")
                return redirect('add_vendor_subscription')
            if price.isspace() or not price:
                messages.error(request, "Plan Price field not be blank.")
                return redirect('add_vendor_subscription')
            if product_count.isspace() or not product_count:
                messages.error(request, "Product field not be blank.")
                return redirect('add_vendor_subscription')
            if validity.isspace() or not validity:
                messages.error(request, "Validity field not be blank.")
                return redirect('add_vendor_subscription')
            if desc.isspace() or not desc:
                messages.error(request, "Validity field not be blank.")
                return redirect('add_vendor_subscription')
            vendor_subscription = stripe.Product.create(
                name = plan_name
            )
            subscription_price = stripe.Price.create(
                unit_amount=int(price)*100,
                currency="usd",
                recurring={"interval": "month", "interval_count":validity},
                product=vendor_subscription['id'],
                )
            SubscriptionPlan.objects.create(plan_type=plan_name, description=desc, price=price,  product_count=product_count, 
            subscription_price_id=subscription_price['id'], plan_id=subscription_price['product'])
            messages.success(request, "Successfully Created.")
            return redirect('vendor_subscription')
    return render(request, template_name, {'admin':admin})

@login_required
def editVendorSubscription(request, id):
    template_name = 'payment-management/edit-vendor-subscription.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    vendor_subscription = SubscriptionPlan.objects.get(id=id)
    if request.method == 'POST':
        plan_name = request.POST.get('plan_name')
        product_count = request.POST.get('product_count')
        days = request.POST.get('days')
        desc = request.POST.get('desc')
        if plan_name.isspace() or not plan_name:
            messages.error(request, "Plan Name field not be blank.")
            return redirect('edit-vendor-subscription/'+str(id)+'/')
        if product_count.isspace() or not product_count:
            messages.error(request, "Product field not be blank.")
            return redirect('edit-vendor-subscription/'+str(id)+'/')
        if days.isspace() or not days:
            messages.error(request, "Days field not be blank.")
            return redirect('edit-vendor-subscription/'+str(id)+'/')
        if desc.isspace() or not desc:
            messages.error(request, "Validity field not be blank.")
            return redirect('edit-vendor-subscription/'+str(id)+'/')
        vendor_subscription.plan_type = plan_name
        vendor_subscription.product_count = product_count
        vendor_subscription.days = days
        vendor_subscription.desc = desc
        vendor_subscription.save()
        messages.success(request, "Successfully Updated.")
        return redirect('vendor_subscription')
    return render(request, template_name, {'admin':admin, 'vendor_subscription':vendor_subscription})

@login_required
def editVendorPaidSubscription(request, id):
    template_name = 'payment-management/edit-vendor-paid-subscription.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    vendor_subscription = SubscriptionPlan.objects.get(id=id)
    if request.method == 'POST':
        product_count = request.POST.get('product_count')
        desc = request.POST.get('desc')
        if product_count.isspace() or not product_count:
            messages.error(request, "Product field not be blank.")
            return redirect('edit-vendor-subscription/'+str(id)+'/')
        if desc.isspace() or not desc:
            messages.error(request, "Validity field not be blank.")
            return redirect('edit-vendor-subscription/'+str(id)+'/')
        vendor_subscription.product_count = product_count
        vendor_subscription.description = desc
        vendor_subscription.save()
        messages.success(request, "Successfully Updated.")
        return redirect('vendor_subscription')
    return render(request, template_name, {'admin':admin, 'vendor_subscription':vendor_subscription})

@login_required
def vendorPaidSubscriptionView(request, slug):
    template_name = 'payment-management/view-vendor-paid-subscription.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    vendor_subscription = VendorSubscription.objects.get(slug=slug)
    return render(request, template_name, {'vendor_subscription':vendor_subscription, 'admin':admin})

@login_required
def vendorActiveSubscriptionList(request):
    template_name = 'payment-management/vendor-subscriptions/active-vendor-subscription.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    subscription = VendorSubscription.objects.all()
    return render(request, template_name, {'subscription': subscription, 'admin':admin})

@login_required
def vendorSettlePaymentList(request):
    template_name = 'payment-management/vendor-invoice.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    invoice = VendorInvoice.objects.all().order_by('-id')
    p = Paginator(invoice, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'page_obj':page_obj, 'invoice': invoice, 'admin':admin, 'show_button': False})

@login_required
def vendorInvoiceView(request, slug):
    template_name = 'payment-management/invoice-view.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    invoice = VendorInvoice.objects.get(slug=slug)
    return render(request, template_name, {'invoice':invoice, 'admin':admin})

@login_required
def vendorInvoiceEdit(request, slug):
    template_name = 'payment-management/invoice-edit.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    invoice = VendorInvoice.objects.get(slug=slug)
    if request.method == 'POST':
        status = request.POST.get('status')
        invoice.status = status
        invoice.payment_date = datetime.now()
        invoice.amount_date = date.today()
        invoice.save()
        goal_order = GoalOrder.objects.get(order_id=invoice.order_id)
        goal_order.payment_status = 'COMPLETED'
        goal_order.save()
        messages.success(request, "Successfully Updated.")
        return redirect('vendor_payment_sattlement')
    return render(request, template_name, {'invoice':invoice, 'admin':admin})

@login_required
def searchInvoice(request):
    template_name = 'payment-management/vendor-invoice.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'GET':
        query = request.GET.get('search_box')
        if query:
            invoiceData = VendorInvoice.objects.filter(Q(vendor__company_name__icontains=query) | Q(goal__goal_name__icontains=query), status='PENDING')
        else:
            invoiceData = None
    return render(request, template_name, {'invoiceData': invoiceData, 'admin':admin, 'show_button':True})

@login_required
def activeGoalList(request):
    template_name = 'payment-management/customer/active-goal.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    goals = UserGoal.objects.filter(status='ACTIVE')
    p = Paginator(goals, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'goals': goals, 'page_obj':page_obj, 'admin':admin})

@login_required
def completedGoalList(request):
    template_name = 'payment-management/customer/completed-goal.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    goals = UserGoal.objects.filter(status='COMPLETED')
    p = Paginator(goals, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'goals': goals, 'page_obj':page_obj, 'admin':admin})

@login_required
def goalQuestionView(request):
    template_name = 'goal-questions/questions.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    questions = GroupAdminQuestion.objects.all().order_by('-id')
    p = Paginator(questions, 10)
    page_number = request.GET.get('page')
    try:
        page_obj = p.get_page(page_number) 
    except PageNotAnInteger:
        page_obj = p.page(1)
    except EmptyPage:
        page_obj = p.page(p.num_pages)
    return render(request, template_name, {'questions': questions, 'admin':admin, 'page_obj':page_obj})

@login_required
def goalAddQuestionView(request):
    template_name = 'goal-questions/add-question.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    if request.method == 'POST':
            question = request.POST.get('question')
            if not question:
                messages.error(request, "Question field not be blank.")
                return redirect('add_questions')
            if question.isspace():
                messages.error(request, "Question field not be blank.")
                return redirect('add_questions')
            questions , created = GroupAdminQuestion.objects.get_or_create(questions=question)
            questions.save()
            messages.success(request, "Successfully Created.")
            return redirect('goal_questions')
    return render(request, template_name, {'admin':admin})

@login_required
def goalUpdateQuestionView(request, slug):
    template_name = 'goal-questions/edit-question.html'
    admin = User.objects.get(id=request.user.id, is_superuser=True)
    questions = GroupAdminQuestion.objects.get(slug=slug)
    if request.method == 'POST':
            ques = request.POST.get('question')
            if not ques:
                messages.error(request, "Question field not be blank.")
                return redirect('/admin/edit-questions/'+str(id)+'/')
            if ques.isspace():
                messages.error(request, "Question field not be blank.")
                return redirect('/admin/edit-questions/'+str(id)+'/')
            questions.questions = ques
            questions.save()
            messages.success(request, "Successfully Updated.")
            return redirect('goal_questions')
    return render(request, template_name, {'questions':questions,'admin':admin})

@login_required 
def goalquestionDelete(request, slug):
    question = GroupAdminQuestion.objects.get(slug=slug)
    question.delete()
    messages.success(request, "Successfully deleted")
    return redirect('goal_questions')
