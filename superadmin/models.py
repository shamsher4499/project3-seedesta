from email.mime import image
from unicodedata import category
from django.db import models
from django.contrib.auth.models import AbstractUser
from .manager import *
from .choices import *
import uuid
from djmoney.models.fields import MoneyField
from random import randint
from django.core.validators import FileExtensionValidator
# Create your models here.

def random_with_N_digits(n):
        range_start = 10**(n-1)
        range_end = (10**n)-1
        return randint(range_start, range_end)

class User(AbstractUser):
    class Meta:
        ordering = ['-created']
    username = None
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    profile_pic = models.ImageField(upload_to='profile/', null=True, blank=True)
    company_name = models.CharField(max_length=255, null=True, blank=True)
    company_regisration_number = models.CharField(max_length=255, null=True, blank=True)
    company_document = models.FileField(upload_to='document/', null=True)
    company_username = models.CharField(max_length=255, null=True, blank=True)
    user_type = models.CharField(max_length=10, choices=USER_TYPE)
    first_name = models.CharField(max_length=255, null=True, blank=True)
    bio = models.TextField(null=True, blank=True)
    last_name = models.CharField(max_length=255, null=True, blank=True)
    mobile = models.CharField(max_length=255, null=True, blank=True)
    otp = models.CharField(max_length=6 ,null=True, blank=True)
    user_category = models.CharField(max_length=50, choices=GOAL_TYPE, default='NEW')
    notification_settings = models.BooleanField(default=False)
    location_settings = models.BooleanField(default=False)
    latitude = models.CharField(max_length=255, null=True, blank=True)
    longitude = models.CharField(max_length=255, null=True, blank=True)
    country_code = models.CharField(max_length=255, null=True, blank=True)
    currency = models.CharField(max_length=50, default='USD')
    customer_id = models.CharField(max_length=255, unique=True,  null=True, blank=True)
    avg_rating = models.IntegerField(default=0)
    provider_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    provider_name = models.CharField(max_length=255, null=True, blank=True)
    fcm_token = models.CharField(max_length=255, unique=False,  null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    slug = models.CharField(max_length=50, unique=True, default=uuid.uuid4)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()
        
    def __str__(self):
        return self.email
    class Meta:
        verbose_name_plural = "Super Admin"

class Goal(models.Model):
    goal_name = models.CharField(max_length=255, blank=True, null=True)
    goal_type = models.CharField(max_length=50, choices=GOAL_TYPE)
    goal_duration = models.CharField(max_length=250, choices=GOAL_DURATION)
    goal_amount = models.PositiveIntegerField(blank=True, null=True)
    goal_desc = models.CharField(max_length=255, blank=True, null=True)
    created_by = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=250, choices=GOAL_STATUS)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.goal_name

class Customer(models.Model):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255, null=True, blank=True)
    first_name = models.CharField(max_length=255, null=True, blank=True)
    last_name = models.CharField(max_length=255, null=True, blank=True)
    mobile = models.CharField(max_length=255, null=True, blank=True, unique=True)
    
    def __str__(self):
        return self.email

class SocialIcon(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    icon = models.ImageField(upload_to='social/', null=True, blank=True)
    link = models.URLField(max_length=250)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class EmailTemplate(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    editor = models.TextField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class AppSlider(models.Model):
    title = models.CharField(max_length=255, null=True, blank=True)
    image = models.ImageField(upload_to='slider/', null=True, blank=True)
    desc = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class PostManagement(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255, null=True, blank=True)
    image = models.ImageField(upload_to='post/', null=True, blank=True)
    desc = models.CharField(max_length=255, null=True, blank=True)
    publish_date = models.DateTimeField(auto_now=True)
    comment = models.CharField(max_length=255, null=True, blank=True)
    is_active = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class TestimonialManagement(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    image = models.ImageField(upload_to='tetsimonial/', null=True, blank=True)
    desc = models.CharField(max_length=255, null=True, blank=True)
    is_active = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class ContactUs(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(null=True, blank=True, unique=False)
    subject = models.CharField(max_length=255, null=True, blank=True)
    message = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=250, choices=QUERY_STATUS, default='PENDING')
    created = models.DateTimeField(auto_now_add=True)

class SlideApp(models.Model):
    title = models.CharField(max_length=255, null=True, blank=True)
    image = models.ImageField(upload_to='home/', null=True, blank=True)
    desc = models.TextField()
    created = models.DateTimeField(auto_now_add=True)

class AboutUs(models.Model):
    title = models.CharField(max_length=255, null=True, blank=True)
    image1 = models.ImageField(upload_to='about-us/', null=True, blank=True)
    image2 = models.ImageField(upload_to='about-us/', null=True, blank=True)
    image3 = models.ImageField(upload_to='about-us/', null=True, blank=True)
    desc1 = models.TextField()
    desc2 = models.TextField()
    desc3 = models.TextField()
    desc4 = models.TextField()
    created = models.DateTimeField(auto_now_add=True)

class PrivacyPolicyWeb(models.Model):
    desc = models.TextField()
    created = models.DateTimeField(auto_now_add=True)

class TermsConditionWeb(models.Model):
    desc = models.TextField()
    created = models.DateTimeField(auto_now_add=True)

class AboutUsApp(models.Model):
    editor = models.TextField()

class TermsCondition(models.Model):
    editor = models.TextField()

class PrivacyPolicy(models.Model):
    editor = models.TextField()

class Help(models.Model):
    question = models.CharField(max_length=255, null=True, blank=True)
    answer = models.TextField()

class Ticket(models.Model):
    question = models.CharField(max_length=255, null=True, blank=True)

class RaiseTicket(models.Model):
    user = models.CharField(max_length=255, null=True, blank=True)
    question = models.CharField(max_length=255, null=True, blank=True)
    ticket_num = models.CharField(max_length=255, null=True, blank=True, unique=True)
    status = models.CharField(max_length=255, null=True, blank=True)
    desc = models.CharField(max_length=255, null=True, blank=True)

class Product(models.Model):
    user = models.CharField(max_length=255, null=True, blank=True)
    category = models.CharField(max_length=255, choices=CATEGORY, null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    desc = models.CharField(max_length=255, null=True, blank=True)
    return_period =  models.CharField(max_length=255, null=True, blank=True)
    return_time_from = models.DateTimeField(null=True, blank=True)
    return_time_to = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    
class ProductImages(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='product_image')
    image = models.ImageField(upload_to='products/', null=True, blank=True)

class PaymentPlan(models.Model):
    plan_name = models.CharField(max_length=255, null=True, blank=True)
    desc = models.CharField(max_length=255, null=True, blank=True)
    active = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)

class UserGoal(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user')
    goal_name = models.CharField(max_length=255, blank=True, null=True)
    goal_as = models.CharField(max_length=50, choices=GOAL_AS)
    goal_priority = models.CharField(max_length=50, choices=GOAL_PRIORITY)
    goal_type = models.CharField(max_length=50, choices=GOAL_TYPE)
    payment_method = models.CharField(max_length=50, choices=PAYMENT_METHOD, default='AUTO')
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='product', default=None, blank=True, null=True)
    payment_plan = models.ForeignKey(PaymentPlan, on_delete=models.CASCADE, related_name='payment_plan')
    plan_status = models.CharField(max_length=255, choices=CHOCIES_PLAN_STATUS, default='ACTIVE', blank=True, null=True)
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_subscription_id = models.CharField(max_length=255, blank=True, null=True)
    start_date = models.DateTimeField(auto_now=False)
    goal_amount = models.DecimalField(max_digits=15, decimal_places=2)
    goal_desc = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=250, choices=GOAL_STATUS, default='ACTIVE')
    accept_members = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
    group_name = models.CharField(max_length=255, blank=True, null=True)
    group_desc = models.CharField(max_length=255, blank=True, null=True)
    total_members = models.CharField(max_length=255, default=0, blank=True, null=True)
    slug = models.CharField(max_length=50, unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)

class GoalGroup(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_user_id', default=None, blank=True, null=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='group_goal_id', default=None, blank=True, null=True)
    group_name = models.CharField(max_length=255, blank=True, null=True)
    group_desc = models.CharField(max_length=255, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

class GoalGroupAdmin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_user', default=None, blank=True, null=True)
    group_goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='group_admin', default=None, blank=True, null=True)
    approve = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class GoalGroupMember(models.Model):
    group_member = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_member', default=None, blank=True, null=True)
    group_goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='group_goal', default=None, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

class GoalMember(models.Model):
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='goal_id', default=None, null=True, blank=True)
    members = models.ForeignKey(User, on_delete=models.CASCADE, related_name='goal_member', default=None, null=True, blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='goal_owner', default=None, null=True, blank=True)
    request = models.BooleanField(default=False)
    approve = models.BooleanField(default=False)
    sentrequest = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class RequestGoal(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=None, blank=True, null=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='request_goal', default=None, blank=True, null=True)
    member = models.CharField(max_length=255, default=None, blank=True, null=True)
    request = models.BooleanField(default=False)
    approve = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class FavouriteGoal(models.Model):
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='fav_goal', default=None, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fav_user', default=None, null=True, blank=True)
    favourite = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class FavouriteProduct(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='fav_product', default=None, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_product', default=None, null=True, blank=True)
    favourite = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class FavouriteUser(models.Model):
    fav_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fav_user_email', default=None, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_id', default=None, null=True, blank=True)
    favourite = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class RatingUser(models.Model):
    rate_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='rate_user', default=None, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='rate_by_user', default=None, null=True, blank=True)
    group = models.ForeignKey(UserGoal, on_delete=models.CASCADE, default=None, null=True, blank=True)
    rating = models.CharField(max_length=255, blank=True, null=True)
    review = models.TextField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

class PostUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='post_by', default=None, null=True, blank=True)
    title = models.CharField(max_length=255, blank=True, null=True)
    desc = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to='post/', null=True, blank=True)
    video = models.FileField(upload_to='post_video/',null=True,  blank=True)
    youtube_id = models.CharField(max_length=255, null=True, blank=True)
    # validators=[FileExtensionValidator(allowed_extensions=['MOV','avi','mp4','webm','mkv'])])
    slug = models.CharField(max_length=50, unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)

class PostImages(models.Model):
    post = models.ForeignKey(PostUser, on_delete=models.CASCADE, related_name='post_image')
    image = models.ImageField(upload_to='post/', null=True, blank=True)

class FavouritePost(models.Model):
    fav_post = models.ForeignKey(PostUser, on_delete=models.CASCADE, related_name='fav_post', default=None, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fav_user_post', default=None, null=True, blank=True)
    favourite = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class FollowUser(models.Model):
    follow_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='follow_user', default=None, null=True, blank=True)
    following_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='following_user', default=None, null=True, blank=True)
    user_email = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_email', default=None, null=True, blank=True)
    req_status = models.BooleanField(default=False)
    approve_status = models.BooleanField(default=False)
    follow = models.BooleanField(default=False)
    following = models.BooleanField(default=False)
    slug = models.CharField(max_length=50, unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)

class SubGoal(models.Model):
    sub_goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='sub_goals', default=None, null=True, blank=True)
    sub_goal_name = models.CharField(max_length=255, blank=True, null=True)
    sub_start_date = models.DateTimeField(auto_now=False)
    sub_goal_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created = models.DateTimeField(auto_now_add=True)

class HomeAPI(models.Model):
    name = models.CharField(max_length=255, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

class HomeSlider(models.Model):
    home_api = models.ForeignKey(HomeAPI, on_delete=models.CASCADE, related_name='home_api_slider', default=None, null=True, blank=True)
    images = models.ImageField(upload_to='home-slider/', null=True, blank=True)
   
class HomeAboutUs(models.Model):
    home_api = models.ForeignKey(HomeAPI, on_delete=models.CASCADE, related_name='home_api_aboutus', default=None, null=True, blank=True)
    text = models.TextField()

class HomeTestimonial(models.Model):
    home_api = models.ForeignKey(HomeAPI, on_delete=models.CASCADE, related_name='home_api_testimonial', default=None, null=True, blank=True)
    images = models.ImageField(upload_to='homeAPI-testimonial/', null=True, blank=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    text = models.TextField()
    designation = models.CharField(max_length=255, blank=True, null=True)

class Room(models.Model):
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user1', default=None, null=True, blank=True)
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user2', default=None, null=True, blank=True)
    room = models.CharField(max_length=254, default=None, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class Chat(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender', default=None, null=True, blank=True)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receiver', default=None, null=True, blank=True)
    room_id = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='room_id', default=None, null=True, blank=True)
    message = models.TextField(default=None, null=True, blank=True)
    # image = models.ImageField(upload_to='chat_image/', null=True, blank=True)
    # video = models.FileField(upload_to='chat_video/', null=True,  blank=True)
    created = models.DateTimeField(auto_now_add=True)

class ChatGroup(models.Model):
    group_name = models.CharField(max_length=255, null=True, blank=True, unique=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, related_name='groupchat_goal', default=None, null=True, blank=True)
    members = models.CharField(max_length=255, null=True, blank=True)
    room_id = models.CharField(max_length=50, unique=True, null=True, blank=True)
    owner = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class GroupMassage(models.Model):
    group = models.ForeignKey(ChatGroup, on_delete=models.CASCADE, related_name='chatgroup_id', default=None, null=True, blank=True)
    sender = models.CharField(max_length=255, null=True, blank=True)
    receiver = models.CharField(max_length=255, null=True, blank=True)
    chat_massage = models.TextField()
    created = models.DateTimeField(auto_now_add=True)

class GetInTouch(models.Model):
    mobile = models.CharField(max_length=254, default=None, null=True, blank=True)
    email = models.EmailField(default=None, null=True, blank=True)
    location = models.CharField(max_length=254, default=None, null=True, blank=True)

class GoalPayment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=None, null=True, blank=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, default=None, null=True, blank=True)
    # amount = models.CharField(max_length=100, default=None, null=True, blank=True)
    payment_due = models.CharField(max_length=100, default=None, null=True, blank=True)
    payment_paid = models.CharField(max_length=100, default=None, null=True, blank=True)
    transaction_id = models.CharField(max_length=100, default=None, null=True, blank=True)
    payment_status = models.CharField(max_length=255, choices=GOAL_PAYMENT_STATUS, default='PENDING')
    created = models.DateTimeField(auto_now_add=True)

class PostLikeDislike(models.Model):
    post = models.ForeignKey(PostUser, on_delete=models.CASCADE, default=None, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=None, null=True, blank=True)
    post_like = models.BooleanField(default=False)
    post_dislike = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class PostViewCount(models.Model):
    post = models.ForeignKey(PostUser, on_delete=models.CASCADE, default=None, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=None, null=True, blank=True)
    post_view = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class GoalOrder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=None, null=True, blank=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, default=None, null=True, blank=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, default=None, null=True, blank=True)
    order_id = models.CharField(max_length=100, default=None, null=True, blank=True)
    status = models.CharField(max_length=255, choices=ORDER_STATUS, default='PENDING')
    invoice_request = models.BooleanField(default=False)
    payment_status = models.CharField(max_length=255, choices=ORDER_STATUS, default='PENDING')
    created = models.DateTimeField(auto_now_add=True)

class GroupAdminQuestion(models.Model):
    questions = models.CharField(max_length=100, null=True, blank=True)
    slug = models.CharField(max_length=50, unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)

class GroupQuestion(models.Model):
    group = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    questions = models.CharField(max_length=100, null=True, blank=True)
    answer = models.CharField(max_length=100, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class GoalComment(models.Model):
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    comment = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to='goal-comment/', null=True, blank=True)
    avg_rating = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class GoalCommentRating(models.Model):
    comment = models.ForeignKey(GoalComment, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    rating = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class PaymentToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    token = models.CharField(max_length=100, null=True, blank=True)
    card_id = models.CharField(max_length=100, null=True, blank=True)
    default_payment = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class GoalDonation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    transaction_id = models.CharField(max_length=100, null=True, blank=True)
    status = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)

class GoalLeaveRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    request = models.BooleanField(default=False)
    approve = models.BooleanField(default=False)
    reject = models.BooleanField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class GoalPoll(models.Model):
    goal_member = models.ForeignKey(User, related_name='member', on_delete=models.CASCADE, null=True, blank=True)
    leave_user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    is_poll = models.BooleanField(default=False)
    approve = models.BooleanField(default=False)
    remove_self = models.BooleanField(default=False)
    remove_admin = models.BooleanField(default=False)
    due_date = models.DateField(auto_now_add=False)
    created = models.DateTimeField(auto_now_add=True)

class SubscriptionPlan(models.Model):
    plan_type = models.CharField(max_length=50, null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    subscription_price_id = models.CharField(max_length=255, null=True, blank=True)
    plan_id = models.CharField(max_length=255, null=True, blank=True)
    product_count = models.CharField(max_length=255, null=True, blank=True)
    days = models.CharField(max_length=255, null=True, blank=True)
    description = models.CharField(max_length=255, null=True, blank=True)
    free_trail = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

class SubscriptionUsed(models.Model):
    subscription_plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    used = models.BooleanField(default=False)

class VendorSubscription(models.Model):
    vendor = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE, null=True, blank=True)
    customer_id = models.CharField(max_length=255,null=True,blank=True)
    subscription_id = models.CharField(max_length=255,null=True,blank=True)
    start_at = models.DateTimeField(blank=True, null=True)
    expire_at = models.DateTimeField(blank=True, null=True)
    # slug = models.CharField(max_length=50, unique=True, default=uuid.uuid4)

class GoalAmountPlan(models.Model):
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    members = models.CharField(max_length=255, null=True, blank=True)
    product_id = models.CharField(max_length=255, null=True, blank=True)
    price_id = models.CharField(max_length=255, null=True, blank=True)
    start_at = models.DateTimeField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

class UserSubscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    plan = models.CharField(max_length=255,null=True,blank=True)
    customer_id = models.CharField(max_length=255,null=True,blank=True)
    subscription_id = models.CharField(max_length=255,null=True,blank=True)
    price_id = models.CharField(max_length=255, null=True, blank=True)
    start_at = models.DateTimeField(blank=True, null=True)
    next_billing_date = models.DateTimeField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)

class GoalSubscriptionTransaction(models.Model):
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    customer_id = models.CharField(max_length=255,null=True,blank=True)
    subscription_id = models.CharField(max_length=255,null=True,blank=True)
    product_id = models.CharField(max_length=255,null=True,blank=True)
    amount = models.CharField(max_length=255,null=True,blank=True)
    created = models.DateTimeField(auto_now_add=True)

class AdminCommission(models.Model):
    amount_percentage = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class UserNotification(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notification_receiver', null=True, blank=True)
    notification_type = models.CharField(max_length=30, choices=NOTIFICATION_TYPE, null=True, blank=True)
    notification = models.CharField(max_length=255, null=True, blank=True)
    notification_id = models.CharField(max_length=255, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

class VendorInvoice(models.Model):
    vendor = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    goal = models.ForeignKey(UserGoal, on_delete=models.CASCADE, null=True, blank=True)
    order_id = models.CharField(max_length=255,null=True,blank=True)
    transaction_id = models.CharField(max_length=255,null=True,blank=True)
    status = models.CharField(max_length=255, choices=GOAL_PAYMENT_STATUS, default='PENDING')
    amount = models.CharField(max_length=255,null=True,blank=True)
    payment_date = models.DateTimeField(auto_now_add=False,null=True,blank=True)
    amount_date = models.DateField(auto_now_add=False,null=True,blank=True)
    slug = models.CharField(max_length=50, unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        previous_id = VendorInvoice.objects.last()
        if previous_id:
            data = previous_id.transaction_id.split('_')
            data2 = int(data[-1])+1
            self.transaction_id = 'trn_'+str(data2)
        else:
            self.transaction_id = 'trn_1000'
        super(VendorInvoice, self).save(*args, **kwargs)

# class SlideApp(models.Model):
#     title = models.CharField(max_length=255, null=True, blank=True)
#     image = models.ImageField(upload_to='web-home-slider/', null=True, blank=True)
#     desc = models.TextField()
#     created = models.DateTimeField(auto_now_add=True)


    