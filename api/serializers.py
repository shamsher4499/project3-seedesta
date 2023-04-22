from superadmin.models import *
from rest_framework import serializers
import stripe
from django.db.models import Q, Sum
from datetime import date
import datetime
from django.conf import Settings
from .utils import currency_convertor

class RegitserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'country_code', 'currency', 'user_type', 
        'first_name', 'provider_id', 'provider_name', 'fcm_token', 'last_name', 'mobile', 
        'company_name', 'company_regisration_number', 'company_document', 'company_username', 'user_category']
        
        extra_kwargs = {
            'password': {'write_only': True}
        }

    if 'user_type' == 'VENDOR':
        def create(self, validated_data):
            user = User.objects.create(email = validated_data['email'], 
            user_type = validated_data['user_type'], mobile = validated_data['mobile'], 
            company_name = validated_data['company_name'], company_regisration_number = validated_data['company_regisration_number'], 
            company_document = validated_data['company_document'], company_username = validated_data['company_username'])
            user.set_password(validated_data['password'])
            user.save()
            return user

    elif 'user_type' == 'USER':
        def create(self, validated_data):
            user = User.objects.create(email = validated_data['email'], user_type = validated_data['user_type'], 
            first_name = validated_data['first_name'], last_name = validated_data['last_name'], mobile = validated_data['mobile'],)
            user.set_password(validated_data['password'])
            user.save()
            return user
        
        def update(self, user, validated_data):
            user.first_name = validated_data["first_name"]
            user.last_name = validated_data["last_name"]
            user.save()
            return user

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    fcm_token = serializers.CharField(required=False, allow_blank=True)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    fcm_token = serializers.CharField(required=False, allow_blank=True)

class LocationUpdateSerializer(serializers.Serializer):
    latitude = serializers.CharField()
    longitude = serializers.CharField()

class MobileLoginSerializer(serializers.Serializer):
    mobile = serializers.CharField(required=False, allow_blank=True)

class MobileVerifyOTPSerializer(serializers.Serializer):
    mobile = serializers.CharField(required=False, allow_blank=True)
    otp = serializers.CharField(required=False, allow_blank=True)
    fcm_token = serializers.CharField()

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class AppSliderSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppSlider
        fields = ['id', 'title', 'image', 'desc',]

class UserViewSerializer(serializers.ModelSerializer):
    total_review = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['id', 'email',  'user_type', 'profile_pic', 'first_name', 'last_name', 'country_code', 
        'mobile', 'avg_rating', 'user_category', 'total_review', 'customer_id', 'currency', 'location_settings', 
        'notification_settings', 'latitude', 'longitude', 'is_verified', 'is_active', 'created']
    
    def get_total_review(self, instance):
        user = User.objects.get(email=instance.email)
        try:
            user_review = RatingUser.objects.filter(rate_user_id=user.id).count()
        except:
            user_review = None
        if user_review:
            return user_review
        else:
            return 0

class VendorViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email',  'user_type', 'profile_pic', 'company_name', 'first_name', 'last_name', 
        'company_regisration_number', 'company_username', 'company_document', 'country_code', 'mobile', 
        'customer_id', 'currency', 'notification_settings', 'is_verified', 'is_active', 'created']

class UserChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

class UserChangePasswordMobileSerializer(serializers.Serializer):
    mobile = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

class UserResetPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()

class UserChangePasswordMailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class UserChangePasswordVerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

class UserProfileViewSerializer(serializers.Serializer):
    first_name = serializers.CharField()
    last_name = serializers.CharField()

class UsreProfilePicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        field = ['profile_pic']
        exclude = ('email',  'user_type', 'first_name', 'last_name', 'country_code', 'mobile', 'currency',
        'is_verified', 'is_active', 'created', 'last_login', 'is_superuser', 'is_staff', 
        'date_joined', 'password', 'company_name', 'company_regisration_number', 'company_document', 
        'company_username', 'otp', 'slug', 'groups', 'user_permissions')

class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = ['name', 'email', 'subject', 'message']
        
class AboutUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AboutUsApp
        fields = ['editor']

class TermsConditionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TermsCondition
        fields = ['editor']

class PrivacyPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = PrivacyPolicy
        fields = ['editor']

class HelpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Help
        fields = ['id', 'question', 'answer']

class NotificationSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        field = ['notification_settings']
        exclude = ('email',  'user_type', 'first_name', 'last_name', 'country_code', 'mobile', 'currency', 'is_verified', 
        'is_active', 'created', 'last_login', 'is_superuser', 'is_staff', 'date_joined', 'password', 
        'company_name', 'company_regisration_number', 'company_document', 'company_username', 'otp', 
        'slug', 'groups', 'user_permissions', 'profile_pic',)

class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        field = ['location_settings']
        exclude = ('email',  'user_type', 'first_name', 'last_name', 'country_code', 'mobile', 'currency', 
        'is_verified', 'is_active', 'created', 'last_login', 'is_superuser', 
        'is_staff', 'date_joined', 'password', 'company_name', 'company_regisration_number', 
        'company_document', 'company_username', 'otp', 'slug', 'groups', 'user_permissions', 
        'profile_pic', 'notification_settings')

class TicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = ['id', 'question',]

    def validate_question(self, value):
        if value == '':
            raise serializers.ValidationError('Please select above questions.')
        return value

class RaiseTicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = RaiseTicket
        fields = ['ticket_num']

class ProductImageSerializer(serializers.ModelSerializer):
    image=serializers.SerializerMethodField()
    class Meta:
        model = ProductImages
        # fields = '__all__'
        fields = ['id', 'image']

    def get_image(self, obj):
        re=self.context.get('request')
        try:
            x=re.build_absolute_uri(obj.image.url)
        except:
            x=None
        return x
    
class ProductSerializer(serializers.ModelSerializer):
    product_image =  ProductImageSerializer(many=True, read_only=True) 
    favourite = serializers.SerializerMethodField()
    price = serializers.SerializerMethodField()
    class Meta:
        model = Product
        fields = ['id', 'category', 'name', 'product_image', 'favourite', 'price', 
        'desc', 'user', 'return_period', 'return_time_from', 'return_time_to', ]
        
    def validate(self, data):
        if not data['category']:
            raise serializers.ValidationError("Category field must be entered.")
        if not data['name']:
            raise serializers.ValidationError("Name field must be entered.")
        if not data['price']:
            raise serializers.ValidationError("Price field must be entered.")
        if not data['desc']:
            raise serializers.ValidationError("Descprition field must be entered.")
        return data

    def get_favourite(self, instance):
        request = self.context.get('request', None)
        try:
            fav_post = FavouriteProduct.objects.filter(product_id = instance, user_id = request.user, favourite=1)
        except:
            fav_post = None
        if fav_post:
            return True
        else:
            return False

    def get_price(self, instance):
        request = self.context.get('request', None)
        request = self.context.get('request', None)
        try:
            user = User.objects.get(id=request.user.id)
        except:
            user = None
        if user:
            con_amount = currency_convertor(instance.amount, user.currency)
            return con_amount
        return instance.amount

class MembersSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class MemberSerializer(serializers.ModelSerializer):
    goal_member = RegitserSerializer(many=True, read_only = True)
    class Meta:
        model = GoalMember
        fields = ['first_name', 'last_name', 'profile_pic', 'goal_member']
        depth = 1

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentPlan
        fields = '__all__'

class FavouriteGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = FavouriteGoal
        fields = '__all__'
        depth = 1

class FavouriteUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = FavouriteUser
        fields = '__all__'
        depth = 1

class RatingUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = RatingUser
        fields = '__all__'
        depth = 1

class FollowUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = FollowUser
        fields = '__all__'
        depth = 1

class SubGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubGoal
        fields = '__all__'

class UserGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGoal
        fields = '__all__'
        depth = 1

class UserGoalPersonalSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGoal
        fields = '__all__'
        depth = 1

class GoalSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    fav_goal = FavouriteGoalSerializer(many=True, read_only=True)
    sub_goals = SubGoalSerializer(read_only=True, many=True)
    goal_id = MemberSerializer(read_only=True, many=True)
    class Meta:
        model = UserGoal
        fields = ['id', 'goal_name', 'goal_as', 'goal_priority', 'payment_method', 'goal_type', 
        'start_date', 'goal_amount', 'goal_desc', 'status', 'created', 'user', 'product', 'payment_plan', 
        'fav_goal', 'sub_goals', 'goal_id']
       
        extra_kwargs = {
            'user': {'required': False},
            'product': {'required': False},
            'members': {'required': False},
            'sub_goal': {'required': False},
        }
    
    def validate(self, data):
        if not data['goal_as']:
            raise serializers.ValidationError("Goal as field must be entered.")
        if not data['goal_name']:
            raise serializers.ValidationError("Goal name field must be entered.")
        if not data['payment_method']:
            raise serializers.ValidationError("Payment method field must be entered.")
        if not data['goal_priority']:
            raise serializers.ValidationError("Goal Priority must be entered.")
        if not data['goal_type']:
            raise serializers.ValidationError("Goal Type field must be entered.")
        if not data['start_date']:
            raise serializers.ValidationError("Start Date field must be entered.")
        if not data['goal_amount']:
            raise serializers.ValidationError("Goal Amount field must be entered.")
        if not data['goal_desc']:
            raise serializers.ValidationError("Goal Description field must be entered.")
        return data

class GoalMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalMember
        fields = '__all__'
        depth = 1
 
class HomeSliderSerializer(serializers.ModelSerializer):
    images=serializers.SerializerMethodField()
    class Meta:
        model = HomeSlider
        fields = ['id', 'images']

    def get_images(self, obj):
        re=self.context.get('request')
        try:
            x=re.build_absolute_uri(obj.images.url)
        except:
            x=None
        return x

class HomeAboutUsSerializer(serializers.ModelSerializer):
    text=serializers.SerializerMethodField()
    class Meta:
        model = HomeAboutUs
        fields = ['id', 'text']

    def get_text(self, obj):
        x = obj.text
        return x

class HomeTestimonialSerializer(serializers.ModelSerializer):
    images=serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    text = serializers.SerializerMethodField()
    designation = serializers.SerializerMethodField()
    class Meta:
        model = HomeTestimonial
        fields = ['id', 'images', 'name', 'text', 'designation']

    def get_images(self, obj):
        re=self.context.get('request')
        try:
            x=re.build_absolute_uri(obj.images.url)
        except:
            x=None
        return x
    
    def get_name(self, obj):
        x=obj.name
        return x

    def get_text(self, obj):
        x=obj.text
        return x

    def get_designation(self, obj):
        x=obj.designation
        return x

class HomeAPISerializer(serializers.ModelSerializer):
    home_api_slider =  HomeSliderSerializer(many=True, read_only=True) 
    home_api_aboutus =  HomeAboutUsSerializer(many=True, read_only=True) 
    home_api_testimonial =  HomeTestimonialSerializer(many=True, read_only=True) 
    class Meta:
        model = HomeAPI
        fields = ['id', 'home_api_slider', 'home_api_aboutus', 'home_api_testimonial']
   
class FavouriteGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = FavouriteGoal
        fields = '__all__'
        depth = 1

class UserDetailsSerializer(serializers.ModelSerializer):
    fav_goal =  FavouriteGoalSerializer(many=True, read_only=True) 
    total_review = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['email', 'user_type', 'first_name', 'last_name', 'country_code', 'mobile', 'currency', 'avg_rating', 
        'total_review', 'company_name', 'company_regisration_number', 'company_document', 'company_username', 'user_category', 'fav_goal']

    def get_total_review(self, instance):
        request = self.context.get('request', None)
        try:
            user_review = RatingUser.objects.filter(rate_user_id=request.user.id).count()
        except:
            user_review = None
        if user_review:
            return user_review
        else:
            return 0

class PostImageSerializer(serializers.ModelSerializer):
    image=serializers.SerializerMethodField()
    class Meta:
        model = PostImages
        # fields = '__all__'
        fields = ['id', 'image']
        extra_kwargs = {
            'image': {'required': False}
        }
        # depth = 1
    def get_image(self, obj):
        re=self.context.get('request')
        try:
            x=re.build_absolute_uri(obj.image.url)
        except:
            x=None
        return x

class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = PostUser
        fields = '__all__'
        depth = 1

class FavouritePostSerializer(serializers.ModelSerializer):
    class Meta:
        model = FavouritePost
        fields = '__all__'
        depth = 1

class UserDetailsPageSerializer(serializers.ModelSerializer):
    total_review = serializers.SerializerMethodField()
    class Meta:
        model = User
        # fields = '__all__'
        fields = ['email', 'user_type', 'first_name', 'profile_pic', 'last_name', 'country_code', 'mobile', 'currency',
        'avg_rating', 'total_review', 'company_name', 'company_regisration_number', 'company_document', 
        'company_username', 'user_category', 'location_settings', 'latitude', 'longitude']
    
    def get_total_review(self, instance):
        request = self.context.get('request', None)
        try:
            user_review = RatingUser.objects.filter(rate_user_id=request.user.id).count()
        except:
            user_review = None
        if user_review:
            return user_review
        else:
            return 0

class GroupGoalSerializer(serializers.ModelSerializer):
    # user_id = serializers.RelatedField(source='user', read_only=True)
    class Meta:
        model = GoalGroup
        fields = ['id', 'user', 'goal', 'group_name', 'group_desc']
        depth = 1

class ProductTestingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'

class GoalTestingSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserGoal
        fields = '__all__'

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['product'] = ProductTestingSerializer(instance.product).data
        return rep

class GoalMemberTestingSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalMember
        fields = '__all__'
        depth = 1
 
    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['goal'] = GoalTestingSerializer(instance.goal).data
        return rep

class GoalSubGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubGoal
        fields = '__all__'
        depth = 1
 
class GoalTestingViewSerializer(serializers.ModelSerializer):
    members = serializers.SerializerMethodField()
    admin = serializers.SerializerMethodField()
    group_room_id = serializers.SerializerMethodField()
    donation = serializers.SerializerMethodField()
    leave_request = serializers.SerializerMethodField()
    leave_request_count = serializers.SerializerMethodField()
    poll_data = serializers.SerializerMethodField()
    accept_member = serializers.SerializerMethodField()
    request_member = serializers.SerializerMethodField()
    paymant_plan_status = serializers.SerializerMethodField()
    goal_amount = serializers.SerializerMethodField()
    class Meta:
        model = UserGoal
        fields = '__all__'
        fields = ['id', 'goal_name', 'group_room_id', 'goal_as', 'goal_priority', 'goal_type', 'payment_method', 
        'plan_status', 'stripe_customer_id','stripe_subscription_id', 'start_date', 'goal_amount', 'donation', 
        'goal_desc', 'request_member', 'accept_member', 'status', 'group_name', 'group_desc', 'created', 
        'leave_request_count', 'leave_request', 'paymant_plan_status', 'poll_data', 'members', 'admin']

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['product'] = ProductTestingSerializer(instance.product).data
        rep['payment_plan'] = PaymentSerializer(instance.payment_plan).data
        rep['user'] = RegitserSerializer(instance.user).data
        return rep
    
    def get_members(self, instance):
        goal_list = []
        try:
            goal_member = GoalMember.objects.filter(goal_id = instance.id, approve=1, request=0)
        except:
            goal_member = None
        if goal_member:
            for i in goal_member:
                goal_list.append(i.members_id)
            return goal_list
        else:
            return goal_list
    
    def get_admin(self, instance):
        admin_list = []
        try:
            goal_admin = GoalGroupAdmin.objects.filter(group_goal_id = instance.id, approve=1)
        except:
            goal_admin = None
        if goal_admin:
            for i in goal_admin:
                admin_list.append(i.user_id)
            return admin_list
        else:
            return admin_list

    def get_group_room_id(self, instance):
        try:
            group_chat = ChatGroup.objects.get(goal_id = instance.id)
        except:
            group_chat = None
        if group_chat:
            return group_chat.room_id
        else:
            return False

    def get_donation(self, instance):
        try:
            donation = GoalDonation.objects.filter(goal_id = instance.id)
        except:
            donation = None
        total_amount = []
        if donation:
            for i in donation:
                total_amount.append(float(i.amount))
            return sum(total_amount)
        else:
            return 0

    def get_leave_request(self, instance):
        request = self.context.get('request', None)
        try:
            leave_request = GoalLeaveRequest.objects.get(goal_id = instance.id, user_id=request.user.id)
        except:
            leave_request = None
        if leave_request:
            leave_data = GoalLeaveRequestSerializer(leave_request)
            return leave_data.data
        else:
            return None

    def get_leave_request_count(self, instance):
        try:
            leave_request = GoalLeaveRequest.objects.filter(goal_id = instance.id).count()
        except:
            leave_request = None
        if leave_request:
            return leave_request
        else:
            return 0

    def get_poll_data(self, instance):
        request = self.context.get('request', None)
        try:
            poll = GoalPoll.objects.get(goal_id = instance.id, goal_member_id=request.user.id)
        except:
            poll = None
        if poll:
            user_poll = GoalPollSerializer(poll)
            return user_poll.data
        else:
            return None

    def get_accept_member(self, instance):
        try:
            goal = UserGoal.objects.get(id = instance.id)
        except:
            goal = None
        if goal:
            approve = []
            reject = []
            try:
                goal_poll = GoalPoll.objects.filer(goal_id=goal.id)
            except: 
                goal_poll = None
            if goal_poll:
                for i in goal_poll:
                    if i.is_poll == 1:
                        if i.approve == 1:
                            approve.append(1)
                        else:
                            reject.append(1)
                    else:
                        pass
                if str(approve.count) >= str(reject.count) or str(approve.count) == str(reject.count):
                    goal.accept_members = 1
                    goal.save()
            goal_date = goal.start_date
            if goal_date.date() > date.today():
                return True
            else:
                goal.accept_members = False
                goal.save()
                return False
        else:
            return None

    def get_request_member(self, instance):
        request = self.context.get('request', None)
        try:
            goal = RequestGoal.objects.filter(goal_id = instance.id, member=request.user.id, request=1).count()
        except:
            goal = None
        if goal:
            return goal
        else:
            return 0

    def get_paymant_plan_status(self, instance):
        try:
            goal_plan = GoalAmountPlan.objects.get(goal_id = instance.id)
        except:
            goal_plan = None
        if goal_plan:
            if GoalAmountPlan.objects.filter(goal_id = instance.id).exists():
                if goal_plan.start_at != None:
                    return True
                else:
                    return False
            else:
                return 'Goal Not found.'
        else:
            pass

    def get_goal_amount(self, instance):
        request = self.context.get('request', None)
        try:
            user = User.objects.get(id=request.user.id)
        except:
            user = None
        if user:
            amount = currency_convertor(instance.goal_amount, user.currency)
            return amount

class UserGoalDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalMember
        fields = '__all__'

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['goal'] = GoalTestingViewSerializer(instance.goal).data
        return rep

class GoalMemberRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalMember
        fields = '__all__'
 
    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['goal'] = GoalTestingViewSerializer(instance.goal).data
        return rep

class GoalMembersViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalMember
        fields = '__all__'

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['members'] = GoalMemberSerializer(instance.members).data
        return rep

class GoalMemberListingSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalMember
        fields = '__all__'

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['goal'] = UserGoalSerializer(instance.goal).data
        rep['members'] = RegitserSerializer(instance.members).data
        return rep
 
class FavouriteProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = FavouriteProduct
        fields = '__all__'

class FavouriteProductGETSerializer(serializers.ModelSerializer):
    class Meta:
        model = FavouriteProduct
        fields = '__all__'

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['product'] = ProductSerializer(instance.product).data
        rep['user'] = RegitserSerializer(instance.user).data
        return rep

class RequestGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = RequestGoal
        fields = '__all__'

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['user'] = RegitserSerializer(instance.user).data
        rep['goal'] = UserGoalSerializer(instance.goal).data
        return rep

class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Room
        fields = '__all__'
        depth = 1

class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = '__all__'
        depth = 1

class UserRoomSerializer(serializers.ModelSerializer):
    chat = serializers.SerializerMethodField()
    user = serializers.SerializerMethodField()
    class Meta:
        model = Room
        # fields = '__all__'
        fields = ['id', 'room', 'chat', 'user', 'user1_id', 'user2_id']
        # depth = 1
    

    def get_chat(self, instance):
        msg_obj=Chat.objects.filter(room_id=instance)
        data=list(msg_obj)
        if data:
            x=data[-1]
            msg = x.message
            # sender = x.sender_id
            # receiver = x.receiver_id
            time_data = x.created
            return msg, time_data
        else:
            return None

    def get_user(self, instance):
        request = self.context.get('request', None)
        if request.user.id == instance.user1_id:
            name_obj = User.objects.get(id=instance.user2_id)
        elif request.user.id == instance.user2_id:
            name_obj = User.objects.get(id=instance.user1_id)
        if name_obj.profile_pic:
            return name_obj.first_name +' '+ name_obj.last_name, name_obj.profile_pic.url
        else:
            return name_obj.first_name +' '+ name_obj.last_name

class ChatRoomViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = '__all__'

class ChatViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = '__all__'
    
        # depth = 1

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['sender'] = UserDetailsPageSerializer(instance.sender).data
        rep['receiver'] = UserDetailsPageSerializer(instance.receiver).data
        return rep

class GroupChatSerializer(serializers.ModelSerializer):
    chat = serializers.SerializerMethodField()
    class Meta:
        model = ChatGroup
        # fields = '__all__'
        fields = ['id', 'group_name', 'chat', 'room_id', 'members']
        # depth = 1

    def get_chat(self, instance):
        msg_obj=GroupMassage.objects.filter(group_id=instance)
        data=list(msg_obj)
        if data:
            x=data[-1]
            msg = x.chat_massage
            time_data = x.created
            return msg, time_data
        else:
            return None

class GroupRoomChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMassage
        fields = '__all__'
        depth = 1

class PostLikeSerializer(serializers.ModelSerializer):
    total_like = serializers.SerializerMethodField()
    total_dislike = serializers.SerializerMethodField()
    class Meta:
        model = PostLikeDislike
        fields = ['post_like', 'post_dislike', 'total_like', 'total_dislike', 'post_id']
        depth = 1

    def get_total_like(self, instance):
        try:
            post_like = PostLikeDislike.objects.filter(post_id = instance.post_id, post_like=1).count()
        except:
            post_like = None
        if post_like:
            return post_like
        else:
            return 0

    def get_total_dislike(self, instance):
        try:
            post_dislike = PostLikeDislike.objects.filter(post_id = instance.post_id, post_dislike=1).count()
        except:
            post_dislike = None
        if post_dislike:
            return post_dislike
        else:
            return 0

class PostDetailSerializer(serializers.ModelSerializer):
    view = serializers.SerializerMethodField()
    favourite = serializers.SerializerMethodField()
    user_like = serializers.SerializerMethodField()
    user_dislike = serializers.SerializerMethodField()
    total_like = serializers.SerializerMethodField()
    total_dislike = serializers.SerializerMethodField()
    total_view = serializers.SerializerMethodField()

    class Meta:
        model = PostUser
        fields = ['id', 'user', 'title', 'view', 'favourite', 'user_like', 'user_dislike', 'total_view', 
        'total_like', 'total_dislike', 'image', 'desc', 'video', 'youtube_id', 'created']
        depth = 1

    def get_view(self, instance):
        request = self.context.get('request', None)
        try:
            post_view = PostViewCount.objects.get(post_id = instance, user_id = request.user, post_view=1)
        except:
            post_view = None
        if post_view:
            return True
        else:
            return False

    def get_favourite(self, instance):
        request = self.context.get('request', None)
        try:
            fav_post = FavouritePost.objects.get(fav_post_id = instance, user_id = request.user, favourite=1)
        except:
            fav_post = None
        if fav_post:
            return True
        else:
            return False

    def get_total_like(self, instance):
        try:
            post_like = PostLikeDislike.objects.filter(post_id = instance, post_like=1).count()
        except:
            post_like = None
        if post_like:
            return post_like
        else:
            return 0

    def get_total_dislike(self, instance):
        try:
            post_dislike = PostLikeDislike.objects.filter(post_id = instance, post_dislike=1).count()
        except:
            post_dislike = None
        if post_dislike:
            return post_dislike
        else:
            return 0

    def get_total_view(self, instance):
        try:
            post_view = PostViewCount.objects.filter(post_id = instance, post_view=1).count()
        except:
            post_view = None
        if post_view:
            return post_view
        else:
            return 0

    def get_user_like(self, instance):
        request = self.context.get('request', None)
        try:
            post_like = PostLikeDislike.objects.get(post_id=instance, user_id=request.user, post_like=1)
        except:
            post_like = None
        if post_like:
            return True
        else:
            return False

    def get_user_dislike(self, instance):
        request = self.context.get('request', None)
        try:
            post_dislike = PostLikeDislike.objects.get(post_id=instance, user_id=request.user, post_dislike=1)
        except:
            post_dislike = None
        if post_dislike:
            return True
        else:
            return False

class PostCountSerializer(serializers.ModelSerializer):
    class Meta:
        model = PostViewCount
        fields = '__all__'
        
    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['post'] = PostDetailSerializer(instance.post).data
        return rep

class GoalOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalOrder
        fields = '__all__'
        depth = 1
        
class CheckSocialLoginSerializer(serializers.Serializer):
    provider_id = serializers.CharField()
    fcm_token = serializers.CharField()

class RegisterUserSocialSerializer(serializers.Serializer):
    provider_id = serializers.CharField()
    provider_name = serializers.CharField()
    fcm_token = serializers.CharField()
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    mobile = serializers.CharField()
    user_type = serializers.CharField()

class RegisterVendorSocialSerializer(serializers.Serializer):
    provider_id = serializers.CharField()
    provider_name = serializers.CharField()
    fcm_token = serializers.CharField()
    email = serializers.EmailField()
    company_name = serializers.CharField()
    company_username = serializers.CharField()
    company_username = serializers.CharField()
    company_regisration_number = serializers.CharField()
    mobile = serializers.CharField()
    user_type = serializers.CharField()

class GroupQuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupAdminQuestion
        fields = '__all__'

class GoalQuestionAnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupQuestion
        fields = '__all__'
        depth = 1

class GoalCommentSerializer(serializers.ModelSerializer):
    rating = serializers.SerializerMethodField()
    class Meta:
        model = GoalComment
        # fields = '__all__'
        fields = ['id', 'comment', 'avg_rating', 'rating', 'image', 'created', 'user', 'goal']
        depth = 1

    def get_rating(self, instance):
        request = self.context.get('request', None)
        try:
            comment_rating = GoalCommentRating.objects.get(comment_id = instance.id, user_id = request.user)
        except:
            comment_rating = None
        if comment_rating:
            return comment_rating.rating
        else:
            return None

class GoalCommentRatingSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalCommentRating
        fields = '__all__'
        depth = 1

class GoalGroupAdminSerializer(serializers.ModelSerializer):
    super_admin = serializers.SerializerMethodField()
    class Meta:
        model = GoalGroupAdmin
        # fields = '__all__'
        fields = ['id', 'approve', 'super_admin', 'created', 'user', 'group_goal']
        depth = 1

    def get_super_admin(self, instance):
        request = self.context.get('request', None)
        try:
            group_member = GoalMember.objects.get(members_id = request.user, goal_id=instance.group_goal)
        except:
            group_member = None
        if group_member.owner_id == instance.user.id:
            return True
        else:
            return False

class UserMemberViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'profile_pic', 'email', 'avg_rating', 'created']

class GroupMemberListingSerializer(serializers.ModelSerializer):
    members_data = serializers.SerializerMethodField()
    class Meta:
        model = GoalMember
        fields = ['id', 'members_data', 'goal_id']
        depth = 1

    def get_members_data(self, instance):
        request = self.context.get('request', None)
        members_list = []
        try:
            goal_member = GoalMember.objects.filter(goal_id=instance.goal_id, approve=1, request=0).exclude(members_id=request.user)
        except:
            goal_member = None
        if goal_member:
            for i in goal_member:
                try:
                    rate_member = RatingUser.objects.get(group_id=instance.goal_id, rate_user_id=i.members_id, user_id=request.user)
                except:
                    rate_member = None
                user = User.objects.get(id=i.members_id)
                json_user = UserMemberViewSerializer(user)
                if rate_member:
                    rate_user = dict({'rating': rate_member.rating, 'review': rate_member.review})
                else:
                    rate_user = dict({'rating': None, 'review': None})
                data = dict(**json_user.data, **rate_user)
                members_list.append(data)
            return members_list
        else:
            return False

class PaymentTokenSerializer(serializers.ModelSerializer):
    default = serializers.SerializerMethodField()
    brand = serializers.SerializerMethodField()
    last4 = serializers.SerializerMethodField()
    class Meta:
        model = PaymentToken
        fields = ['id', 'user_id', 'card_id', 'brand', 'last4', 'default', 'created']
        depth = 1

    def get_default(self, instance):
        if PaymentToken.objects.filter(card_id=instance.card_id, default_payment=1).exists():
            return True
        else:
            return False

    def get_brand(self, instance):
        try:
            user_token = User.objects.get(id=instance.user_id)
        except:
            user_token = None
        user_card = stripe.Customer.list_sources(
            user_token.customer_id,
            object="card",
            )
        for i in user_card['data']:
            if i['id'] == instance.card_id:
                return i['brand']

    def get_last4(self, instance):
        try:
            user_token = User.objects.get(id=instance.user_id)
        except:
            user_token = None
        user_card = stripe.Customer.list_sources(
            user_token.customer_id,
            object="card",
            )
        for i in user_card['data']:
            if i['id'] == instance.card_id:
                return i['last4']

class GoalDonationSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalDonation
        fields = '__all__'

class GoalLeaveRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalLeaveRequest
        fields = '__all__'

class GoalAdminLeaveRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalLeaveRequest
        fields = '__all__'
        depth = 1

class GoalPollSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoalPoll
        fields = '__all__'

class VendorSubscriptionPlanSerializer(serializers.ModelSerializer):
    duration = serializers.SerializerMethodField()
    activated = serializers.SerializerMethodField()
    subscription_id = serializers.SerializerMethodField()
    price = serializers.SerializerMethodField()
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'plan_type', 'duration', 'product_count', 'subscription_id',  'price', 'description', 'free_trail', 'activated']

    def get_duration(self, instance):
        return 'Monthly'
    
    def get_subscription_id(self, instance):
        request = self.context.get('request', None)
        if VendorSubscription.objects.filter(vendor_id=request.user.id).exists():
            vendor = VendorSubscription.objects.get(vendor_id=request.user.id)
            return vendor.subscription_id
        return None
    
    def get_activated(self, instance):
        request = self.context.get('request', None)
        if VendorSubscription.objects.filter(vendor_id=request.user.id).exists():
            vendor_data = VendorSubscription.objects.get(vendor_id=request.user.id)
            if vendor_data.plan.free_trail == 0:
                subscription_plan =  stripe.Subscription.retrieve(
                    vendor_data.subscription_id,
                    )
                product_details = stripe.Product.retrieve(
                    subscription_plan['items']['data'][0]['price']['product']
                    )
                if VendorSubscription.objects.filter(plan__plan_type=product_details['name']).exists():
                    if instance.plan_type == product_details['name']:
                        return True
                else:
                    return False
            if vendor_data.plan.free_trail == 1:
                if VendorSubscription.objects.filter(plan__plan_type='Free Trail1').exists():
                    if instance.plan_type == 'Free Trail1':
                        return True
                else:
                    return False
        return False

    def get_price(self, instance):
        request = self.context.get('request', None)
        try:
            user = User.objects.get(id=request.user.id)
        except:
            user = None
        if user:
            amount = currency_convertor(instance.price, user.currency)
            return amount

class VendorSubscriptionDetailsSerializer(serializers.ModelSerializer):
    active_plan_id = serializers.SerializerMethodField()
    class Meta:
        model = VendorSubscription
        # fields = '__all__'
        fields = ['id', 'subscription_id', 'customer_id', 'start_at', 'expire_at', 'vendor_id', 'active_plan_id']
        depth = 1

    def get_active_plan_id(self, instance):
        vendor_subscription =  stripe.Subscription.retrieve(
            instance.subscription_id
            )
        vendor_subscription_plan = stripe.Product.retrieve(vendor_subscription['items']['data'][0]['price']['product'])
        vendor_plan = SubscriptionPlan.objects.get(plan_type=vendor_subscription_plan['name'])
        current_plan = VendorSubscription.objects.get(subscription_id=instance.subscription_id)
        current_plan.plan_id = vendor_plan.id
        current_plan.save()
        vendor_plan_serializer = VendorSubscriptionPlanSerializer(vendor_plan)
        return vendor_plan_serializer.data

class GoalPaymentPlanSerializer(serializers.ModelSerializer):
    min_amount = serializers.SerializerMethodField()
    class Meta:
        model = GoalAmountPlan
        fields = ['id', 'goal_id', 'amount', 'min_amount', 'members', 'start_at', 'created']

    def get_min_amount(self, instance):
        goal = UserGoal.objects.get(id=instance.goal_id)
        goal_member = GoalMember.objects.filter(goal_id=instance.goal_id, approve=1).count()
        total_months_emi = goal.goal_amount / goal_member
        return total_months_emi

class GoalSubscriptionPlanSerializer(serializers.ModelSerializer):
    subscription_name = serializers.SerializerMethodField()
    billing_cycle = serializers.SerializerMethodField()
    total_amount_paid = serializers.SerializerMethodField()
    latest_invoice = serializers.SerializerMethodField()
    class Meta:
        model = UserSubscription
        # fields = '__all__'
        fields = ['id', 'billing_cycle', 'subscription_name', 'price_id', 'start_at', 'next_billing_date', 'total_amount_paid', 'latest_invoice', 'created']

    def get_subscription_name(self, instance):
        subscription_plan =  stripe.Subscription.retrieve(
            instance.subscription_id,
            )
        product_details = stripe.Product.retrieve(
            subscription_plan['items']['data'][0]['price']['product']
            )
        return product_details['name']
    
    def get_billing_cycle(self, instance):
        subscription_plan =  stripe.Subscription.retrieve(
            instance.subscription_id,
            )
        return subscription_plan['items']['data'][0]['price']['recurring']['interval']
    
    def get_total_amount_paid(self, instance):
        subscription_plan =  stripe.Subscription.retrieve(
            instance.subscription_id,
            )
        stripe_invoice = stripe.Invoice.retrieve(
            subscription_plan['latest_invoice'],
            )
        return stripe_invoice['amount_paid']

    def get_latest_invoice(self, instance):
        subscription_plan =  stripe.Subscription.retrieve(
            instance.subscription_id,
            )
        stripe_invoice = stripe.Invoice.retrieve(
            subscription_plan['latest_invoice'],
            )
        return stripe_invoice['invoice_pdf']

class UserNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserNotification
        # fields = '__all__'
        fields = ['id', 'notification_type', 'notification', 'notification_id', 'created']

class VendorInvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorInvoice
        fields = '__all__'
        # depth = 1

class VendorRequestInvoiceSerializer(serializers.Serializer):
    order_id = serializers.CharField()
    amount = serializers.CharField()


class VendorTransactionSerializer(serializers.ModelSerializer):
    goal_name = serializers.SerializerMethodField()
    amount = serializers.SerializerMethodField()
    class Meta:
        model = VendorInvoice
        fields = ['id', 'transaction_id', 'amount', 'goal_name', 'payment_date']

    def get_goal_name(self, instance):
        goal = UserGoal.objects.get(id=instance.goal_id)
        return goal.goal_name

    def get_amount(self, instance):
        request = self.context.get('request', None)
        try:
            user = User.objects.get(id=request.user.id)
        except:
            user = None
        if user:
            con_amount = currency_convertor(instance.amount, user.currency)
            return con_amount
        return instance.amount

class VendorTransactioHeadingSerializer(serializers.Serializer):
    total_due_amount = serializers.SerializerMethodField()
    total_received_amount = serializers.SerializerMethodField()
    total_refund_amount = serializers.SerializerMethodField()

    def get_total_due_amount(self, instance):
        request = self.context.get('vendor', None)
        vendor_data = User.objects.get(id=request)
        products = Product.objects.filter(user=vendor_data.email).values_list('id')
        received_payment = VendorInvoice.objects.filter(vendor_id=request, status='COMPLETED').aggregate(received_amount=Sum('amount'))
        return UserGoal.objects.filter(product_id__in=products).aggregate(goal_amount=Sum('goal_amount')).goal_amount - received_payment
        

    def get_total_received_amount(self, instance):
        pass

    def get_total_refund_amount(self, instance):
        pass