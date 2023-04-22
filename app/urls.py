from unicodedata import name
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('about-us/', views.aboutus, name='about_us'),
    path('profile/', views.profile, name='profile'),
    path('contact-us/', views.contactus, name='contact_us'),
    path('contact-us/ajax/', views.contactus_ajax, name='contact_us_ajax'),
    path('terms-conditions/', views.termsCondition, name='terms_condition'),
    path('privacy-policy/', views.privacyPolicy, name='privacy_policy'),
    path('help/', views.help, name='help'),
    path('login/', views.login, name='signin'),
    path("select_user/",views.select_user,name="select_user"),
    path('login/ajax/', views.loginAjax, name='signin_ajax'),
    path('signup/', views.signup, name='signup'),
    path('signup-vendor/ajax/', views.signupVendorAjax, name='signup_vendor_ajax'),
    path('signup-user/ajax/', views.signupUserAjax, name='signup_user_ajax'),
    path('verify/<str:slug>/', views.verifyUser, name='verify-otp'),
    path('logout', views.logoutUser, name='logout'),
    path('forget-password/step1/', views.forgetPassword1, name='forget-password1'),
    path('resend-otp/<str:slug>/', views.resendOtp, name='resend_otp'),
    path('forget-resend-otp/<str:slug>/', views.forgetResendOtp, name='forget_resend_otp'),
    path('forget-password/step2/<str:slug>/', views.forgetPassword2, name='forget-password2'),
    path('forget-password/step3/<str:slug>/', views.forgetPassword3, name='forget-password3'),
    path('favourite-user/', views.favouriteUserListView, name='favourite_user'),
    #-------------------------follow-----------------
    path('follow-user/', views.followerUserListView, name='follow_user'),
    path('following-user/', views.followingUserListView, name='following_user'),
    path('following-req-accept/<slug>', views.followerReqAccept, name='following_req_accept'),
    #------------------------end follow---------------------------------
    path('goals/', views.goalListView, name='goal_lists'),
    path('create-goal/', views.createGoal, name='create_goal'),
    path('admin-user/', views.adminUser, name='admin_user'),
    path('user-queston/', views.userQueston, name='user_queston'),
    path('payment-plan/', views.paymentPlan, name='payment_plan'),
    path('edit-goal/<str:slug>/', views.editGoal, name='edit_goal'),
    path('edit-question/<str:id>/', views.editQuestion, name='edit_question'),
    path('edit-user-list/<str:slug>/', views.editUserList, name='edit_user_list'),



    path('sent-goal-reqaccept/', views.sentGoalReqAccept, name='sent_goal_reqaccept'),
    path('sent-request/<str:slug>/', views.sentRequest, name='sent_request'),
    path('group-goals/', views.groupGoalListView, name='group_goal_list'),
    path('goal-req-accept/', views.goalReqAccept, name='goal_req_accept'),
    path('posts/', views.postListView, name='post_lists'),
    path('create-post/', views.postCreateView, name='post_create'),
    path('all-users/', views.allUserListView, name='all_users'),
    path('user-list/', views.userList, name='user_list'),
    path('user-details/<str:slug>/', views.userDetailsView, name='user_details'),
    path('user-goal/<str:slug>/', views.userGoal, name='user_goal'),
    path('user-group-goal/<str:slug>/', views.userGroupGoal, name='user_group_goal'),   
    path('goal-details/<str:slug>/', views.goalView, name='goal_details'),
    path('user-follow/<str:slug>/', views.userFollow, name='user_follow'),
    path('user-favourite/<str:slug>/', views.userFavourute, name='user_favourite'),
    path('user-favourute-post/<str:slug>/', views.userFavourutePost, name='userFavourutePost'),
    path('user-favourute-goal/<str:slug>/', views.userFavouruteGoal, name='userFavouruteGoal'),
    path('post-like-dislike/<str:slug>/', views.postLike, name='postLike'),
    path('post-user-like-dislike/<str:slug>/', views.postUsertLike, name='postuserLike'),
    path('post-dislike/<str:slug>/', views.postDislike, name='postDislike'),
    path('post-User-dislike/<str:slug>/', views.postUserDislike, name='postuserDislike'),
    path('favourite-delete/<int:id>/', views.favouriteUserDelete, name='favourite_delete'),
    path('goal-donate/', views.goalDonate, name='goal_donate'),
    path('goal-donate-stripe/', views.goalDonateStripe, name='goal_donate_stripe'),
    path('goal-donate-stripe-success/', views.goalDonateStripeSuccess, name='goal_donate_stripe_success'),
    path('user-goal-detail/<str:slug>/', views.userGoalDetail, name='user_goal_detail'),
    path('user-group-goal-detail/<str:slug>/', views.userGroupGoalDetail, name='user_group_goal_detail'),
    path('user-rating/', views.userRating, name='user_rating'),
    path('user-star-rating/', views.userStarRating, name='user_star_rating'),
    path('members-deatils/<str:slug>/', views.membersDeatils, name='members_deatils'),
    path('user-comment/<str:slug>/', views.userComment, name='user_comment'),
    path('users-favourute-goal/<str:slug>/', views.usersFavouruteGoal, name='users_favourute_goal'),
    path('product-list-view/', views.productListView, name='product_list_view'),
    path('product-view/<str:id>/', views.productView, name='product_view'),
    path('edit-product/<str:id>/', views.editProduct, name='edit_product'),
    path('user-payment/', views.userPayment, name='user_payment'),
    path('user-payment-card/', views.userPaymentCard, name='user_payment_card'),
    path('card-delete/<str:id>/', views.cardDelete, name='card_delete'),
    path('card-set-default/<str:id>/', views.cardSetDefault, name='card_set_default'),
    path('goal-start/<str:slug>/', views.goalStart, name='goal_start'),
    path('goal-amount-detail/<str:slug>/', views.goalAmountDetail, name='goal_amount_detail'),
    path('delete-product/<str:id>/', views.deleteProduct, name='delete_product'),
    


#------------------------------------- Vendor ------------------------------------------
    path('vendor-dashboard/', views.vendorDashboardView, name='vendor_dashboard'),
    path('vendor-products/', views.vendorProductListView, name='vendor_products'),
    path('vendor-product-view/', views.vendorProductView, name='vendor_product_view'),
    path('vendor-product-create/', views.vendorProductCreate, name='vendor_product_create'),
    path('vendor-subscription-plan/', views.vendorSubscriptionPlan, name='vendor_subscription_plan'),
    path('vendor-subscription-stripe/<str:plan_type>/', views.vendorSubscriptionStripe, name='vendor_subscription_stripe'),
    path('vendor-subscription-stripe-success/', views.vendorSubscriptionStripeSuccess, name='vendor_subscription_stripe_success'),
    path('delete-subscription/', views.deleteSubscription, name='delete_subscription'),
    path('delete-vendor-product/', views.deleteVendorProduct, name='delete_vendor_product'),
    path('vendor-invoice/', views.vendorInvoice, name='vendor_invoice'),
    path('vendor-order-detail/', views.vendorOrderDetail, name='vendor_order_detail'),
    path('invoice-list/', views.invoiceList, name='invoice_list'),
#----------------------------------------------------------------------------------
    path('location-update/', views.locationUpdate, name='location_update'),
    path('notification-update/', views.notificationUpdate, name='notification_update'),
    path('user-post-detail/<str:slug>/', views.userPostDetail, name='user_post_detail'),
    path('DeletegoalReq/', views.DeletegoalReq, name='DeletegoalReq'),

# --------------------------------Web Chat Start-------------------------------------------
    path('chat', views.web_chat, name="web_chat"),
    path('chat_count', views.chat_count, name="chat_count"),
    path('create_room_for_chat', views.create_room_for_chat, name='create_room_for_chat'),
    path('delete-chat/<str:slug>/', views.delete_chat, name='delete_chat'),
    path('group-web-chat/<str:slug>/', views.group_web_chat, name="group_web_chat"),
    path('create-room-for-group-chat', views.create_room_for_group_chat, name="create_room_for_group_chat"),
    path('get_name_of_sender', views.get_name_of_sender, name='get_name_of_sender'),
# --------------------------------Web Chat End---------------------------------------------


    
    # path('user-post-detail/<str:slug>/', views.favouritePostDelete, name='user_post_detail'),



]