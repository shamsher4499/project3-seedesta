from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.homepage, name='dashboard'),
    path('login/', views.loginSuperAdmin, name='login'),
    path('login/ajax/', views.loginSuperAdminAjax, name='login_ajax'),
    path('tables/', views.tables, name='tables'),
    path('search-users/', views.searchUser, name='search_users'),
    path('vendors/', views.vendor, name='vendors'),
    path('search-vendors/', views.searchVendor, name='search_vendors'),
    path('search-pending-vendors/', views.searchPendingVendor, name='search_pending_vendors'),
    path('goal/', views.goalList, name='goal'),
    path('contact/', views.contactUsView, name='contact'),
    path('resolved-contact/', views.resolvedView, name='resolved_contact'),
    path('delete-contact/<int:id>/', views.resolvedDelete, name='resolved_contact_delete'),
    path('reply-contact/<int:id>/', views.replyContactUs, name='reply_contact'),
    path('tickets/', views.ticketView, name='tickets'),
    path('reply-ticket/<int:id>/', views.replyTicket, name='reply_ticket'),
    path('resolved-tickets/', views.ticketResolvedView, name='resolved_tickets'),
    path('tickets-delete/<int:id>/', views.resolveTicketdDelete, name='resolved_tickets_delete'),
    path('questions/', views.questionView, name='questions'),
    path('add-questions/', views.addQuestionView, name='add_questions'),
    path('edit-questions/<int:id>/', views.updateQuestionView, name='edit_questions'),
    path('question-delete/<int:id>/', views.questionDelete, name='question_delete'),
    path('about/', views.aboutUs, name='about'),
    path('privacy-policy/', views.privacypolicy, name='admin_privacy_policy'),
    path('edit-privacy-policy/<int:id>/', views.updatePrivacyPolicy, name='edit_privacy_policy'),
    path('terms-condition/', views.termsandcondition, name='admin_terms_condition'),
    path('edit-terms-condition/<int:id>/', views.updateTermsCondition, name='edit_terms_condition'),
    path('about-us-app/', views.aboutusApp, name='about_us_app'),
    path('view-about-us-app/<int:id>/', views.viewAppAboutUs, name='view_about_us_app'),
    path('add-about-us-app/', views.addAboutUsApp, name='add_about_us_app'),
    path('edit-about-us-app/<int:id>/', views.appAboutUsUpdate, name='edit_about_us_app'),
    path('add-about/', views.addAboutUs, name='add_about'),
    path('view-about/<int:id>/', views.ViewAboutUs, name='view_about'),
    path('edit-about/<int:id>/', views.aboutUsUpdate, name='edit_about'),
    path('add-about/ajax/', views.addAboutusAjax, name='add_about_ajax'),
    path('social/', views.socialList, name='social'),
    path('register/', views.register, name='register'),
    path('slider/', views.slider, name='slider'),
    path('posts/', views.posts, name='post'),
    path('testimonial/', views.testimonial, name='testimonial'),
    path('app-testimonial/', views.appTestimonialList, name='app_testimonial'),
    path('app-testimonial-add/', views.appTestimonialAdd, name='app_testimonial_add'),
    path('app-testimonial-edit/<int:id>/', views.appTestimonialUpdate, name='app_testimonial_edit'),
    path('app-testimonial-view/<int:id>/', views.appTestimonialView, name='app_testimonial_view'),
    path('app-testimonial-delete/<int:id>/', views.appTestimonialDelete, name='app_testimonial_delete'),
    path('email-template/', views.emailTemplate, name='email'),
    path('pendingUsers/', views.pendingVendor, name='pending'),
    path('approve-vendor/<str:slug>/', views.changeVendorStatus, name='vendor-status'),
    path('verify/<str:slug>/', views.verifyUser, name='verify-otp'),
    path('resend-otp/<str:slug>/', views.resendEmailOTP, name='resend-otp'),
    path('user-register/', views.registerUser, name='register-user'),
    path('user-login/', views.loginUser, name='login-user'),
    path('goal-view/<int:id>/', views.goalView, name='goal_view'),
    path('user-view/<int:id>/', views.userView, name='user_view'),
    path('post-view/<int:id>/', views.postView, name='post_view'),
    path('add-user/', views.addUser, name='add_user'),
    path('add-user/ajax/', views.add_user_ajax, name='add_user_ajax'),
    path('user-edit/<int:id>/', views.userUpdate, name='user_edit'),
    path('user-delete/<int:id>/', views.userDelete, name='user_delete'),
    path('vendor-view/<int:id>/', views.vendorView, name='vendor_view'),
    path('pendingVendor-view/<str:slug>/', views.pendingVendorView, name='pending_vendor_view'),
    path('vendor-edit/<int:id>/', views.vendorUpdate, name='vendor_edit'),
    path('add-vendor/', views.addVendor, name='add_vendor'),
    path('add-vendor/ajax/', views.add_vendor_ajax, name='add_vendor_ajax'),
    path('vendor-delete/<int:id>/', views.vendorDelete, name='vendor_delete'),
    path('add-social/', views.addSocialLink, name='add_social'),
    path('add-social/ajax/', views.addSocialLinkAjax, name='add_social_ajax'),
    path('social-delete/<int:id>/', views.socialDelete, name='social_delete'),
    path('social-view/<int:id>/', views.socialView, name='social_view'),
    path('social-edit/<int:id>/', views.socialUpdate, name='social_edit'),
    path('logout/', views.logout, name='admin_logout'),
    path('admin-forget-password/', views.forgetPasswordSuperAdmin, name='admin_forget_password'),
    path('verify-admin/<str:slug>/', views.verifySuperAdmin, name='verify-admin-otp'),
    path('change-password/<str:slug>/', views.changePassword, name='admin_change_password'),
    path('superAdmin-Profile/<str:slug>/', views.superAdminProfile, name='admin_profile'),
    path('add-email/', views.addEmailTemplate, name='add_email'),
    # path('add-email/ajax/', views.addEmailTemplateAjax, name='add_email_ajax'),
    path('email-delete/<int:id>/', views.emailDelete, name='email_delete'),
    path('email-edit/<int:id>/', views.emailUpdate, name='email_edit'),
    path('email-view/<int:id>/', views.emailView, name='email_view'),
    path('add-slider/', views.addAppSlider, name='add_slider'),
    path('slider-edit/<int:id>/', views.sliderUpdate, name='slider_edit'),
    path('add-testimonial/', views.addTestimonial, name='add_testimonial'),
    path('testimonial-edit/<int:id>/', views.testimonialUpdate, name='testimonial_edit'),
    path('testimonial-delete/<int:id>/', views.testimonialDelete, name='testimonial_delete'),
    path('testimonial-view/<int:id>/', views.testimonialView, name='testimonial_view'),
    path('get-in-touch/', views.getInTouch, name='get_in_touch'),
    path('vendor-subscription/', views.vendorSubscriptionList, name='vendor_subscription'),
    path('activeVendor-subscriptionView/<str:slug>/', views.vendorPaidSubscriptionView, name='vendor_subscription_view'),
    path('add-vendor-subscription/', views.addVendorSubscription, name='add_vendor_subscription'),
    path('view-vendor-subscription/<int:id>/', views.VendorSubscriptionView, name='view_vendor_subscription'),
    path('edit-vendor-subscription/<int:id>/', views.editVendorSubscription, name='edit_vendor_subscription'),
    path('edit-vendor-paid-subscription/<int:id>/', views.editVendorPaidSubscription, name='edit_vendor_paid_subscription'),
    path('delete-vendor-subscription/<int:id>/', views.VendorSubscriptionDelete, name='delete_vendor_subscription'),
    path('active-vendor-subscription/', views.vendorActiveSubscriptionList, name='vendor_active_subscription'),
    path('vendor-payment-sattlement/', views.vendorSettlePaymentList, name='vendor_payment_sattlement'),
    path('commission/', views.CommissionView, name='commission'),
    path('active-goals/', views.activeGoalList, name='active_goals'),
    path('completed-goals/', views.completedGoalList, name='completed_goals'),
    path('searchInvoice/', views.searchInvoice, name='search_invoice'),
    path('invoice-view/<str:slug>/', views.vendorInvoiceView, name='invoice_view'),
    path('invoice-edit/<str:slug>/', views.vendorInvoiceEdit, name='invoice_edit'),
    path('goalQuestions/', views.goalQuestionView, name='goal_questions'),
    path('add-goalQuestions/', views.goalAddQuestionView, name='add_goal_questions'),
    path('update-goalQuestions/<str:slug>/', views.goalUpdateQuestionView, name='update_goal_question'),
    path('delete-goalQuestions/<str:slug>/', views.goalquestionDelete, name='delete_goal_question'),




    # path('change-current-password/<str:slug>/', views.changeSuperAdminPassword, name='admin_current_password'),
]