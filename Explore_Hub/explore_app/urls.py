"""
URL configuration for Explore_Hub project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from Explore_Hub import settings
from django.contrib.auth import views as auth_views

from . views import *

urlpatterns = [
    path('login/', login_view, name = 'login'),
    path('register/', register_view, name = 'register'),
    path('', reg_user_home_view, name='regularuser'),
    path("logout/", logout_view, name="logout"),
    path('oauth/', include('social_django.urls', namespace='social')),
    path('packages/', package_view, name="package"),    
    path('package_details/<int:package_id>/', package_details, name="package_detail"),
    path('book/<int:package_id>/', book_package_view, name='book_package'),
    path('package/payment/success/', payment_success, name='package_payment_success'),
    path('update_profile/', update_profile, name='update_profile'),
    path('my_bookings/', my_bookings, name='my_bookings'),
    path('cancel_booking/<int:booking_id>/', cancel_booking, name='cancel_booking'),
    path('admindashboard/', admin_dashboard, name='admin_dashboard'),
    path('adminmain/approve-agencies/', admin_approve_agencies, name='admin_approve_agencies'),
    path('approve-agency/<int:agency_id>/', approve_travel_agency, name='approve_agency'),
    path('adminmain/manage-packages/', admin_manage_packages, name='admin_manage_packages'),
    path('adminmain/archive_package/<int:package_id>/', admin_archive_package, name='admin_archive_package'),
    path('adminmain/manage-groups/', admin_manage_groups, name='admin_manage_groups'),
    path('adminmain/delete_group/<int:group_id>/', admin_delete_group, name='admin_delete_group'),
    path('adminmain/admin-manage-users/', admin_manage_users, name='admin_manage_users'),
    path('adminmain/delete-user/<int:user_id>/', admin_delete_user, name='admin_delete_user'),
    path('taregistration/', ta_registration_view, name="ta_registration"),
    path('tahome/', ta_home, name="tahome"),
    path('ta/manage_packages/', ta_manage_package, name='ta_manage_packages'),
    path('manage_archived/', manage_archived_packages, name='manage_archived_packages'),
    path('manageprofile/', ta_manage_profile, name="ta_profile"),
    path('addpackage/', add_package, name="add_package"),
    path('check-package-title/', check_package_title, name='check_package_title'),
    path('updatepackage/<int:package_id>/', update_package, name="update_package"),
    path('deletepackage/<int:package_id>/', delete_package, name="delete_package"),
    path('ta_bookings/', ta_bookings, name='ta_bookings'),
    path('forgot_password/', forgot_password_view, name='forgot_password'),
    path('reset_password/<uidb64>/<token>/', reset_password_view, name='reset_password'),
    path('check_username/', check_username, name='check_username'),
    path('groups/',group_view, name='groups'),
    path('create_group/', create_group, name='create_group'),
    path('available_group/', available_groups, name='available_group'),
    path('user_group/', user_group,name='user_group'),
    path('join_group/<int:group_id>/', join_group, name='join_group'),
    path('groups/<int:group_id>/',group_detail_view,name='group_details'),
    path('group/delete/<int:group_id>/', delete_group, name='delete_group'),
    path('group/remove_member/<int:group_id>/<int:member_id>/', remove_member, name='remove_member'),
    path('group/edit/<int:group_id>', edit_group, name='edit_group'),
    path('leave_group/<int:group_id>/', leave_group_view, name='leave_group'),
    path('chat/<int:group_id>/', group_chat_view, name='group_chat'),
    path('get_new_messages/<int:group_id>/<int:last_message_id>/', get_new_messages, name='get_new_messages'),
    path('send_message/<int:group_id>/', send_message, name='send_message'),
    path('package/search/', package_search, name='package_search'),
    path('group/search/', group_search, name='group_search'),
    path('available_group/search/', available_group_search, name='available_group_search'),
    path('registration/guide/', guide_registration, name="guide_registration"),
    path('guide_home/', guide_home, name='guide_home'),
    path('approve_guide/<int:guide_id>/', approve_local_guide, name='approve_guide'),
    path('local-guides/', local_guide_list, name='local_guide_list'),
    path('guide-search/', guide_search, name='guide_search'),
    path('local-guide/<int:guide_id>/', local_guide_detail, name='local_guide_detail'),
    path('local-guide/<int:guide_id>/request-guidance/', request_guidance, name='request_guidance'),
    path('local-guide/<int:guide_id>/book/', book_guide, name='book_guide'),
    path('guide/payment/success/', guide_payment_success, name='guide_payment_success'),
    path('advice-requests/', advice_request_list, name='advice_request_list'),
    path('advice-requests/<int:request_id>/', advice_reply_detail, name='advice_reply_detail'),
    path('guide/advice-requests/', advice_requests_view, name='advice_requests'),
    path('guide/advice-requests/reply/<int:request_id>', reply_advice_request, name='reply_advice_request'),
    path('local-guide/bookings/', local_guide_bookings, name='local_guide_bookings'),
    path('local-guide/booking/details/<str:booking_id>/', booking_details, name='booking_details'),
    path('guide/bookings/<int:booking_id>/update-trip-plan/', guide_update_trip_plan, name='guide_update_trip_plan'),
    path('my-bookings/guide/', my_guide_bookings, name='my_guide_bookings'),
    path('cancel_guide_booking/<int:booking_id>/', cancel_guide_booking, name='cancel_guide_booking'),
    path('my_booking/guide/details/<int:booking_id>',guide_booking_detail, name='guide_booking_detail'),
    path('guide/update_profile/', update_guide_profile, name='update_guide_profile'),
    path('itinerary-planner/', itinerary_planner, name='itinerary_planner'),
    path('registration/event-organizer/', event_organizer_registration, name='event_organizer_registration'),
    path('approve_organizer/<int:organizer_id>/', approve_organizer, name='approve_organizer'),
    path('event_organizer/home/', event_organizer_home, name='event_organizer_home'),
    path('event_organizer/event/create/', create_event, name='create_event'),
    path('events/list/', event_list, name='event_list'),
    path('event/<int:event_id>/', event_detail, name='event_detail'),
    path('event/search/', event_search, name='event_search'),
    path('event/<int:event_id>/book/', book_event, name='book_event'),
    path('event/payment/success/', event_payment_success, name='event_payment_success'),
    path('event/bookings/', my_event_bookings, name='my_event_bookings'),
    path('event_organizer/bookings/', event_organizer_bookings, name='event_organizer_bookings'),
    path('event_organizer/my_events/', my_events, name='my_events'),
    path('event_organizer/event/<int:event_id>/update/', update_event, name='update_event'),
    path('event_organizer/event/<int:event_id>/delete/', delete_event, name='delete_event'),
    path('event_organizer/event/<int:event_id>/participants/', event_participants, name='event_participants'),
    path('event_organizer/profile/', event_organizer_profile, name='event_organizer_profile'),
    path('adminmain/manage-events/', admin_manage_events, name='admin_manage_events'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)