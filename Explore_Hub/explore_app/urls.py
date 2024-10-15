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
    path('payment/success/', payment_success, name='payment_success'),
    path('update_profile/', update_profile, name='update_profile'),
    path('my_bookings/', my_bookings, name='my_bookings'),
    path('cancel_booking/<int:booking_id>/', cancel_booking, name='cancel_booking'),
    path('admindashboard/', admin_dashboard, name='admin_dashboard'),
    path('adminmain/approve-agencies/', admin_approve_agencies, name='admin_approve_agencies'),
    path('approve-agency/<int:agency_id>/', approve_travel_agency, name='approve_agency'),
    path('adminmain/manage-packages/', admin_manage_packages, name='admin_manage_packages'),
    path('adminmain/manage_archived_package/', admin_manage_archived_packages, name='admin_manage_archived_packages'),
    path('adminmain/archive_package/<int:package_id>/', admin_archive_package, name='admin_archive_package'),
    path('adminmain/manage-groups/', admin_manage_groups, name='admin_manage_groups'),
    path('adminmain/delete_group/<int:group_id>/', admin_delete_group, name='admin_delete_group'),
    path('adminmain/admin-manage-users/', admin_manage_users, name='admin_manage_users'),
    path('adminmain/delete-user/<int:user_id>/', admin_delete_user, name='admin_delete_user'),
    path('taregistration/', ta_registration_view, name="ta_registration"),
    path('tahome/', ta_home, name="tahome"),
    path('manage_archived/', manage_archived_packages, name='manage_archived_packages'),
    path('manageprofile/', ta_manage_profile, name="ta_profile"),
    path('addpackage/', add_package, name="add_package"),
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
    path('leave_group/<int:group_id>/', leave_group_view, name='leave_group'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)