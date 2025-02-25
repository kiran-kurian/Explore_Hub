from datetime import datetime, timedelta
import re
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from explore_app.models import *
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.cache import never_cache, cache_control
from django.contrib import messages
from django.core.mail import send_mail, EmailMessage
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.contrib.auth import views as auth_views
from django.core.cache import cache
from django.core.files.uploadedfile import UploadedFile
from django.core.files.storage import default_storage
from django.db.models import F, Count, Q
import uuid
import razorpay
from django.views.decorators.csrf import csrf_exempt
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from reportlab.pdfgen import canvas
from io import BytesIO
import base64
from django.utils import timezone
import requests
from opencage.geocoder import OpenCageGeocode
from django.db.models import Sum
import json
from django.utils.timezone import now


# Create your views here.

#login page view
def login_view(request):
    if request.method == "POST":

        # Attempt to sign user in
        username = request.POST["username"]
        password = request.POST["password"]
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # If no user exists with that username, return the error
            return render(request, "login.html", {
                "message": "Invalid username and/or password."
            })

        # Check if the user is inactive
        if not user.is_active:
            return render(request, "login.html", {
                "message": "Account is inactive. Please contact the admin."
            })
        user = authenticate(request, username=username, password=password)


        # Check if authentication successful
        if user is not None:
            login(request, user)
            if user.is_superuser:
                request.session['master'] = user.id
                return redirect('admin_dashboard')
            else:
                custom_user = CustomUser.objects.get(id=user.id)
                role = custom_user.role
                if role == 'ta':
                    request.session['travel'] = user.id
                    return HttpResponseRedirect(reverse('tahome'))
                elif role == 'guide':
                    request.session['guide'] = user.id
                    return HttpResponseRedirect(reverse('guide_home'))
                elif role == 'organizer':
                    request.session['organizer'] = user.id
                    return HttpResponseRedirect(reverse('event_organizer_home'))
                else:
                    request.session['normal'] = user.id
                    return HttpResponseRedirect(reverse("regularuser"))
        else:
            return render(request, "login.html", {
                "message": "Invalid username and/or password."
            })
    else:
        return render(request, "login.html")

#for logout
def logout_view(request):
    logout(request)
    request.session.flush()
    cache.clear()
    return redirect('regularuser')

#to test for whether user is admin
def admin_check(user):
    return user.is_superuser

#registration page view
def register_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        name = request.POST["name"]
        email = request.POST["email"]
        number = request.POST["number"]
        role = request.POST["role"]

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmpassword"]
        if password != confirmation:
            return render(request, "registration.html", {
                "message": "Passwords must match."
            })

        # Validate email format
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            return render(request, "registration.html", {
                "message": "Invalid email format."
            })
        
        # Validate phone number
        phone_pattern = r'^[6-9]\d{9}$'
        if not re.match(phone_pattern, number):
            return render(request, "registration.html", {
                "message": "Enter a valid 10-digit phone number"
            })
        
        # Attempt to create new user
        try:
            if role == 'ta':
                # Store travel agent details in session
                request.session['username'] = username
                request.session['name'] = name
                request.session['email'] = email
                request.session['number'] = number
                request.session['password'] = password
                # Redirect to document upload page
                return redirect('ta_registration')
            elif role == 'guide':
                request.session['username'] = username
                request.session['name'] = name
                request.session['email'] = email
                request.session['number'] = number
                request.session['password'] = password
                #redirect to other details entering page
                return redirect('guide_registration')
            elif role == 'organizer':
                request.session['username'] = username
                request.session['name'] = name
                request.session['email'] = email
                request.session['number'] = number
                request.session['password'] = password
                return redirect('event_organizer_registration')   
            else:
                user = CustomUser.objects.create_user(username=username, email=email, password=password, first_name=name, phone_number=number, role=role)
                user.save()

            # login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return HttpResponseRedirect(reverse("login"))
        except IntegrityError:
            return render(request, "registration.html", {
                "message": "Username already taken."
            })
    else:
        return render(request, "registration.html")

#Package listing view
def package_view(request):
    try:
        print("first")
        recommended_packgs = recommended_package(request, request.user)
        print("recommended")
        travel_package = TravelPackage.objects.prefetch_related('package_images').filter(is_archived=False, is_active=True).annotate(total_bookings=Count('booking_count')).order_by('-total_bookings', '-views')
        return render(request, "packages.html", {'packages': travel_package, 'recommended' : recommended_packgs})
    except:
        print("second")
        travel_package = TravelPackage.objects.prefetch_related('package_images').filter(is_archived=False, is_active=True).annotate(total_bookings=Count('booking_count')).order_by('-total_bookings', '-views')
        return render(request, "packages.html", {'packages': travel_package})
    

#view for past booking based recommendation
def recommended_package(request, user):
    if 'normal' in request.session:
        booked_packages = user.booking_set.values_list('package_id', flat=True)
        users_with_same_bookings = Booking.objects.filter(package_id__in=booked_packages).values_list('user_id', flat=True)
        recommended = (
            TravelPackage.objects.filter(booking__user_id__in=users_with_same_bookings).exclude(package_id__in=booked_packages).exclude(is_archived=True).exclude(is_active=False).annotate(book_count=Count('booking')).order_by('-book_count')[:5] 
        )
    else:
        recommended = TravelPackage.objects.none()
    return recommended

#detailed package view
def package_details(request, package_id):
    package = get_object_or_404(TravelPackage, pk = package_id)
    package.views += 1
    package.save(update_fields=['views'])
    return render(request, 'package_detail.html', {'package': package, 'agency_name': package.agency_id.name})

#view for profile updation
def update_profile(request):
    if 'normal' in request.session:
        user = request.user.customuser 

        if request.method == 'POST':
            user.first_name = request.POST.get('name')
            user.email = request.POST.get('email')
            user.phone_number = request.POST.get('number')
            # Don't update role here
            user.save()
            return redirect('regularuser') 

        return render(request, 'update_profile.html', {'user': user})
    else:
        return redirect('login')

#Travel agent registration view
def ta_registration_view(request):
    if request.method== "POST":
        documents = request.FILES.get("documents")
        agreement = request.POST.get("agreement") == 'on'
        username = request.session.get("username")
        name = request.session.get("name")
        email = request.session.get("email")
        number = request.session.get("number")
        password = request.session.get("password")

        if not all([username, name, email, number, password]):
            return redirect('register')
        
        if agreement:
            try:
                hashed_password = make_password(password)
                travelagency = TravelAgency(
                    username = username,
                    name = name,
                    email = email,
                    contact = number,
                    password = hashed_password,
                    documents = documents,
                    agreement = agreement,
                    approved = False
                )
                travelagency.save()
                #saving this to user table
                user = CustomUser(username=username, first_name=name, email=email, password=hashed_password,phone_number=number, role='ta', travel_agency=travelagency)
                user.save()
                # login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                return HttpResponseRedirect(reverse("login"))
            except IntegrityError:
                return render(request, "registration.html", {
                    "message": "Data Repetition"
                })
    else:
        return render(request, "ta_registration.html")

#default homepage of the website
def reg_user_home_view(request):
    return render(request, 'index.html')

#admin page view
@login_required(login_url='login')
@user_passes_test(admin_check)
def admin_dashboard(request):
    if request.session.has_key('master'):
        return render(request, 'admin_dashboard.html')
    else:
        return redirect('login')

@login_required(login_url='login')
def admin_approve_agencies(request):
    if 'master' in request.session: 
        view = request.GET.get('view', 'agencies')  
        if view == 'agencies':
            agencies = TravelAgency.objects.filter(approved=False)
            return render(request, 'approve_agencies.html', {
                'agencies': agencies,
                'active_section': 'agencies',
            })
        elif view == 'guides':
            guides = LocalGuide.objects.filter(approved=False)
            return render(request, 'approve_agencies.html', {
                'guides': guides,
                'active_section': 'guides',
            })
        elif view == 'organizer':
            organizer = EventOrganizer.objects.filter(approved=False)
            return render(request, 'approve_agencies.html', {
                'organizer': organizer,
                'active_section': 'organizer',
            })
    else:
        return redirect('login')

@login_required(login_url='login')
def approve_travel_agency(request, agency_id):
    if 'master' in request.session:
        agency = get_object_or_404(TravelAgency, pk=agency_id)
        agency.approved = True
        agency.save()
        send_mail(
                'Account Approved Notification',
                f'Dear {agency.name},\n\n'
                f'This email is to inform you that your account with EXPLORE HUB has been approved.'
                'You can start using our platform from now on.'
                'If you have any questions, please contact support.',
                'explorehub123@gmail.com',
                [agency.email]
            )
        return redirect('admin_approve_agencies')
    else:
        return redirect('login')

@login_required(login_url='login')
def admin_manage_packages(request):
    if 'master' in request.session:
        package = TravelPackage.objects.prefetch_related('package_images').filter(is_archived=False, is_active=True)
        return render(request, 'admin_manage_package.html', {'packages': package})
    else:
        return redirect('login')

@login_required(login_url='login')
def admin_manage_archived_packages(request):
    if 'master' in request.session:
        package = TravelPackage.objects.prefetch_related('package_images').filter(is_archived=True, is_active=True)
        return render(request, 'admin_manage_package.html', {'packages': package})
    else:
        return redirect('login')

@login_required(login_url='login')
def admin_manage_groups(request):
    if 'master' in request.session:
        groups = TravelGroup.objects.all() 
        return render(request, 'admin_manage_group.html', {'groups': groups})
    else:
        return redirect('login')
    
#make a group inactive by admin
def admin_delete_group(request, group_id):
    if 'master' in request.session:
        group = get_object_or_404(TravelGroup, group_id=group_id)
        group.is_active = not group.is_active  # Toggle the active status
        group.save()
        return redirect('admin_manage_groups')
    else:
        return redirect('login')

#to manage users by admin
@login_required(login_url='login')
def admin_manage_users(request):
    if 'master' in request.session:
        users = CustomUser.objects.filter(is_superuser=False)
        return render(request, 'admin_manage_users.html', {'users': users})
    else:
        return redirect('login')

#to delete the user by admin
@login_required(login_url='login')
def admin_delete_user(request, user_id):
    if 'master' in request.session:
        user = get_object_or_404(CustomUser, pk=user_id)
        if not user.is_active:
            subject = "Account Unblocked"
            message = render_to_string("account_unblocked_email.html", { "user": user })
            user.is_active = True
            send_mail(subject, message, 'explorehub123@gmail.com', [user.email], html_message=message)
        else:
            subject = "Account Blocked"
            message = render_to_string("account_blocked_email.html", { "user": user })
            user.is_active = False
            send_mail(subject, message, 'explorehub123@gmail.com', [user.email], html_message=message)
        user.save()
        return redirect('admin_manage_users')
    else:
        return redirect('login')
    
#home page for travel agency
@login_required(login_url='login')
def ta_home(request):
    if 'travel' in request.session:
        try:
            agency = TravelAgency.objects.get(username=request.user.username)
            if not agency.approved:
                return render(request, "login.html", {
                    "message": "Approval pending"
                })
            total_packages = TravelPackage.objects.filter(agency_id=agency).count()
            total_bookings = Booking.objects.filter(package__agency_id=agency).count()
            total_customers = Booking.objects.filter(package__agency_id=agency).values('user').distinct().count()
            total_revenue = Booking.objects.filter(package__agency_id=agency).aggregate(Sum('total_amount'))['total_amount__sum'] or 0
            context = {
                'agency': agency,
                'total_packages': total_packages,
                'total_bookings': total_bookings,
                'total_customers': total_customers,
                'total_revenue': total_revenue,
            }
            return render(request, 'ta_home.html', context)
        except TravelAgency.DoesNotExist:
            return redirect('login')
    else:
        return redirect('login')

#view for managing packages of travel agency
@never_cache
@login_required(login_url='login')
def ta_manage_package(request):
    if 'travel' in request.session:
        agency = TravelAgency.objects.get(username=request.user.username)    
        packages = TravelPackage.objects.filter(agency_id=agency, is_archived=False, is_active=True).prefetch_related('package_images')
        return render(request, 'ta_packages.html', {'agency': agency, 'packages': packages})
    else:
        return redirect('login')

@never_cache
@login_required(login_url='login')
def manage_archived_packages(request):
    if 'travel' in request.session:
        try:
            agency = TravelAgency.objects.get(username=request.user.username)
            if not agency.approved:
                return render(request, "login.html", {
                    "message": "Approval pending"
                })
            packages = TravelPackage.objects.filter(agency_id=agency, is_archived=True, is_active=True).prefetch_related('package_images')
        except TravelAgency.DoesNotExist:
            return redirect('login')
        return render(request, 'ta_archived.html', {'agency': agency, 'packages': packages})
    else:
        return redirect('login')

#to manage profile of travel agency
@never_cache
@login_required(login_url='login')
def ta_manage_profile(request):
    if 'travel' in request.session:
        travel_agency= TravelAgency.objects.get(username=request.user.username)
        if request.method == "POST":
            # Get the updated details from the form
            name = request.POST.get("name")
            contact = request.POST.get("contact")
            email = request.POST.get("email")

            # Update the travel agency user details
            travel_agency.name = name
            travel_agency.contact = contact
            travel_agency.email = email

            # Save the updated information
            travel_agency.save()
            return redirect('tahome')
        return render(request, "ta_manage_profile.html", { 'travel_agency': travel_agency })
    else:
        return redirect('login')

#to add package by the travel agency
@login_required(login_url='login')
def add_package(request):
    if 'travel' in request.session:
        if request.method == 'POST':
            user = request.user
            if hasattr(user, 'customuser') and user.customuser.travel_agency:
                travel_agency = user.customuser.travel_agency

                title = request.POST.get('title')
                description = request.POST.get('description')
                price = float(request.POST.get('price'))
                if price <= 0:
                    return render(request, 'add_package.html', {'message': 'Price cannot be zero or less than'})
                duration = request.POST.get('duration')
                origin = request.POST.get('origin')
                destination = request.POST.get('destination')
                discount_percentage = request.POST.get('discount_percentage')
                cancellation = request.POST.get('cancellation') == 'on'
                itinerary = request.POST.get('itinerary')
                images = request.FILES.getlist('images')

                valid_image_types = ['image/jpeg', 'image/png', 'image/gif']

                if title and description and price and duration and origin and destination:

                    for image in images:
                        if isinstance(image, UploadedFile):
                            if image.content_type not in valid_image_types:
                                return render(request, 'add_package.html', {'message': 'Insert valid image format'})
                    # Create and save the package
                    package = TravelPackage(
                        title=title,
                        description=description,
                        price=price,
                        duration=duration,
                        origin=origin,
                        destination=destination,
                        discount_percentage=discount_percentage,
                        cancellation=cancellation,
                        itinerary=itinerary,
                        agency_id=travel_agency
                    )
                    package.save()

                    # Save multiple images for the package
                    for image in images:
                        PackageImage.objects.create(
                            travel_package=package,
                            image=image,
                        )


                    return redirect('tahome')
        return render(request, 'add_package.html')
    else:
        return redirect('login')

#to update package by the travel agency
@login_required(login_url='login')
@never_cache
def update_package(request, package_id):
    if 'travel' in request.session:
        package = get_object_or_404(TravelPackage, pk=package_id)
        
        if request.method == 'POST':
            try:
                package.title = request.POST.get('title', package.title)
                package.description = request.POST.get('description', package.description)
                package.price = float(request.POST.get('price', package.price))
                if package.price <= 0:
                    messages.error(request, 'Price must be greater than 0.')
                    return render(request, 'update_package.html', {'package': package})
                package.origin = request.POST.get('origin', package.origin)
                package.destination = request.POST.get('destination', package.destination)
                package.duration = request.POST.get('number_of_days', package.duration)
                package.discount_percentage = request.POST.get('discount_percentage', package.discount_percentage)
                package.itinerary = request.POST.get('itinerary', package.itinerary)
                cancellation = request.POST.get('cancellation') == 'True'
                package.cancellation = cancellation

                delete_image_ids = request.POST.getlist('delete_images')
                if delete_image_ids:
                    for image_id in delete_image_ids:
                        image = get_object_or_404(PackageImage, id=image_id)
                        # Delete the image file from storage
                        if default_storage.exists(image.image.path):
                            default_storage.delete(image.image.path)
                        # Delete the image record from the database
                        image.delete()

                # Handle image file uploads
                valid_image_types = ['image/jpeg', 'image/png', 'image/jpg']
                if 'images' in request.FILES:
                    for image in request.FILES.getlist('images'):
                        if isinstance(image, UploadedFile):
                            if image.content_type not in valid_image_types:
                                messages.error(request, f"File '{image.name}' is not a valid image type.")
                                return render(request, 'update_package.html', {'package': package,
                                                                            'message':'Not a valid image type'})
                        new_image = PackageImage(travel_package=package, image=image)
                        new_image.save()
                package.is_archived = False
                package.save()
                messages.success(request, 'Package updated successfully!')
                return redirect('tahome')
            except Exception as e:
                messages.error(request, f'An error occurred: {e}')
        
        return render(request, 'update_package.html', {'package': package})
    else:
        return redirect('login')

#to delete package by the travel agency
def delete_package(request, package_id):
    if 'travel' in request.session:
        try:
            package = get_object_or_404(TravelPackage, pk=package_id)
            package.is_active = False
            package.save()
            messages.success(request, 'Package deleted successfully!')
        except IntegrityError:
            messages.error(request, 'Failed to delete the package')
        return redirect('tahome')
    else:
        return redirect('login')

#to delete package by admin
def admin_archive_package(request, package_id):
    if 'master' in request.session:
        if request.method == 'POST':
            reason = request.POST.get('archiveReason')
            if not reason:
                return JsonResponse({'error':"Please enter the reason to archive"}, status=400)
        try:
            package = get_object_or_404(TravelPackage, pk=package_id)
            package.is_archived = True
            package.save()
            send_mail(
                    'Package Archived Notification',
                    f'Dear {package.agency_id.name},\n\n'
                    f'Your package titled "{package.title}" has been archived for the following reason:\n'
                    f'{reason}\n\n'
                    'Please review your package\n'
                    'If you have any questions, please contact support.',
                    'explorehub123@gmail.com',
                    [package.agency_id.email]
                )
            return JsonResponse({'success': 'Package archived successfully!'})
        except IntegrityError:
            return JsonResponse({'error': "Failed to archive the package."}, status=400)
        return redirect('admin_manage_packages')
    else:
        return redirect('login')

#forgot password
def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            # Send the reset email
            reset_url = request.build_absolute_uri(f'/reset_password/{uid}/{token}/')
            subject = 'Reset Your Password'
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_url': reset_url,
            })
            send_mail(subject, message, 'explorehub123@gmail.com', [user.email], html_message=message)
            return render(request, 'login.html', {"message": "Password reset link is sent"})
        except User.DoesNotExist:
            return render(request, 'forgot_password.html', {'error': 'No user found with that email.'})
    return render(request, 'forgot_password.html')

#resetting password
def reset_password_view(request, uidb64, token):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if password != confirm_password:
            return render(request, 'reset_password.html', {'error': 'Passwords do not match'})
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                # Update the user's password
                user.set_password(password)
                user.save()
                logout(request)
                return render(request, 'login.html', {"message": "Reset complete, Login now"})
            else:
                return render(request, 'reset_password.html', {'error':'Invalid or expired reset link. Please request a new password reset.'})
        except:
            return render(request, 'reset_password.html', {'error': 'Invalid link'})
    return render(request, 'reset_password.html')

#check username for live validation
def check_username(request):
    username = request.GET.get('username', None)
    is_taken = CustomUser.objects.filter(username=username).exists()
    return JsonResponse({'is_taken': is_taken})

#view for listing groups
def group_view(request):
    groups = TravelGroup.objects.filter(is_active=True).annotate(current_count=Count('current_members')).filter(current_count__lt=F('max_members'))
    return render(request, 'travel_group.html',{'groups':groups})
    
#view for available groups
def available_groups(request):
    if 'normal' in request.session:
        groups = TravelGroup.objects.filter(is_active=True).exclude(current_members=request.user).annotate(current_count=Count('current_members')).filter(current_count__lt=F('max_members'))
        return render(request, 'available_group.html',{'groups': groups})
    else:
        return redirect('login')

#view for user joined group
@never_cache
def user_group(request):
    if 'normal' in request.session:
        user_group = TravelGroup.objects.filter(current_members=request.user.id, is_active=True)
        return render(request, 'user_group.html',{'user_groups': user_group})
    else:
        return redirect('login')

#view for creating group
def create_group(request):
    if 'normal' in request.session:
        if request.method == 'POST':
            group_name = request.POST.get('group_name')
            destination = request.POST.get('destination')
            max_members = request.POST.get('max_members')
            description = request.POST.get('description')
            trip_date = request.POST.get('date')
            gender = request.POST.get('gender_preference')
            print(gender)

            username = request.user.username
            creator = CustomUser.objects.get(username=username)
            # Create a new group
            new_group = TravelGroup(
                name=group_name,
                destination=destination,
                max_members=max_members,
                creator=creator,  
                description=description,
                trip_date=trip_date,
                gender=gender
            )
            new_group.save()

            # Add the creator as the first member of the group
            new_group.current_members.add(creator)
            return redirect('user_group')
        today = timezone.now().date().strftime('%Y-%m-%d')
        print(today)
        return render(request, 'create_group.html', {'today': today})
    else:
        return redirect('login')
    
#view for joining group
def join_group(request, group_id):
    if 'normal' in request.session:
        group = get_object_or_404(TravelGroup, pk=group_id)

        # Check if the user is already a member of the group
        if group.current_members.filter(id=request.user.id).exists():
            return JsonResponse({
                'status': 'warning',
                'message': 'You are already a member of this group.'
            })

        # Check if the group has space for more members
        if group.current_members.count() >= group.max_members:
            return JsonResponse({
                'status': 'error',
                'message': 'This group is already full.'
            })

        user_id = request.session.get('normal')
        current_user = CustomUser.objects.get(id=user_id)
        group.current_members.add(current_user)
        return JsonResponse({
            'status': 'success',
            'message': f'You have successfully joined the group "{group.name}".'
        })
    else:
        return redirect('login')
    
#view for the creator of the group to delete the group
def delete_group(request, group_id):
    if 'normal' in request.session:
        group = get_object_or_404(TravelGroup, group_id=group_id)
        if request.method == 'POST':
            group.is_active = False
            group.save()  
            return JsonResponse({'message': 'Group deleted successfully.'})
        return redirect('user_group')
    else:
        return redirect('login')
    
#view for detailed group view
def group_detail_view(request, group_id):
    if 'normal' in request.session:
        group = get_object_or_404(TravelGroup, group_id=group_id)
        if 'trip_status' in request.POST:
            group.trip_status = request.POST['trip_status']
            group.save()
        return render(request, 'group_detail.html', {'group': group})
    else:
        return redirect('login')
    
#view for the group creator to remove the current members
def remove_member(request, group_id, member_id):
    if 'normal' in request.session:
        group = get_object_or_404(TravelGroup, group_id=group_id)
        member = get_object_or_404(CustomUser, id=member_id)

        if request.method == 'POST' and request.user.id == group.creator_id:
            group.current_members.remove(member)
            return JsonResponse({'message': 'Member removed successfully.'})
        return JsonResponse({'message': 'Failed to remove member.'}, status=400)
    else:
        return redirect('login')

#view for leaving the joined group
def leave_group_view(request, group_id):
    if 'normal' in request.session:
        if request.method == 'POST':
            user_id = request.session.get('normal') 
            if user_id:
                current_user = CustomUser.objects.get(id=user_id)
                group = get_object_or_404(TravelGroup, group_id=group_id)
                group.current_members.remove(current_user)

                return JsonResponse({'message': 'You have successfully left the group.'})

            return JsonResponse({'message': 'User not found.'}, status=404)

        return JsonResponse({'message': 'Invalid request.'}, status=400)
    else:
        return redirect('login')
    
#view for editing group details
def edit_group(request, group_id):
    if 'normal' in request.session:
        group = get_object_or_404(TravelGroup, group_id=group_id)

        if request.method == 'POST':
            # Update group details from the request
            group.name = request.POST.get('group_name', group.name)
            group.destination = request.POST.get('destination', group.destination)
            group.description = request.POST.get('description', group.description)
            group.max_members = request.POST.get('max_members', group.max_members) 
            group.trip_date = request.POST.get('date', group.trip_date)
            group.gender = request.POST.get('gender_preference', group.gender)
            group.save()
            return redirect('group_details', group_id=group.group_id)  # Redirect to the group detail page after update
        today = timezone.now().date().strftime('%Y-%m-%d')
        return render(request, 'edit_group.html', {'group': group, 'today': today})
    else:
        return redirect('login')

#view for booking package
def book_package_view(request, package_id):
    if 'normal' in request.session:
        package = get_object_or_404(TravelPackage, pk=package_id)
        user = request.user.customuser
        number_of_people = int(request.GET.get('number_of_people', 1))
        people_range = range(1, number_of_people + 1)
        razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        if request.method == 'POST':
            number_of_people = int(request.POST.get('number_of_people', 1))
            date_of_travel = request.POST.get('date_of_travel')
            contact = request.POST.get('phone_number')
            discount_price = package.discounted_price()
            total_amount = float(discount_price) * number_of_people
            cancellation = package.cancellation
            print(cancellation)
            print(timezone.localtime())
            print(datetime.now())
            id = request.session['normal']
            user = CustomUser.objects.get(id = id)
            user.phone_number = contact
            user.save()
            id_type = request.POST.get('id_type')
            id_number = request.POST.get('id_number')
            id_upload = request.FILES.get('id_upload')
            package.booking_count = +1
            package.save(update_fields=['booking_count'])
            
            # Create a new booking entry
            booking = Booking.objects.create(
                user=request.user,
                package=package,
                total_amount=total_amount,
                booking_id=str(uuid.uuid4()),
                number_of_people=number_of_people,
                trip_date=date_of_travel,
                payment_status='pending', 
                cancellation = cancellation, 
                id_type=id_type,
                id_number=id_number,
                id_upload=id_upload,
            )

            for i in range(1, number_of_people + 1):
                full_name = request.POST.get(f'passenger_name_{i}')
                age = request.POST.get(f'passenger_age_{i}')
                gender = request.POST.get(f'passenger_gender_{i}')
                Passenger.objects.create(
                    booking=booking,
                    full_name=full_name,
                    age=int(age),
                    gender=gender
                )
            
            # Create Razorpay order
            razorpay_order = razorpay_client.order.create({
                'amount': int(total_amount * 100),  
                'currency': 'INR',
                'payment_capture': '1'
            })
            
            # Store Razorpay order ID in session for further verification
            request.session['razorpay_order_id'] = booking.booking_id
            
            context = {
                'booking_type': 'Package',
                'title': package.title,
                'package': package,
                'booking': booking,
                'razorpay_key': settings.RAZORPAY_KEY_ID,
                'razorpay_order_id': razorpay_order['id'],
                'payment_success_url': 'package_payment_success',
                'total_amount': total_amount,
            }
            return render(request, 'payment_page.html', context) 
        
        return render(request, 'book_package.html', {'package': package, 'user': user, 'number_of_people': number_of_people, 'people_range': people_range})
    else:
        return redirect('login')

#package payment confirmation view
@csrf_exempt
def payment_success(request):
    if 'normal' in request.session:
        razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        if request.method == 'POST':
            payment_id = request.POST.get('razorpay_payment_id', '')
            razorpay_order_id = request.POST.get('razorpay_order_id', '')
            signature = request.POST.get('razorpay_signature', '')
            
            try:
                # Verify payment signature
                params_dict = {
                    'razorpay_order_id': razorpay_order_id,
                    'razorpay_payment_id': payment_id,
                    'razorpay_signature': signature
                }
                
                # Verify signature
                razorpay_client.utility.verify_payment_signature(params_dict)
                
                # If successful, mark the booking as confirmed
                booking = Booking.objects.get(booking_id=request.session['razorpay_order_id'])
                booking.payment_status = 'completed'
                booking.transaction_id = payment_id
                booking.is_confirmed = True
                booking.payment_date = timezone.localtime()
                booking.razorpay_payment_id = payment_id
                booking.save()

                user = request.user.customuser
                
                pdf_buffer = BytesIO()
                generate_pdf(booking, pdf_buffer)
                pdf_buffer.seek(0)

                email = EmailMessage(
                subject='Booking Confirmation',
                body=f'Your booking for {booking.package.title} has been confirmed. Booking ID: {booking.booking_id}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[booking.user.email],
                )

                # Attach the PDF
                email.attach('booking_details.pdf', pdf_buffer.getvalue(), 'application/pdf')

                # Send the email
                email.send(fail_silently=False)
                pdf_data = base64.b64encode(pdf_buffer.getvalue()).decode('utf-8')
                pdf_buffer.close()
                

                # Render success page with a message
                return render(request, 'payment_success.html', {'booking': booking, 'pdf_data': pdf_data})

            except razorpay.errors.SignatureVerificationError:
                return HttpResponse("Payment failed. Signature verification failed.", status=400)

        return HttpResponse("Invalid request.")
    else:
        return redirect('login')

def generate_pdf(booking, buffer):
    p = canvas.Canvas(buffer, pagesize=A4)

    logo_path = "static/images/logo.png" 
    p.drawImage(logo_path, 50, 770, width=40, height=50) 

    p.setTitle("Booking Invoice")

    p.setFont("Helvetica-Bold", 24)
    p.drawCentredString(300, 740, "Booking Invoice") 

    p.setFont("Helvetica", 12)
    p.drawString(50, 725, "Explore Hub")
    p.drawString(50, 710, "123 Travel Street")
    p.drawString(50, 695, "Travel City, TC 12345")
    p.drawString(50, 680, "Phone: +91 1234567890")
    p.drawString(50, 665, "Email: explorehub123@gmail.com")

    p.line(50, 655, 550, 655)

    discounted_price = booking.package.discounted_price()

    customer_details = [
        ["Customer Name:", booking.user.first_name],
        ["Email:", booking.user.email],
        ["Booking ID:", booking.booking_id],
        ["Package:", booking.package.title],
        ["Date of Travel:", booking.trip_date.strftime('%d-%m-%Y')],
        ["Amount Paid:", f"₹{booking.total_amount:.2f}"], 
        ["Discounted Price(per person):", f"₹{discounted_price:.2f}"], 
        ["Payment Date:", booking.payment_date.strftime('%d-%m-%Y')],
        ["Transaction ID:", booking.transaction_id]
    ]

    table = Table(customer_details, colWidths=[150, 350])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  
        ('FONTSIZE', (0, 0), (-1, 0), 12),  
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige), 
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  
    ]))

    table.wrapOn(p, 400, 600)
    table.drawOn(p, 50, 400) 

    p.line(50, 380, 550, 380)

    p.setFont("Helvetica-Oblique", 10)
    p.drawCentredString(300, 120, "Thank you for booking with Explore Hub!")
    p.drawCentredString(300, 105, "Please contact us if you have any questions regarding your booking.")

    p.showPage()
    p.save()

#view for displaying the bookings of the user
def my_bookings(request):
    if 'normal' in request.session:
        user = request.user
        current_date = timezone.now().date()
        my_bookings = Booking.objects.filter(user = user, is_confirmed = True)
        return render(request, 'my_bookings.html', {'my_bookings': my_bookings, 'current_date': current_date})
    else:
        return redirect('login')
    
def cancel_booking(request, booking_id):
    if 'normal' in request.session:
        booking = get_object_or_404(Booking, id=booking_id)
        current_date = timezone.now().date()

        if request.method == 'POST':
            if booking.cancellation:
            # Check if the trip date is more than a week away
                if booking.trip_date > current_date + timedelta(weeks=1):
                    booking.is_cancelled = True
                    booking.is_confirmed = False  
                    booking.refunded_amount = booking.total_amount  
                    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

                    try:
                        # Create a refund
                        refund_response = client.payment.refund(booking.razorpay_payment_id, {
                            'amount': int(booking.total_amount * 100) 
                        })

                        if refund_response.get('id'):
                            booking.save()  
                            messages.success(request, 'Booking has been cancelled successfully. Amount refunded.')
                        else:
                            messages.error(request, 'Refund failed. Please contact support.')
                    except Exception as e:
                        messages.error(request, f'Error processing refund: {str(e)}')
                else:
                    messages.error(request, 'Cancellation is only allowed if the trip date is more than a week away.')
            else:
                messages.error(request, 'Cancellation is not available for this package')
        else:
            messages.error(request, 'Failed to cancel the booking.')

        return redirect('my_bookings')
    else:
        return redirect('login')
    
#view for listing the booking for a travel agency
def ta_bookings(request):
    if 'travel' in request.session:
        current_month = timezone.now().month
        current_year = timezone.now().year
        months = Booking.objects.dates('trip_date', 'month')
        travel_agency = TravelAgency.objects.get(username=request.user.username)
        bookings = Booking.objects.filter(package__agency_id = travel_agency, is_confirmed=True).order_by('trip_date')
        return render(request, 'ta_bookings.html', {'bookings': bookings, 'months': months})
    else:
        return redirect('login')
    
#view for group messaging
def get_new_messages(request, group_id, last_message_id):
    if 'normal' in request.session:
        group = TravelGroup.objects.get(group_id=group_id)
        new_messages = Message.objects.filter(group=group, id__gt=last_message_id).order_by('send_at')
        messages_data = [
            {'id': message.id, 'user': message.user.username, 'content': message.content, 'send_at': message.send_at}
            for message in new_messages
        ]
        return JsonResponse({'messages': messages_data})
    else:
        return redirect('login')
    
def group_chat_view(request, group_id):
    if 'normal' in request.session:
        group = get_object_or_404(TravelGroup, group_id=group_id)
        messages = Message.objects.filter(group=group).order_by('send_at')
        if messages.exists():
            last_message = messages.last()  # Get the first message since it's ordered by -send_at
            last_message_id = last_message.id
        else:
            last_message_id = 0
        return render(request, 'chat.html', {'group': group, 'messages': messages, 'last_message_id': last_message_id,})
    else:
        return redirect('login')
    
def send_message(request, group_id):
    if 'normal' in request.session:
        if request.method == 'POST':
            group = get_object_or_404(TravelGroup, group_id=group_id)
            content = request.POST.get('content', '')
            if content:
                # Create the message and get the time it was sent
                message = Message.objects.create(user=request.user, group=group, content=content)
                # Return the response with the username and the time
                return JsonResponse({
                    'success': True,
                    'username': message.user.username,
                    'content': message.content,
                    'send_at': message.send_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'message_id': message.id
                })
        return JsonResponse({'success': False})
    else:
        return redirect('login')
    
#view for searching for packages
def package_search(request):
    query = request.GET.get('query', '')
    packages = TravelPackage.objects.filter(Q(destination__icontains=query) | Q(title__icontains=query))  # Adjust as necessary

    # Render the filtered packages as HTML
    return render(request, 'package_partial.html', {'packages': packages})

#view for searching for group
def group_search(request):
    query = request.GET.get('query', '')
    groups = TravelGroup.objects.filter(Q(destination__icontains=query) | Q(name__icontains=query)) 

    # Render the filtered packages as HTML
    return render(request, 'group_partial.html', {'groups': groups})

#view for searching the available groups
def available_group_search(request):
    if 'normal' in request.session:
        query = request.GET.get('query', '')
        groups = TravelGroup.objects.filter(is_active=True).exclude(current_members=request.user).annotate(current_count=Count('current_members')).filter(current_count__lt=F('max_members'))

        # If a search query is present, apply additional filters
        if query:
            groups = groups.filter(Q(destination__icontains=query) | Q(name__icontains=query))
            return render(request, 'group_partial.html', {'groups': groups})
    else:
        return redirect('login')
    
#local guide registration view
def guide_registration(request):
    if request.method == "POST":
        # Get uploaded file and form data
        documents = request.FILES.get("guide_license")
        agreement = request.POST.get("agreement") == 'on'
        years_of_experience = request.POST.get("years_of_experience")
        cost_per_day = request.POST.get('cost_per_day')
        languages_known = request.POST.get("languages_known")
        location = request.POST.get("location")
        
        # Fetch details from session
        username = request.session.get("username")
        name = request.session.get("name")
        email = request.session.get("email")
        number = request.session.get("number")
        password = request.session.get("password")

        if not all([username, name, email, number, password]):
            return redirect('register')  # Redirect if session data is incomplete

        if agreement:
            try:
                hashed_password = make_password(password)
                # Save the local guide
                local_guide = LocalGuide(
                    username=username,
                    name=name,
                    email=email,
                    contact=number,
                    password=hashed_password,
                    guide_license=documents,
                    agreement=agreement,
                    years_of_experience=years_of_experience,
                    languages_known=languages_known,
                    location=location,
                    cancellation=True,
                    approved=False,
                    cost_per_day=cost_per_day
                )
                local_guide.save()
                
                # Save in the CustomUser model
                user = CustomUser(
                    username=username,
                    first_name=name,
                    email=email,
                    password=hashed_password,
                    phone_number=number,
                    role='guide',
                    travel_guide=local_guide
                )
                user.save()

                return HttpResponseRedirect(reverse("login"))
            except IntegrityError:
                print(IntegrityError)
                return render(request, "guide_registration.html", {
                    "message": "Username or email already exists"
                })
    else:
        return render(request, "guide_registration.html")
    
#view for the homepage of local guide
def guide_home(request):
    if 'guide' in request.session:
        try:
            guide =LocalGuide.objects.get(username=request.user.username)
            if not guide.approved:
                return render(request, "login.html", {
                    "message": "Approval pending"
                })
        except LocalGuide.DoesNotExist:
            return redirect('login')
        
        today = timezone.now().date()
        total_bookings = GuideBooking.objects.filter(guide=guide).count()
        upcoming_tours = GuideBooking.objects.filter(guide=guide, start_date__gte=today).count()
        completed_tours = GuideBooking.objects.filter(guide=guide, end_date__lt=today).count()
        total_earnings = GuideBooking.objects.filter(guide=guide, end_date__lt=today).aggregate(Sum('total_amount'))['total_amount__sum'] or 0
        context = {
        'total_bookings': total_bookings,
        'upcoming_tours': upcoming_tours,
        'completed_tours': completed_tours,
        'total_earnings': round(total_earnings, 2),
        }
        return render(request, 'guide_home.html', context)
    else:
        return redirect('login')
    
#view for approving travel guide
def approve_local_guide(request, guide_id):
    if 'master' in request.session:
        guide = get_object_or_404(LocalGuide, pk=guide_id)
        guide.approved = True
        guide.save()
        send_mail(
                'Account Approved Notification',
                f'Dear {guide.name},\n\n'
                f'This email is to inform you that your account with EXPLORE HUB has been approved.'
                'You can start using our platform from now on.'
                'If you have any questions, please contact support.',
                'explorehub123@gmail.com',
                [guide.email]
            )
        return redirect('admin_approve_agencies')
    else:
        return redirect('login')
    
#view for local guide listing
def local_guide_list(request):
    guides = LocalGuide.objects.filter(approved=True)
    return render(request, 'localguide.html', {'guides': guides})

#view for searching the local guide listing
def guide_search(request):
    query = request.GET.get('query', '').strip()
    guides = LocalGuide.objects.filter(approved=True, name__icontains=query) if query else LocalGuide.objects.filter(approved=True)
    return render(request, 'guide_list_partial.html', {'guides': guides})

#view for detailed view of local guide
def local_guide_detail(request, guide_id):
    guide = get_object_or_404(LocalGuide, guide_id=guide_id, approved=True)
    bookings = GuideBooking.objects.filter(guide_id=guide_id, payment_status='Completed', is_cancelled=False)
    booked_dates = []
    for booking in bookings:
        current_date = booking.start_date
        while current_date <= booking.end_date:
            booked_dates.append(current_date.strftime('%Y-%m-%d'))
            current_date += timedelta(days=1)
    print(booked_dates)
    return render(request, 'local_guide_detail.html', {'guide': guide, 'booked_dates': booked_dates})

#view for request guidance by the regular user
def request_guidance(request, guide_id):
    if 'normal' in request.session:
        if request.method == 'POST':
            guide = get_object_or_404(LocalGuide, pk=guide_id)
            location_request = request.POST.get('location_request')
            
            advice_request = AdviceRequest(
                guide_name = guide.name,
                user_name = request.user.username,
                location = location_request,
            )
            advice_request.save()
            return redirect('local_guide_detail', guide_id=guide_id)
        return redirect('local_guide_list')
    else:
        return redirect('login')

#view for booking local guide by the regular user
def book_guide(request, guide_id):
    if 'normal' in request.session:
        guide = get_object_or_404(LocalGuide, pk=guide_id)
        if request.method == 'POST':
            start_date = request.POST.get('start_date')
            end_date = request.POST.get('end_date')
            number_of_people = request.POST.get('number_of_people')
            try:
                days = (datetime.strptime(end_date, "%Y-%m-%d") - datetime.strptime(start_date, "%Y-%m-%d")).days + 1
                total_amount = days * guide.cost_per_day 
            except ValueError:
                return redirect('local_guide_detail', guide_id=guide_id)
            booking = GuideBooking.objects.create(
            user=request.user,
            guide=guide,
            start_date=start_date,
            end_date=end_date,
            number_of_people=number_of_people,
            total_amount=total_amount,
            payment_status='Pending',
            booking_id=str(uuid.uuid4()),
            cancellation=guide.cancellation,
            )

            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            razorpay_order = client.order.create({
                'amount': int(total_amount * 100),  
                'currency': 'INR',
                'payment_capture': '1'
            })
            request.session['razorpay_order_id'] = booking.booking_id

            # booking.razorpay_order_id = razorpay_order['id']
            booking.save()

            context = {
                'booking_type': 'Guide Service',
                'title': guide.name,
                'total_amount': total_amount,
                'razorpay_key': settings.RAZORPAY_KEY_ID,
                'razorpay_order_id': razorpay_order['id'],
                'payment_success_url': 'guide_payment_success',
            }
            return render(request, 'payment_page.html', context)
        return redirect('local_guide_list')
    else:
        return redirect('login')
    
#view for payment success for guide booking
@csrf_exempt
def guide_payment_success(request):
    if 'normal' in request.session:
        razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        if request.method == 'POST':
            payment_id = request.POST.get('razorpay_payment_id', '')
            razorpay_order_id = request.POST.get('razorpay_order_id', '')
            signature = request.POST.get('razorpay_signature', '')

            try:
                params_dict = {
                    'razorpay_order_id': razorpay_order_id,
                    'razorpay_payment_id': payment_id,
                    'razorpay_signature': signature
                }

                razorpay_client.utility.verify_payment_signature(params_dict)

                booking = GuideBooking.objects.get(booking_id=request.session['razorpay_order_id'])
                booking.payment_status = 'completed'
                booking.transaction_id = payment_id
                booking.is_confirmed = True
                booking.payment_date = timezone.localtime()
                booking.razorpay_payment_id = payment_id
                booking.save()

                user = request.user.customuser

                pdf_buffer = BytesIO()
                generate_guide_pdf(booking, pdf_buffer)
                pdf_buffer.seek(0)

                email = EmailMessage(
                    subject='Guide Booking Confirmation',
                    body=f'Your booking with guide {booking.guide.name} has been confirmed. Booking ID: {booking.booking_id}',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[booking.user.email],
                )

                email.attach('guide_booking_details.pdf', pdf_buffer.getvalue(), 'application/pdf')

                email.send(fail_silently=False)
                pdf_data = base64.b64encode(pdf_buffer.getvalue()).decode('utf-8')
                pdf_buffer.close()

                return render(request, 'guide_payment_success.html', {'booking': booking, 'pdf_data': pdf_data})

            except razorpay.errors.SignatureVerificationError:
                return HttpResponse("Payment failed. Signature verification failed.", status=400)

        return HttpResponse("Invalid request.")
    else:
        return redirect('login')
    
#pdf receipt for guide booking
def generate_guide_pdf(booking, buffer):
    p = canvas.Canvas(buffer, pagesize=A4)

    logo_path = "static/images/logo.png"        
    p.drawImage(logo_path, 50, 770, width=40, height=50)

    p.setTitle("Guide Booking Invoice")

    p.setFont("Helvetica-Bold", 24)
    p.drawCentredString(300, 740, "Guide Booking Invoice")

    p.setFont("Helvetica", 12)
    p.drawString(50, 725, "Explore Hub")
    p.drawString(50, 710, "123 Travel Street")
    p.drawString(50, 695, "Travel City, TC 12345")
    p.drawString(50, 680, "Phone: +91 1234567890")
    p.drawString(50, 665, "Email: explorehub123@gmail.com")

    p.line(50, 655, 550, 655)

    # Booking and guide details
    total_days = (booking.end_date - booking.start_date).days + 1
    total_cost = total_days * booking.guide.cost_per_day

    booking_details = [
        ["Customer Name:", booking.user.first_name],
        ["Email:", booking.user.email],
        ["Booking ID:", booking.booking_id],
        ["Guide Name:", booking.guide.name],
        ["Start Date:", booking.start_date.strftime('%d-%m-%Y')],
        ["End Date:", booking.end_date.strftime('%d-%m-%Y')],
        ["Total Days:", f"{total_days} days"],
        ["Cost per Day:", f"₹{booking.guide.cost_per_day:.2f}"],
        ["Total Amount:", f"₹{total_cost:.2f}"],
        ["Payment Date:", booking.payment_date.strftime('%d-%m-%Y')],
        ["Transaction ID:", booking.transaction_id]
    ]

    table = Table(booking_details, colWidths=[150, 350])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  
        ('FONTSIZE', (0, 0), (-1, 0), 12),  
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige), 
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  
    ]))

    table.wrapOn(p, 400, 600)
    table.drawOn(p, 50, 400)

    p.line(50, 380, 550, 380)

    # Thank you message
    p.setFont("Helvetica-Oblique", 10)
    p.drawCentredString(300, 120, "Thank you for booking a guide with Explore Hub!")
    p.drawCentredString(300, 105, "Please contact us if you have any questions regarding your booking.")

    p.showPage()
    p.save()

#view for listing the replies to the requests from the local guide
def advice_request_list(request):
    if 'normal' in request.session:
        advice_requests = AdviceRequest.objects.filter(user_name=request.user.username).order_by('-created_at')
        return render(request, 'advice_request_list.html', {'advice_requests': advice_requests})
    else:
        return redirect('login')
    
#view for viewing the reply for the requests from the local guide
def advice_reply_detail(request, request_id):
    if 'normal' in request.session:
        advice_request = get_object_or_404(AdviceRequest, id=request_id, user_name=request.user.username)
        return render(request, 'advice_reply_detail.html', {'advice_request': advice_request})
    else:
        return redirect('login')
    
#view for listing all the requests made by the users to the guide
def advice_requests_view(request):
    if 'guide' in request.session:
        advice_requests = AdviceRequest.objects.filter(guide_name=request.user.first_name).order_by('-created_at')
        return render(request, 'advice_requests.html', {'advice_requests': advice_requests})
    else:
        return redirect('login')    
    
def reply_advice_request(request, request_id):
    if 'guide' in request.session:
        if request.method == 'POST':
            advice_request = get_object_or_404(AdviceRequest, id=request_id)
            reply = request.POST.get('reply')
            if reply:
                advice_request.guide_response = reply
                advice_request.save()
                messages.success(request, "Your reply has been submitted successfully.")
            else:
                messages.error(request, "Reply cannot be empty.")
        return redirect('advice_requests')
    else:
        return redirect('login')
    
#view for displaying the bookings of local guide
@login_required
def local_guide_bookings(request):
    if 'guide' in request.session:
        guide = LocalGuide.objects.get(username=request.user.username)
        bookings = GuideBooking.objects.filter(guide=guide, payment_status='Completed', end_date__gt=timezone.now()).order_by('start_date')
        return render(request, 'guide_bookings.html', {'bookings': bookings, 'guide':guide})
    else:
        return redirect('login')
    
@login_required
def booking_details(request, booking_id):
    if 'guide' in request.session:
        guide = LocalGuide.objects.get(username=request.user.username)
        booking = get_object_or_404(GuideBooking, pk=booking_id)
        try:
            plan = BookingPlan.objects.get(booking=booking)
            return render(request, 'guide_booking_detail.html', {'booking': booking, 'guide': guide, 'plan' : plan})
        except:
            return render(request,'guide_booking_detail.html', {'booking': booking, 'guide': guide})
        
    else:
        return redirect('login')
    
#view for updating the trip plan by the guide
def guide_update_trip_plan(request, booking_id):
    if 'guide' in request.session:
        booking = get_object_or_404(GuideBooking, pk=booking_id)
        try:
            plan = BookingPlan.objects.get(booking=booking)
            if request.method == 'POST':
                itinerary = request.POST.get('trip_itinerary')
                plan = BookingPlan.objects.get(booking=booking)
                plan.guide_plan = itinerary

                plan.save()
        except BookingPlan.DoesNotExist:
            if request.method == 'POST':
                itinerary = request.POST.get('trip_itinerary')
                plan = BookingPlan.objects.create(booking=booking)
                plan.guide_plan = itinerary

                plan.save()

        return redirect('booking_details', booking_id=booking_id)
    else:
        return redirect('login')
    
#view for listing guide bookings by the user
def my_guide_bookings(request):
    if 'normal' in request.session:
        my_bookings = GuideBooking.objects.filter(user=request.user, end_date__gt=timezone.now(), payment_status='Completed').order_by('start_date')
        context = {
            'my_bookings': my_bookings,
            'is_guide_bookings': True,
        }
        return render(request, 'my_bookings.html', context)
    else:
        return redirect('login')

#view for cancelling guide booking
def cancel_guide_booking(request, booking_id):
    if 'normal' in request.session:
        booking = get_object_or_404(GuideBooking, id=booking_id)
        current_date = timezone.now().date()

        if request.method == 'POST':
            if booking.cancellation:
                if booking.start_date > current_date + timedelta(weeks=1):
                    booking.is_cancelled = True
                    booking.is_confirmed = False
                    booking.refunded_amount = booking.total_amount  
                    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

                    try:
                        refund_response = client.payment.refund(booking.razorpay_payment_id, {
                            'amount': int(booking.total_amount * 100) 
                        })

                        if refund_response.get('id'):
                            booking.save() 
                            messages.success(request, 'Guide booking has been cancelled successfully. Amount refunded.')
                        else:
                            messages.error(request, 'Refund failed. Please contact support.')
                    except Exception as e:
                        messages.error(request, f'Error processing refund: {str(e)}')
                else:
                    messages.error(request, 'Cancellation is only allowed if the trip date is more than a week away.')
            else:
                messages.error(request, 'Cancellation is not available for this guide booking.')
        else:
            messages.error(request, 'Failed to cancel the guide booking.')

        return redirect('my_guide_bookings')  
    else:
        return redirect('login')
    
#view for viewing the details of the guide booked by the user
def guide_booking_detail(request, booking_id):
    if 'normal' in request.session:
        booking = get_object_or_404(GuideBooking, pk=booking_id)
        try:
            plan = BookingPlan.objects.get(booking=booking)
        except BookingPlan.DoesNotExist:
            plan = None
        if request.method == 'POST':
            suggestion_text = request.POST.get('suggestion_text')
            
            if suggestion_text:
                if len([char for char in suggestion_text if char.isalpha()]) < 3:
                    messages.error(request, "Enter valid suggestion")
                    return redirect("guide_booking_detail", booking_id=booking_id)
                else:
                    suggestion = BookingPlan.objects.update(
                        booking=booking,
                        user_preferences=suggestion_text
                    )
                    messages.success(request, "Your suggestion has been submitted successfully!")
                    return redirect('guide_booking_detail', booking_id=booking_id)

        context = {
            'booking': booking,
            'plan': plan
        }
        return render(request, 'my_guide_details.html', context)
    else:
        return redirect('login')

#view for updating profile of guide
def update_guide_profile(request):
    if 'guide' in request.session:
        guide = get_object_or_404(LocalGuide, username=request.user.username)

        if request.method == "POST":
            guide.name = request.POST.get('name')
            guide.contact = request.POST.get('contact')
            guide.email = request.POST.get('email')
            guide.location = request.POST.get('location')
            guide.years_of_experience = request.POST.get('years_of_experience')
            guide.languages_known = request.POST.get('languages_known')        
            guide.cost_per_day = request.POST.get('cost_per_day')
            guide.save()
            return redirect('guide_home')  

        return render(request, 'guide_update_profile.html', {'guide': guide})
    return redirect('login')

def itinerary_planner(request):
    if request.method == 'POST':
        budget = request.POST.get('budget')
        origin = request.POST.get('origin')
        destination = request.POST.get('destination')
        duration = int(request.POST.get('duration'))
        preferences = request.POST.get('preferences')
        start_date = request.POST.get('start_date')
        no_of_people = request.POST.get('no_of_people')

        start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
        end_date = start_date_obj + timedelta(days=duration)

        origin_code = get_city_code(origin)
        # print(origin_code)
        destination_code = get_city_code(destination)
        # print(destination_code)

        flights = search_flights(origin_code, destination_code, start_date, end_date) if origin_code and destination_code else "No flights available"
        hotels = search_hotels(destination_code)
        activities = search_activities(destination)
        trains = search_trains(origin, destination, start_date)
        # print(search_buses(origin, destination, start_date))

        items=[]

        if isinstance(flights, dict):  
            carriers = flights.get("dictionaries", {}).get("carriers", {})
            aircrafts = flights.get("dictionaries", {}).get("aircraft", {})

            if "data" in flights and isinstance(flights["data"], list):
                for flight in flights["data"]:
                    airline_code = flight.get("airline", "")
                    aircraft_code = flight.get("aircraft", "")

                    airline_name = carriers.get(airline_code, airline_code)
                    aircraft_name = aircrafts.get(aircraft_code, aircraft_code)

                    items.append({
                        "name": f"Flight: {airline_name} - {aircraft_name}",
                        "cost": flight.get("cost", 0),
                        "value": flight.get("rating", 0),
                        "category": "transport"
                    })


        if isinstance(trains, list):
            for train in trains:
                items.append({
                    "name": f"Train: {train.get('train', 'Unknown Train')}",
                    "cost": train.get("cost", 0),
                    "value": train.get("rating", 0),
                    "category": "transport"
                })

        if isinstance(hotels, list):
            for hotel in hotels:
                items.append({
                    "name": f"Hotel: {hotel.get('name', 'Unknown Hotel')}",
                    "cost": hotel.get("cost_per_night", 0) * duration,  
                    "value": hotel.get("rating", 0),
                    "category": "hotel"
                })

        if isinstance(activities, list):
            for activity in activities:
                items.append({
                    "name": f"Activity: {activity.get('name', 'Unknown Activity')}",
                    "cost": activity.get("cost", 0),
                    "value": activity.get("rating", 0),
                    "category": "activity"
                })
        # print(items, budget)

        selected_items, total_cost = knapsack(items, budget)

        planned_itinerary = {
            "destination": destination,
            "start_date": start_date,
            "end_date": end_date.isoformat(),
            "budget": budget,
            "used_budget": total_cost,
            "details": selected_items
        }
        return render(request, 'itinerary_planner.html', {'itinerary': planned_itinerary})
    return render(request, 'itinerary_planner.html')


def knapsack(items, max_budget):
    n = len(items)
    max_budget = int(max_budget)
    dp = [[0 for _ in range(max_budget + 1)] for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for w in range(max_budget + 1):
            if items[i - 1]["cost"] <= w:
                dp[i][w] = max(items[i - 1]["value"] + dp[i - 1][w - items[i - 1]["cost"]], dp[i - 1][w])
            else:
                dp[i][w] = dp[i - 1][w]

    w = max_budget
    selected_items = []
    total_cost = 0
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i - 1][w]:
            selected_items.append(items[i - 1])
            w -= items[i - 1]["cost"]
            total_cost += items[i - 1]["cost"]

    print(selected_items, total_cost)

    return selected_items, total_cost


def get_amadeus_access_token():
    url = "https://test.api.amadeus.com/v1/security/oauth2/token"
    client_id = settings.AMADEUS_CLIENT_ID
    client_secret = settings.AMADEUS_CLIENT_SECRET

    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }

    response = requests.post(url, data=payload)

    if response.status_code == 200:
        return response.json()['access_token']
    else:
        raise Exception('Failed to get Amadeus access token')
    
def get_city_code(city_name):
    access_token = get_amadeus_access_token()  
    url = "https://test.api.amadeus.com/v1/reference-data/locations"

    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"keyword": city_name, "subType": "CITY"}  

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        if "data" in data and len(data["data"]) > 0:
            return data["data"][0]["iataCode"]  # Return IATA code if available
        else:
            return get_city_code_google(city_name)  # Fallback to Google Places API
    else:
        return get_city_code_google(city_name)

def get_city_code_google(city_name):
    api_key = settings.GOOGLE_PLACES_API_KEY
    url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json"

    params = {
        "input": city_name,
        "inputtype": "textquery",
        "fields": "name,geometry",
        "key": api_key
    }

    response = requests.get(url, params=params)

    if response.status_code == 200:
        data = response.json()
        if "candidates" in data and len(data["candidates"]) > 0:
            return city_name.upper()  
        else:
            return None  
    else:
        return None  

# def search_buses(origin, destination, date_of_journey):
#     options = Options()
#     options.add_argument("--disable-gpu")
#     options.add_argument("--no-sandbox")
#     options.add_argument("--ignore-certificate-errors")
#     options.add_argument("--allow-running-insecure-content")
#     options.add_argument("--incognito")

#     driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

#     driver.get("https://www.abhibus.com")

#     time.sleep(3)

#     wait = WebDriverWait(driver, 10)

#     from_input = wait.until(EC.element_to_be_clickable((By.XPATH, "//input[@placeholder='From Station']")))
#     from_input.send_keys(origin)
#     time.sleep(2)
#     from_input.send_keys(Keys.RETURN)

#     to_input = wait.until(EC.element_to_be_clickable((By.XPATH, "//input[@placeholder='To Station']")))
#     to_input.send_keys(destination)
#     time.sleep(2)
#     to_input.send_keys(Keys.RETURN)

#     date_input = driver.find_element(By.XPATH, "//input[@placeholder='Onward Journey Date']")
#     date_input.click()
#     time.sleep(1)
#     date_input.send_keys(Keys.RETURN)

#     search_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Search')]")
#     search_button.click()

#     time.sleep(5)

#     buses = driver.find_elements(By.XPATH, "//div[contains(@id, 'service-operator-info')]")
    
#     bus_list = []
    
#     for bus in buses:
#         try:
#             operator_name = bus.find_element(By.XPATH, ".//h5[@class='title']").text
#             bus_type = bus.find_element(By.XPATH, ".//p[@class='sub-title']").text
#             departure_time = bus.find_element(By.XPATH, ".//span[@class='departure-time']").text
#             travel_time = bus.find_element(By.XPATH, ".//div[@class='travel-time']").text
#             arrival_time = bus.find_element(By.XPATH, ".//span[@class='arrival-time']").text
#             destination = bus.find_element(By.XPATH, ".//div[@class='destination-name']").text
#             fare = bus.find_element(By.XPATH, ".//strong[@class='h5 fare']/span").text

#             bus_list.append({
#                 "operator_name": operator_name,
#                 "bus_type": bus_type,
#                 "departure_time": departure_time,
#                 # "source": source,
#                 "travel_time": travel_time,
#                 "arrival_time": arrival_time,
#                 "destination": destination,
#                 "fare": fare,
#             })
        
#         except Exception as e:
#             print("Error extracting bus details:", e)

#     driver.quit()
#     return bus_list


def search_trains(origin, destination, start_date):
    api_url = f"https://www.ixigo.com/trains/v2/search/between/{origin}/{destination}?date={start_date}&languageCode=en"
    
    headers = {
        "accept": "*/*",
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
        "apikey": "iximweb!2$",  
    }

    try:
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            train_data = response.json()
            return train_data
        else:
            return HttpResponse(f"Error: {response.status_code}", status=response.status_code)

    except requests.exceptions.RequestException as e:
        return HttpResponse(f"API Request Failed: {e}", status=500)
    
def search_flights(origin, destination, departure_date, return_date=None):
    access_token = get_amadeus_access_token()
    url = f"https://test.api.amadeus.com/v2/shopping/flight-offers"

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    params = {
        "originLocationCode": get_city_code(origin),  
        "destinationLocationCode": get_city_code(destination), 
        "departureDate": departure_date, 
        "returnDate": return_date if return_date else None,
        "adults": 1
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Error fetching flight data")
    
def search_hotels(city_code):
    access_token = get_amadeus_access_token()
    url = f"https://test.api.amadeus.com/v1/reference-data/locations/hotels/by-city"

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    params = {
        "cityCode": get_city_code(city_code),  
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Error fetching hotel data")
    
def get_lat_long(location):
    geocoder = OpenCageGeocode(settings.OPENCAGE_API_KEY)
    result = geocoder.geocode(location)

    if result and len(result):
        latitude = result[0]['geometry']['lat']
        longitude = result[0]['geometry']['lng']
        return latitude, longitude
    else:
        raise Exception(f"Could not find location: {location}")
    
def search_activities(location):
    access_token = get_amadeus_access_token()
    url = f"https://test.api.amadeus.com/v1/shopping/activities"

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    latitude, longitude = get_lat_long(location)

    params = {
        "latitude": latitude,  
        "longitude": longitude
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Error fetching activities data")
    
def event_organizer_registration(request):
    if request.method == "POST":
        bio = request.POST.get("bio")
        organizer_license = request.FILES.get("organizer_license")
        agreement = request.POST.get("agreement") == 'on'
        print(organizer_license)

        username = request.session.get("username")
        name = request.session.get("name")
        email = request.session.get("email")
        number = request.session.get("number")
        password = request.session.get("password")

        if not all([username, name, email, number, password]):
            return redirect('register')
        
        if agreement:
            try:
                hashed_password = make_password(password)
                organizer = EventOrganizer(
                    username=username,
                    name=name,
                    email=email,
                    contact=number,
                    password=hashed_password,
                    bio=bio,
                    organizer_license=organizer_license,
                    agreement=agreement,
                    approved=False
                )
                organizer.save()

                user = CustomUser(
                    username=username,
                    first_name=name,
                    email=email,
                    password=hashed_password,
                    phone_number=number,
                    role='organizer',
                    event_organizer=organizer
                )
                user.save()
                return HttpResponseRedirect(reverse("login"))
            except IntegrityError:
                print(IntegrityError)
                return render(request, "registration.html", {
                    "message": "Username or email already exists"
                })
    else:
        return render(request, "event_organizer_registration.html")

#view for approving event organizer
def approve_organizer(request, organizer_id):
    if 'master' in request.session:
        organizer = get_object_or_404(EventOrganizer, pk=organizer_id)
        organizer.approved = True
        organizer.save()
        send_mail(
                'Account Approved Notification',
                f'Dear {organizer.name},\n\n'
                f'This email is to inform you that your account with EXPLORE HUB has been approved.'
                'You can start using our platform from now on.'
                'If you have any questions, please contact support.',
                'explorehub123@gmail.com',
                [organizer.email]
            )
        return redirect('admin_approve_agencies')
    else:
        return redirect('login')
    
#view for home page of event organizer
def event_organizer_home(request):
    if 'organizer' in request.session:
        try:
            organizer = EventOrganizer.objects.get(username=request.user.username)
            if not organizer.approved:
                return render(request, "login.html", {
                    "message": "Approval pending"
                })
        except EventOrganizer.DoesNotExist:
            return redirect('login')
        events = Event_tbl.objects.filter(organizer_id=organizer).count()
        upcoming_events = Event_tbl.objects.filter(organizer_id=organizer, event_date__gte=timezone.now()).count()
        booking_count = EventBooking.objects.filter(event__organizer_id=organizer).count()
        return render(request, 'event_organizer_home.html', {'events': events, 'upcoming_events': upcoming_events, 'booking_count': booking_count})
    else:
        return redirect('login')
    
#view for creating event by the event organizer
def create_event(request):
    if 'organizer' in request.session:
        if request.method == 'POST':
            event_name = request.POST.get('event_name')
            event_date = request.POST.get('event_date')
            event_time = request.POST.get('event_time')
            event_location = request.POST.get('event_location')
            event_description = request.POST.get('event_description')
            event_image = request.FILES.getlist('event_image')
            event_capacity = request.POST.get('event_capacity')
            event_price = request.POST.get('event_price')

            organizer = EventOrganizer.objects.get(username=request.user.username)
            event = Event_tbl(
                organizer_id=organizer,
                title=event_name,
                event_date=event_date,
                event_time=event_time,
                location=event_location,
                description=event_description,
                max_seats=event_capacity,
                price=event_price
            )
            event.save()

            for image in event_image:
                        EventImage.objects.create(
                            event=event,
                            image=image,
                        )
            return redirect('event_organizer_home')
        return render(request, 'create_event.html')
    else:
        return redirect('login')
    
#view for listing the events
def event_list(request):
    events = Event_tbl.objects.filter(event_date__gte=timezone.now(), is_active=True)
    return render(request, 'event_list.html', {'events': events})

#view for details of the events
def event_detail(request, event_id):
    event = get_object_or_404(Event_tbl, pk=event_id)
    images = EventImage.objects.filter(event=event)
    available_seats = event.max_seats - event.booking_count
    return render(request, 'event_detail.html', {'event': event, 'images': images, 'available_seats': available_seats})

#view for searching the events
def event_search(request):
    query = request.GET.get('query', '')
    if query:
        events = Event_tbl.objects.filter(title__icontains=query, is_active=True)  
    else:
        events = Event_tbl.objects.all()

    return render(request, 'event_list_partial.html', {'events': events})

#view for booking the event
def book_event(request, event_id):
    if 'normal' in request.session:
        event = get_object_or_404(Event_tbl, pk=event_id)
        if request.method == 'POST':
            number_of_seats = request.POST.get('number_of_seats')
            total_amount = int(number_of_seats) * event.price
            booking = EventBooking(
                user=request.user,
                event=event,
                number_of_people=number_of_seats,
                total_amount=total_amount,
                event_date=event.event_date,
                organizer=event.organizer_id,
                payment_status='Pending',
                booking_id=str(uuid.uuid4()),
            )

            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            razorpay_order = client.order.create({
                'amount': int(total_amount * 100),  
                'currency': 'INR',
                'payment_capture': '1'
            })
            request.session['razorpay_order_id'] = booking.booking_id

            booking.save()

            context = {
                'booking_type': 'Event',
                'title': event.title,
                'total_amount': total_amount,
                'razorpay_key': settings.RAZORPAY_KEY_ID,
                'razorpay_order_id': razorpay_order['id'],
                'payment_success_url': 'event_payment_success',
            }
            return render(request, 'payment_page.html', context)
        return redirect('event_list')
    else:
        return redirect('login')
    
#view for payment success for event booking
@csrf_exempt
def event_payment_success(request):
    if 'normal' in request.session:
        razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        if request.method == 'POST':
            payment_id = request.POST.get('razorpay_payment_id', '')
            razorpay_order_id = request.POST.get('razorpay_order_id', '')
            signature = request.POST.get('razorpay_signature', '')

            try:
                params_dict = {
                    'razorpay_order_id': razorpay_order_id,
                    'razorpay_payment_id': payment_id,
                    'razorpay_signature': signature
                }

                razorpay_client.utility.verify_payment_signature(params_dict)

                booking = EventBooking.objects.get(booking_id=request.session['razorpay_order_id'])
                booking.payment_status = 'completed'
                booking.transaction_id = payment_id
                booking.is_confirmed = True
                booking.payment_date = timezone.localtime()
                booking.razorpay_payment_id = payment_id
                booking.save()

                user = request.user.customuser

                pdf_buffer = BytesIO()
                generate_event_pdf(booking, pdf_buffer)
                pdf_buffer.seek(0)

                email = EmailMessage(
                    subject='Event Booking Confirmation',
                    body=f'Your booking for event {booking.event.title} has been confirmed. Booking ID: {booking.booking_id}',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[booking.user.email],
                )

                email.attach('event_booking_details.pdf', pdf_buffer.getvalue(), 'application/pdf')

                email.send(fail_silently=False)
                pdf_data = base64.b64encode(pdf_buffer.getvalue()).decode('utf-8')
                pdf_buffer.close()

                return render(request, 'event_payment_success.html', {'booking': booking, 'pdf_data': pdf_data})

            except razorpay.errors.SignatureVerificationError:
                return HttpResponse("Payment failed. Signature verification failed.", status=400)

        return HttpResponse("Invalid request.")
    else:
        return redirect('login')
    
#pdf receipt for event booking
def generate_event_pdf(booking, buffer):
    p = canvas.Canvas(buffer, pagesize=A4)

    logo_path = "static/images/logo.png"  
    p.drawImage(logo_path, 50, 770, width=40, height=50)

    p.setTitle("Event Booking Invoice")

    p.setFont("Helvetica-Bold", 24)
    p.drawCentredString(300, 740, "Event Booking Invoice")

    p.setFont("Helvetica", 12)
    p.drawString(50, 725, "Explore Hub")
    p.drawString(50, 710, "123 Travel Street")
    p.drawString(50, 695, "Travel City, TC 12345")
    p.drawString(50, 680, "Phone: +91 1234567890")
    p.drawString(50, 665, "Email: explorehub123@gmail.com")

    p.line(50, 655, 550, 655)

    total_cost = booking.total_amount

    booking_details = [
        ["Customer Name:", booking.user.first_name],
        ["Email:", booking.user.email],
        ["Booking ID:", booking.booking_id],
        ["Event Name:", booking.event.title],
        [" Date:", booking.event.event_date.strftime('%d-%m-%Y')],
        ["Total Amount:", f"₹{total_cost:.2f}"],
        ["Payment Date:", booking.payment_date.strftime('%d-%m-%Y')],
        ["Transaction ID:", booking.transaction_id]
    ]

    table = Table(booking_details, colWidths=[150, 350])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  
        ('FONTSIZE', (0, 0), (-1, 0), 12),  
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige), 
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  
    ]))

    table.wrapOn(p, 400, 600)
    table.drawOn(p, 50, 400)

    p.line(50, 380, 550, 380)

    # Thank you message
    p.setFont("Helvetica-Oblique", 10)
    p.drawCentredString(300, 120, "Thank you for booking an event with Explore Hub!")
    p.drawCentredString(300, 105, "Please contact us if you have any questions regarding your booking.")

    p.showPage()
    p.save()

#view for listing the event bookings of the user
def my_event_bookings(request):
    if 'normal' in request.session:
        my_bookings = EventBooking.objects.filter(user=request.user, event__event_date__gte=timezone.now(), payment_status='completed').order_by('event__event_date')
        context = {
            'my_bookings': my_bookings,
            'is_event_bookings': True,
        }
        return render(request, 'my_bookings.html', context)
    else:
        return redirect('login')
    
#view for viewing bookings for the organizer
def event_organizer_bookings(request):
    if 'organizer' in request.session:
        organizer = EventOrganizer.objects.get(username=request.user.username)
        bookings = EventBooking.objects.filter(organizer=organizer)
        months = EventBooking.objects.dates('event_date', 'month')

        context = {
            "organizer": organizer,
            "bookings": bookings,
            "months": months,
        }
        return render(request, 'event_organizer_bookings.html', context)
    else:
        return redirect('login')
    
#view for listing all the events of the organizer
def my_events(request):
    if 'organizer' in request.session:
        organizer = EventOrganizer.objects.get(username=request.user.username)
        events = Event_tbl.objects.filter(organizer_id=organizer, is_active=True)
        return render(request, 'my_events.html', {'events': events})
    else:
        return redirect('login')
    
#view for updating the event details
def update_event(request, event_id):
    if 'organizer' in request.session:
        event = get_object_or_404(Event_tbl, pk=event_id)
        if request.method == 'POST':
            event.title = request.POST.get('event_name')
            event.event_date = request.POST.get('event_date')
            event.event_time = request.POST.get('event_time')
            event.location = request.POST.get('event_location')
            event.description = request.POST.get('event_description')
            event.max_seats = request.POST.get('event_capacity')
            event.price = request.POST.get('event_price')
            event.save()
            return redirect('my_events')
        return render(request, 'update_event.html', {'event': event})
    else:
        return redirect('login')
    
#view for deleting the event
def delete_event(request, event_id):
    if 'organizer' in request.session:
        event = get_object_or_404(Event_tbl, pk=event_id)
        event.is_active = False
        event.save()
        return redirect('my_events')
    else:
        return redirect('login')
    
#view for showing evnet participants
def event_participants(request, event_id):
    if 'organizer' in request.session:
        event = get_object_or_404(Event_tbl, pk=event_id)
        bookings = EventBooking.objects.filter(event=event)
        return render(request, 'event_participants.html', {'event': event, 'bookings': bookings})
    else:
        return redirect('login')
    
#view for updating the profile of the event organizer
def event_organizer_profile(request):
    if 'organizer' in request.session:
        organizer = get_object_or_404(EventOrganizer, username=request.user.username)
        event_organizer = get_object_or_404(CustomUser, username=request.user.username)

        if request.method == "POST":
            organizer.name = request.POST.get('name')
            organizer.contact = request.POST.get('contact')
            organizer.bio = request.POST.get('bio')
            organizer.save()
            event_organizer.first_name = request.POST.get('name')
            event_organizer.phone_number = request.POST.get('contact')
            event_organizer.save()
            return redirect('event_organizer_home')  

        return render(request, 'event_organizer_profile.html', {'organizer': organizer})
    return redirect('login')