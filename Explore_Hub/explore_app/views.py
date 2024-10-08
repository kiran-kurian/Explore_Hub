from datetime import timezone, datetime
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
from django.db.models import F, Count
import uuid
import razorpay
from django.views.decorators.csrf import csrf_exempt
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from io import BytesIO
import base64

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
            elif role in ['guide', 'eorg']:
                return render(request, "registration.html", {
                    "message": "Currently not available"
                })
            else:
                # Create regular user record
                user = CustomUser.objects.create_user(username=username, email=email, password=password, first_name=name, phone_number=number, role=role)
                # user.first_name = name
                # user.phone_number = number
                # user.role = role
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
    travel_package = TravelPackage.objects.prefetch_related('package_images').filter(is_archived=False)
    return render(request, "packages.html", {'packages': travel_package})

#detailed package view
def package_details(request, package_id):
    package = get_object_or_404(TravelPackage, pk = package_id)
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
        pending_agencies = TravelAgency.objects.filter(approved=False)
        return render(request, 'approve_agencies.html', {'agencies': pending_agencies})
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
        package = TravelPackage.objects.prefetch_related('package_images').filter(is_archived=False)
        return render(request, 'admin_manage_package.html', {'packages': package})
    else:
        return redirect('login')

@login_required(login_url='login')
def admin_manage_archived_packages(request):
    if 'master' in request.session:
        package = TravelPackage.objects.prefetch_related('package_images').filter(is_archived=True)
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

#view for home page of travel agency
@never_cache
@login_required(login_url='login')
def ta_home(request):
    if 'travel' in request.session:
        try:
            agency = TravelAgency.objects.get(username=request.user.username)
            if not agency.approved:
                return render(request, "login.html", {
                    "message": "Approval pending"
                })
            packages = TravelPackage.objects.filter(agency_id=agency, is_archived=False).prefetch_related('package_images')
        except TravelAgency.DoesNotExist:
            return redirect('login')
        return render(request, 'ta_home.html', {'agency': agency, 'packages': packages})
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
            packages = TravelPackage.objects.filter(agency_id=agency, is_archived=True).prefetch_related('package_images')
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
                departure_day = request.POST.get('departure_day')
                cancellation = request.POST.get('cancellation') == 'on'
                itinerary = request.POST.get('itinerary')
                images = request.FILES.getlist('images')

                valid_image_types = ['image/jpeg', 'image/png', 'image/gif']

                if title and description and price and duration and origin and destination and departure_day:

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
                        departure_day=departure_day,
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
                package.departure_day = request.POST.get('departure_day', package.departure_day)
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
    try:
        package = get_object_or_404(TravelPackage, pk=package_id)
        package.delete()
        messages.success(request, 'Package deleted successfully!')
    except IntegrityError:
        messages.error(request, 'Failed to delete the package')
    return redirect('tahome')

#to delete package by admin
def admin_archive_package(request, package_id):
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

#view for listing available groups
def group_view(request):
    groups = TravelGroup.objects.filter(is_active=True).annotate(current_count=Count('current_members')).filter(current_count__lt=F('max_members'))
    return render(request, 'travel_group.html',{'groups':groups})
    
#view for available groups
def available_groups(request):
    if 'normal' in request.session:
        available_groups = TravelGroup.objects.filter(is_active=True).exclude(current_members=request.user).annotate(current_count=Count('current_members')).filter(current_count__lt=F('max_members'))
        return render(request, 'available_group.html',{'available_groups': available_groups})
    else:
        return redirect('login')

#view for user joined group
@never_cache
def user_group(request):
    if 'normal' in request.session:
        user_group = TravelGroup.objects.filter(current_members=request.user.id)
        return render(request, 'user_group.html',{'user_groups': user_group})
    else:
        return redirect('login')

def create_group(request):
    if 'normal' in request.session:
        if request.method == 'POST':
            group_name = request.POST.get('group_name')
            destination = request.POST.get('destination')
            max_members = request.POST.get('max_members')
            description = request.POST.get('description')

            username = request.user.username
            creator = CustomUser.objects.get(username=username)
            # Create a new group
            new_group = TravelGroup(
                name=group_name,
                destination=destination,
                max_members=max_members,
                creator=creator,  
                description=description
            )
            new_group.save()

            # Add the creator as the first member of the group
            new_group.current_members.add(creator)

            
            return redirect('user_group')
        return render(request, 'create_group.html')
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
    
#view for detailed group view
def group_detail_view(request, group_id):
    if 'normal' in request.session:
        group = get_object_or_404(TravelGroup, group_id=group_id)
        return render(request, 'group_detail.html', {'group': group})
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

#view for booking package
def book_package_view(request, package_id):
    package = get_object_or_404(TravelPackage, pk=package_id)
    user = request.user.customuser
    print(settings.RAZORPAY_KEY_SECRET)
    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
    if request.method == 'POST':
        number_of_people = int(request.POST.get('number_of_people', 1))
        total_amount = package.price * number_of_people
        
        # Create a new booking entry
        booking = Booking.objects.create(
            user=request.user,
            package=package,
            total_amount=total_amount,
            booking_id=str(uuid.uuid4()),
            number_of_people=number_of_people,
            payment_status='pending',  # Initially set payment status to pending
        )
        
        # Create Razorpay order
        razorpay_order = razorpay_client.order.create({
            'amount': int(total_amount * 100),  # Amount in paise (100 paise = 1 INR)
            'currency': 'INR',
            'payment_capture': '1'
        })
        
        # Store Razorpay order ID in session for further verification
        request.session['razorpay_order_id'] = booking.booking_id
        
        context = {
            'package': package,
            'booking': booking,
            'razorpay_key': settings.RAZORPAY_KEY_ID,
            'razorpay_order_id': razorpay_order['id'],
            'total_amount': total_amount,
        }
        return render(request, 'payment_page.html', context) 
    
    return render(request, 'book_package.html', {'package': package, 'user': user})

#payment confirmation view
@csrf_exempt
def payment_success(request):
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
            booking.payment_date = datetime.now()
            booking.save()

            user = request.user.customuser

            # Send confirmation email
            # send_mail(
            #     'Booking Confirmation',
            #     f"Dear {booking.user.first_name},\n\nYour booking for {booking.package.title} has been confirmed.\n\nBooking ID: {booking.booking_id}\nTotal Amount: ₹{booking.total_amount}\nNumber of People: {booking.number_of_people}\nPhone Number: {user.phone_number}\n\nThank you for booking with us!",
            #     settings.DEFAULT_FROM_EMAIL,
            #     [booking.user.email],
            #     fail_silently=False,
            # )
            
            pdf_buffer = BytesIO()
            generate_pdf(booking, pdf_buffer)
            pdf_buffer.seek(0)
            
            
            # Here you can send the PDF as an email attachment if needed
            # send_mail(
            #     'Booking Confirmation',
            #     f"Dear {booking.user.first_name},\n\nYour booking for {booking.package.title} has been confirmed.\n\nBooking ID: {booking.booking_id}\nTotal Amount: ₹{booking.total_amount}\nNumber of People: {booking.number_of_people}\nPhone Number: {user.phone_number}\n\nThank you for booking with us!",
            #     'Please find attached your booking details.',
            #     settings.DEFAULT_FROM_EMAIL,
            #     [booking.user.email],
            #     fail_silently=False,
            #     attachments=[('booking_details.pdf', pdf_buffer.read(), 'application/pdf')]
            # )
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

def generate_pdf(booking, buffer):
    # Create a canvas object
    p = canvas.Canvas(buffer, pagesize=A4)

    # Set title and document properties
    p.setTitle("Booking Invoice")

    # Draw invoice title
    p.setFont("Helvetica-Bold", 24)
    p.drawString(200, 800, "Booking Invoice")

    # Draw company details
    p.setFont("Helvetica", 12)
    p.drawString(50, 770, "Explore Hub")
    p.drawString(50, 755, "123 Travel Street")
    p.drawString(50, 740, "Travel City, TC 12345")
    p.drawString(50, 725, "Phone: +91 1234567890")
    p.drawString(50, 710, "Email: explorehub123@gmail.com")

    # Draw a horizontal line
    p.line(50, 695, 550, 695)

    # Draw customer details
    p.drawString(50, 670, f"Customer: {booking.user.username}")
    p.drawString(50, 655, f"Email: {booking.user.email}")
    p.drawString(50, 640, f"Booking ID: {booking.booking_id}")
    p.drawString(50, 625, f"Package: {booking.package.title}")

    # Draw booking details
    p.drawString(50, 600, f"Amount Paid: ₹{booking.total_amount}")
    p.drawString(50, 585, f"Payment Date: {booking.payment_date.strftime('%d-%m-%Y')}")
    p.drawString(50, 570, f"Transaction ID: {booking.transaction_id}")

    # Draw a horizontal line
    p.line(50, 550, 550, 550)

    # Draw footer
    p.setFont("Helvetica-Oblique", 10)
    p.drawString(50, 500, "Thank you for booking with Explore Hub!")
    p.drawString(50, 485, "Please contact us if you have any questions regarding your booking.")

    # Save the PDF to the buffer
    p.showPage()
    p.save()

