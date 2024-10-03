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
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.contrib.auth import views as auth_views
from django.core.cache import cache
from django.core.files.uploadedfile import UploadedFile
from django.core.files.storage import default_storage

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

            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return HttpResponseRedirect(reverse("regularuser"))
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

#Travel agent registration view
def ta_registration_view(request):
    if request.method== "POST":
        documents = request.FILES.get("documents")
        username = request.session.get("username")
        name = request.session.get("name")
        email = request.session.get("email")
        number = request.session.get("number")
        password = request.session.get("password")

        if not all([username, name, email, number, password]):
            return redirect('register')
        
        try:
            hashed_password = make_password(password)
            travelagency = TravelAgency(
                username = username,
                name = name,
                email = email,
                contact = number,
                password = hashed_password,
                documents = documents,
                approved = False
            )
            travelagency.save()
        #saving this to user table
            user = CustomUser(username=username, first_name=name, email=email, password=hashed_password,phone_number=number, role='ta', travel_agency=travelagency)
            user.save()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return HttpResponseRedirect(reverse("tahome"))
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
    agency = get_object_or_404(TravelAgency, pk=agency_id)
    agency.approved = True
    agency.save()
    return redirect('admin_approve_agencies')

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
        return render(request, 'admin_dashboard.html')
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
                includes_charges = request.POST.get('includes_charges') == 'on'
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
                        include_charges=includes_charges,
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

                # Set includes_charges based on dropdown selection
                includes_charges_value = request.POST.get('includes_charges') == 'True'
                package.include_charges = includes_charges_value

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