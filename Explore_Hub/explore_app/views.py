from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from explore_app.models import *
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.cache import never_cache
from django.contrib import messages

# Create your views here.

#login page view
def login_view(request):
    if request.method == "POST":

        # Attempt to sign user in
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)


        # Check if authentication successful
        if user is not None:
            login(request, user)
            if user.is_superuser:
                return HttpResponseRedirect(reverse('admin_dashboard'))
            else:
                custom_user = CustomUser.objects.get(id=user.id)
                role = custom_user.role
                if role == 'ta':
                    return HttpResponseRedirect(reverse('tahome'))
                else:
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
    return HttpResponseRedirect(reverse("regularuser"))

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

            login(request, user)
            return HttpResponseRedirect(reverse("regularuser"))
        except IntegrityError:
            return render(request, "registration.html", {
                "message": "Username already taken."
            })
    else:
        return render(request, "registration.html")

#Package listing view
def package_view(request):
    travel_package = TravelPackage.objects.all()
    return render(request, "packages.html", {'package': travel_package})

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
        user = CustomUser(username=username, first_name=name, email=email, password=hashed_password,phone_number=number, role='ta')
        user.save()
        login(request, user)
        return HttpResponseRedirect(reverse("tahome"))
    else:
        return render(request, "ta_registration.html")

#default homepage of the website
def reg_user_home_view(request):
    return render(request, 'index.html')

#admin page view
@login_required
@user_passes_test(admin_check)
def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')

@login_required
def admin_approve_agencies(request):
    pending_agencies = TravelAgency.objects.filter(approved=False)
    return render(request, 'approve_agencies.html', {'agencies': pending_agencies})

@login_required
def approve_travel_agency(request, agency_id):
    agency = get_object_or_404(TravelAgency, pk=agency_id)
    agency.approved = True
    agency.save()
    return redirect('admin_approve_agencies')

@login_required
def admin_manage_packages(request):
    return render(request, 'admin_dashboard.html')

def admin_manage_groups(request):
    return render(request, 'admin_dashboard.html')

def ta_home(request):
    try:
        agency = TravelAgency.objects.get(username=request.user.username)
        if not agency.approved:
            return render(request, "login.html", {
                "message": "Approval pending"
            })
        packages = TravelPackage.objects.filter(agency_id=agency)
    except TravelAgency.DoesNotExist:
        return redirect('register')
    return render(request, 'ta_home.html', {'agency': agency, 'packages': packages})

#to manage profile of travel agency
def manage_profile(request):
    return render("ta_home.html")

#to add package by the travel agency
@login_required
def add_package(request):
    if request.method == 'POST':
        user = request.user
        if hasattr(user, 'customuser') and user.customuser.travel_agency:
            travel_agency = user.customuser.travel_agency

            title = request.POST.get('title')
            description = request.POST.get('description')
            price = request.POST.get('price')
            image = request.FILES.get('image')

            if title and description and price and image:
                # Create and save the package
                package = TravelPackage(
                    title=title,
                    description=description,
                    price=price,
                    image=image,
                    agency_id=travel_agency  # Set the current agency as the owner
                )
                package.save()

                return redirect('tahome')  # Redirect to the home page or another page
    return render(request, 'add_package.html')

#to update package by the travel agency
def update_package(request, package_id):
    package = get_object_or_404(TravelPackage, pk=package_id)
    if request.method == 'POST':
        try:
            # Update package attributes
            package.title = request.POST.get('title', package.title)
            package.description = request.POST.get('description', package.description)
            package.price = request.POST.get('price', package.price)

            # Handle image file upload
            if 'image' in request.FILES:
                package.image = request.FILES['image']
            
            package.save()
            messages.success(request, 'Package updated successfully!')
            return redirect('tahome')
        except:
            messages.error(request, f'An error occurred')
    return render(request, 'update_package.html', {'package': package})

#to delete package by the travel agency
def delete_package(request, package_id):
    try:
        package = get_object_or_404(TravelPackage, pk=package_id)
        package.delete()
        messages.success(request, 'Package deleted successfully!')
    except IntegrityError:
        messages.error(request, 'Failed to delete the package due to integrity error.')
    return redirect('tahome')
