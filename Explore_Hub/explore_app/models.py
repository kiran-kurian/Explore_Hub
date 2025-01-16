from django.db import models
from django.contrib.auth.models import User, AbstractUser
from django.db import models
from django.conf import settings
from django.contrib.auth.hashers import make_password

#travel agency table
class TravelAgency(models.Model):
    agency_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    contact = models.CharField(max_length=10)
    email = models.EmailField(unique=True)
    documents = models.FileField(upload_to='documents/')
    agreement = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)

#model for travel guide
class LocalGuide(models.Model):
    guide_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    contact = models.CharField(max_length=10)
    email = models.EmailField(unique=True)
    location = models.CharField(max_length=255) 
    years_of_experience = models.PositiveIntegerField()
    languages_known = models.TextField()
    guide_license = models.FileField(upload_to='guide_licenses/')
    agreement = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)

#to ammend the already known table with phone number and role
class CustomUser(User):
    phone_number = models.CharField(max_length=15, unique=True)
    role = models.CharField(max_length=30,default='reguser')
    travel_agency = models.ForeignKey(TravelAgency, on_delete=models.CASCADE, null=True, blank=True)
    travel_guide = models.ForeignKey(LocalGuide, on_delete=models.CASCADE, null=True, blank=True)

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

#table for travel package
class TravelPackage(models.Model):
    package_id = models.AutoField(primary_key=True)
    agency_id = models.ForeignKey(TravelAgency, on_delete=models.CASCADE, related_name="packages")
    title = models.CharField(max_length=200)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    duration = models.CharField(max_length=10)  
    origin = models.CharField(max_length=200)
    destination = models.CharField(max_length=200, default='Unknown')
    cancellation = models.BooleanField(default=False)
    itinerary = models.TextField(null=True)
    images = models.ManyToManyField('PackageImage')
    is_archived = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)

    def discounted_price(self):
        discount_amount = (self.discount_percentage / 100) * self.price
        return self.price - discount_amount
    
    def you_save(self):
        discount_amount = (self.discount_percentage / 100) * self.price
        return discount_amount

#table for storing images of the packages
class PackageImage(models.Model):
    travel_package = models.ForeignKey(TravelPackage, on_delete=models.CASCADE, related_name='package_images', null=True)
    image = models.ImageField(upload_to='package_images/')
    caption = models.CharField(max_length=255, blank=True)

#table for travel groups
class TravelGroup(models.Model):
    group_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    destination = models.CharField(max_length=200)
    max_members = models.IntegerField(default=10)
    creator = models.ForeignKey(CustomUser, on_delete=models.CASCADE) 
    current_members = models.ManyToManyField(CustomUser, related_name='group_members')
    description = models.TextField()
    trip_date = models.DateField(null=True)
    trip_status = models.CharField(max_length=20, choices=[
        ('not started', 'Not Started'),
        ('started', 'Started'),
        ('completed', 'Completed')
        ], default='Not Started')  
    gender = models.CharField(max_length=20, choices=[
        ('male', 'Male'),
        ('female', 'female'),
        ('no preference', 'No preference')
    ], default='No Preference')
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

#table for package booking
class Booking(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    package = models.ForeignKey('TravelPackage', on_delete=models.CASCADE)
    trip_date = models.DateField(null=True, blank=False)
    booking_date = models.DateTimeField(auto_now_add=True)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    booking_id = models.CharField(max_length=100, unique=True)
    is_confirmed = models.BooleanField(default=False)
    number_of_people = models.PositiveIntegerField(default=1)
    is_cancelled = models.BooleanField(default=False)  
    cancellation_reason = models.TextField(null=True, blank=True)
    cancellation = models.BooleanField(default=False)
    payment_status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='pending')  
    transaction_id = models.CharField(max_length=100, unique=True, null=True, blank=True)  
    payment_method = models.CharField(max_length=50, choices=[
        ('credit_card', 'Credit Card'),
        ('debit_card', 'Debit Card'),
        ('paypal', 'PayPal'),
        ('net_banking', 'Net Banking'),
        ('upi', 'UPI'),
    ], null=True, blank=True)  
    payment_date = models.DateTimeField(null=True, blank=True)
    refunded_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    razorpay_payment_id = models.CharField(max_length=255, blank=True, null=True)
    id_type = models.CharField(max_length=50)
    id_number = models.CharField(max_length=100)
    id_upload = models.FileField(upload_to='id_proofs/')

#model for storing details of passengers
class Passenger(models.Model):
    booking = models.ForeignKey('Booking', on_delete=models.CASCADE, related_name='passengers')
    full_name = models.CharField(max_length=100)
    age = models.PositiveIntegerField()
    gender = models.CharField(max_length=10)

#model for messages
class Message(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(TravelGroup, on_delete=models.CASCADE)
    content = models.TextField()
    send_at = models.DateTimeField(auto_now_add=True)

#model for requesting advice from the local guide
class AdviceRequest(models.Model):
    guide_name = models.CharField(max_length=100)
    user_name = models.CharField(max_length=100)
    location = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    guide_response = models.TextField(null=True, blank=True)
    response_date = models.DateTimeField(null=True, blank=True)