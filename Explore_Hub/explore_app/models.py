from django.db import models
# Create your models here.
from django.contrib.auth.models import User, AbstractUser
from django.db import models
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
    approved = models.BooleanField(default=False)

#to ammend the already known table with phone number and role
class CustomUser(User):
    phone_number = models.CharField(max_length=15, unique=True)
    role = models.CharField(max_length=30,default='reguser')
    travel_agency = models.ForeignKey(TravelAgency, on_delete=models.CASCADE, null=True, blank=True)

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
    departure_day = models.CharField(max_length=50, default='Everyday')
    include_charges = models.BooleanField(default=False)
    itinerary = models.TextField(null=True)
    images = models.ManyToManyField('PackageImage')
    is_archived = models.BooleanField(default=False)

#table for storing images of the packages
class PackageImage(models.Model):
    travel_package = models.ForeignKey(TravelPackage, on_delete=models.CASCADE, related_name='package_images', null=True)
    image = models.ImageField(upload_to='package_images/')
    caption = models.CharField(max_length=255, blank=True)