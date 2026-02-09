"""
Models for the ecommerce application.

This module defines database models for users, vendors, stores,
products, buyers, reviews, orders, and authentication-related data.
"""

from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser


# -------------------------
# Custom User
# -------------------------
class CustomUser(AbstractUser):
    """
    Custom user model extending Django's AbstractUser.

    Adds support for vendor and customer roles.
    """

    is_vendor = models.BooleanField(default=False)
    is_customer = models.BooleanField(default=True)

    def __str__(self):
        """
        Returns the username of the user.
        """
        return self.username


# -------------------------
# Vendor
# -------------------------
class Vendor(models.Model):
    """
    Represents a vendor who owns and manages stores.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vendor_profile"
    )

    store_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)

    verified = models.BooleanField(default=False)
    joined_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        Returns the vendor's store name.
        """
        return self.store_name


# -------------------------
# Store
# -------------------------
class Store(models.Model):
    """
    Represents a physical or online store owned by a vendor.
    """

    vendor = models.ForeignKey(
        Vendor,
        on_delete=models.CASCADE,
        related_name="stores"
    )

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)

    logo = models.ImageField(
        upload_to="store_logos/",
        blank=True,
        null=True
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        Returns the store name.
        """
        return self.name


# -------------------------
# Product
# -------------------------
class Product(models.Model):
    """
    Represents a product sold in a store.
    """

    store = models.ForeignKey(
        Store,
        related_name="products",
        on_delete=models.CASCADE
    )

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField(default=0)

    image = models.ImageField(
        upload_to="products/",
        blank=True,
        null=True
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        Returns the product name.
        """
        return self.name


# -------------------------
# Buyer
# -------------------------
class Buyer(models.Model):
    """
    Represents a customer who purchases products.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="buyer_profile"
    )

    shipping_address = models.TextField(blank=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        Returns the username of the buyer.
        """
        return self.user.username


# -------------------------
# Review (Linked to Product)
# -------------------------
class Review(models.Model):
    """
    Represents a customer review for a product.
    """

    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name="reviews"
    )

    customer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )

    rating = models.IntegerField()
    comment = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        Returns the rating in readable format.
        """
        return f"{self.rating}/5"


# -------------------------
# Orders
# -------------------------
class Order(models.Model):
    """
    Represents a customer order containing purchased products.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )

    email = models.EmailField()

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)

    address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    province = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)

    total = models.DecimalField(max_digits=10, decimal_places=2)

    payment_method = models.CharField(max_length=50)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        Returns a readable order identifier.
        """
        return f"Order #{self.id}"


# -------------------------
# Order Items
# -------------------------
class OrderItem(models.Model):
    """
    Represents an individual item in an order.
    """

    order = models.ForeignKey(
        Order,
        related_name="items",
        on_delete=models.CASCADE
    )

    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE
    )

    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def total_price(self):
        """
        Calculates the total price for this order item.
        """
        return self.quantity * self.price


# -------------------------
# Password Reset Token
# -------------------------
class ResetToken(models.Model):
    """
    Stores password reset tokens for user authentication.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )

    token = models.CharField(max_length=500)

    expiry_date = models.DateTimeField()

    used = models.BooleanField(default=False)
