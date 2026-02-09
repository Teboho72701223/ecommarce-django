from rest_framework import serializers
from .models import (
    Store,
    Product,
    Review,
    Vendor
)


# ---------------- Store ----------------

class StoreSerializer(serializers.ModelSerializer):

    class Meta:
        model = Store
        fields = "__all__"
        read_only_fields = ["vendor"]


# ---------------- Product ----------------

class ProductSerializer(serializers.ModelSerializer):

    class Meta:
        model = Product
        fields = "__all__"
        read_only_fields = ["store"]


# ---------------- Review ----------------

class ReviewSerializer(serializers.ModelSerializer):

    class Meta:
        model = Review
        fields = "__all__"
        read_only_fields = ["customer"]


# ---------------- Vendor ----------------

class VendorSerializer(serializers.ModelSerializer):

    stores = StoreSerializer(many=True, read_only=True)

    class Meta:
        model = Vendor
        fields = "__all__"
