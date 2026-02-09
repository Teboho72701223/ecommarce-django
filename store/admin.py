from django.contrib import admin
from .models import Store, Product


# These are going to be store that have been registered
@admin.register(Store)
class StoreAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor')
    list_filter = ('vendor',)
    search_fields = ('name', 'owner__username')


# These are going to be products that have been registered
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'store')
    list_filter = ('store',)
    search_fields = ('name', 'store__name')
