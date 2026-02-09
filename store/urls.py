from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    StoreViewSet,
    ProductViewSet,
    ReviewViewSet,
    VendorStoresView,
    StoreProductsView,
)


router = DefaultRouter()

router.register("stores", StoreViewSet)
router.register("products", ProductViewSet)
router.register("reviews", ReviewViewSet)
app_name = "ecommerce"

urlpatterns = [
    # Public Pages (for buyers)
    path('customer/home/', views.home, name='home'),
    path('customer/home/products/', views.product_list, name='product_list'),
    path('customer/home/cart/', views.view_cart, name='cart'),
    path('customer/home/cart/checkout/', views.checkout, name='checkout'),
    path(
        'customer/home/store/<int:store_id>/',
        views.store_detail, name='store_detail'
         ),

    # Cart Management
    path(
        'customer/products/cart/add_to_cart/<int:product_id>/',
        views.add_to_cart, name='add_to_cart'
        ),
    path(
        'customer/products/cart/remove_from_cart/<int:product_id>/',
        views.remove_from_cart, name='remove_from_cart'
        ),
    path(
        'customer/products/cart/clear_cart/',
        views.clear_cart, name='clear_cart'
        ),

    # Authentication
    path('', views.login_view, name='login'),  # root goes to custom login
    path('logout/', views.custom_logout, name='logout'),

    # Vendor Dashboard & Store Management
    path('vendor/dashboard/', views.vendor_dashboard, name='vendor_dashboard'),
    path('vendor/store/create/', views.create_store, name='create_store'),
    path(
        'vendor/store/<int:store_id>/edit/',
        views.edit_store, name='edit_store'
        ),
    path(
        'vendor/store/<int:store_id>/delete/',
        views.delete_store, name='delete_store'
        ),

    # Vendor Product Management
    path(
        'vendor/store/<int:store_id>/products/',
        views.store_products, name='store_products'
        ),
    path('vendor/store/<int:store_id>/add-product/',
         views.add_product, name='add_product'
         ),
    path(
        'vendor/product/<int:product_id>/edit/',
        views.edit_product, name='edit_product'
        ),
    path(
        'vendor/product/<int:product_id>/delete/',
        views.delete_product, name='delete_product'
        ),

    # Registration
    path('register/', views.register, name='register'),
    path('register/vendor/', views.vendor_register, name='vendor_register'),
    path(
        'register/customer/', views.customer_register, name='customer_register'
        ),

    # Password reset URLs
    path(
        'forgot-password/send/',
        views.send_password_reset,
        name='send_password_reset'
    ),
    path('reset_password/<str:token>/', views.reset_user_password, name='password_reset'),
    path('login/', views.login_view, name='login'),

    # API's
    path(
        'api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'
        ),
    path(
        'api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'
        ),

    # Step 1: user submits email
    path(
        "password-reset/",
        views.send_password_reset,
        name="password_reset"
    ),

    # Step 2: user clicks emailed link (token in URL)
    path(
        "reset-password/<str:token>/",
        views.reset_user_password,
        name="reset_user_password"
    ),

    # Step 3: user submits new password
    path(
        "reset-password/confirm/",
        views.reset_password,
        name="reset_password_confirm"
    ),
    path("reset-password/", views.forgot_password, name="forgot_password"),

    path("", include(router.urls)),

    path(
        "vendors/<int:vendor_id>/stores/",
        VendorStoresView.as_view()
    ),

    path(
        "stores/<int:store_id>/products/",
        StoreProductsView.as_view()
    ),
    ]
