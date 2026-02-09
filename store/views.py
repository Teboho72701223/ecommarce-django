from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login, logout
from django.urls import reverse, reverse_lazy
from requests import Response
from .serializers import StoreSerializer
from .utils.tweet import Tweet
from .forms import ProductForm, StoreForm, ReviewForm, User
from .models import ResetToken, Store, Product, Vendor, Review
from .forms import VendorRegisterForm, CustomerRegisterForm
from django.contrib.auth import views as auth_views
from django.core.mail import EmailMessage
from hashlib import sha1
from django.http import HttpResponse
import secrets
from django.conf import settings
from .models import Product, Order
from .emails import send_invoice_email
from datetime import datetime, timedelta, timezone
import secrets
from django.contrib.auth import get_user_model
from rest_framework.viewsets import ModelViewSet
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated

from .models import Store, Product, Review, Vendor
from .serializers import (
    StoreSerializer,
    ProductSerializer,
    ReviewSerializer,
)
from .permissions import IsVendor


# HOME
@login_required
def home(request):
    stores = Store.objects.all()  # Show all vendor stores
    return render(request, 'store/home.html', {'stores': stores})


# Store Details
def store_detail(request, store_id):
    store = get_object_or_404(Store, id=store_id)
    products = store.products.all()
    # newest review will be shown first
    reviews = store.reviews.all().order_by('-created_at')
    form = ReviewForm(request.POST or None)

    # Handle review POST
    if request.method == 'POST':
        if request.user.is_authenticated:
            form = ReviewForm(request.POST)
            if form.is_valid():
                # Check if the user already reviewed this store
                existing_review = Review.objects.filter(
                    store=store, customer=request.user
                    ).exists()
                if existing_review:
                    return redirect(
                        'ecommerce:store_detail', store_id=store.id
                        )

                review = form.save(commit=False)
                review.store = store
                review.customer = request.user
                review.save()
                return redirect('ecommerce:store_detail', store_id=store.id)
        else:
            return redirect('ecommerce:login')

    context = {
        'store': store,
        'products': products,
        'reviews': reviews,
        'form': form,
    }
    return render(request, 'store/store_detail.html', context)


# AUTHENTICATION
# The user will enter depending if they are a
# vendor or customer they will be able to enter diffrent applications
def login_view(request):
    if request.user.is_authenticated:
        if getattr(request.user, 'is_vendor', False):
            return redirect('ecommerce:vendor_dashboard')
        return redirect('ecommerce:home')

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)

            if getattr(user, 'is_vendor', False):
                return redirect('ecommerce:vendor_dashboard')
            return redirect('ecommerce:home')
    else:
        form = AuthenticationForm()

    return render(request, 'store/login.html', {'form': form})


@login_required
def custom_logout(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('ecommerce:login')


# Registeration
def register(request):
    # Will just display options between vendor/customer
    return render(request, 'store/register.html')


# CUSTOMER REGISTRATION

def customer_register(request):
    if request.method == 'POST':
        form = CustomerRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_vendor = False  # important flag
            user.save()
            messages.success(
                request,
                "Customer account created successfully! Please log in."
                )
            return redirect('ecommerce:login')
    else:
        form = CustomerRegisterForm()

    return render(request, 'store/customer_register.html', {'form': form})


# VENDOR REGISTRATION

def vendor_register(request):
    if request.method == 'POST':
        form = VendorRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_vendor = True
            user.is_customer = False
            user.save()

            # Create the Vendor profile immediately after saving user
            Vendor.objects.create(
                user=user,
                # store_name=form.cleaned_data['store_name'],
                phone=form.cleaned_data['phone'],
                address=form.cleaned_data['address'],
            )

            return redirect('ecommerce:login')
    else:
        form = VendorRegisterForm()

    return render(request, 'store/vendor_register.html', {'form': form})


# CART (CUSTOMER SIDE)

@login_required
def product_list(request):
    products = Product.objects.all()  # List the products of the vendor
    return render(request, 'store/product_list.html', {'products': products})


@login_required
def clear_cart(request):
    request.session['cart'] = {}
    request.session.modified = True
    return redirect('ecommerce:cart')


@login_required
def add_to_cart(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    cart = request.session.get('cart', {})

    if str(product_id) in cart:
        # Will count how many items that are on customers cart
        cart[str(product_id)]['quantity'] += 1
    else:
        cart[str(product_id)] = {
            'name': product.name,
            'price': float(product.price),
            'quantity': 1,
            'image': product.image.url if product.image else '',
        }

    request.session['cart'] = cart
    return redirect('ecommerce:cart')


# Will show the total of the customers cart viewing whta they have ordered
@login_required
def view_cart(request):
    cart = request.session.get('cart', {})
    total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render(request, 'store/cart.html', {
        'cart_items': cart,
        'cart_total': total
    })


@login_required
def remove_from_cart(request, product_id):
    cart = request.session.get('cart', {})
    if str(product_id) in cart:
        del cart[str(product_id)]
        request.session['cart'] = cart
    return redirect('ecommerce:cart')


@login_required
def checkout(request):
    cart = request.session.get('cart', {})
    cart_items = []
    total = 0

    for product_id, item in cart.items():
        product = get_object_or_404(Product, id=product_id)
        quantity = item['quantity']
        total_price = product.price * quantity
        cart_items.append({
            'product': product,
            'quantity': quantity,
            'total_price': total_price
        })
        total += total_price

    # ONLY handle order + email on POST
    if request.method == "POST":
        # create order
        order = Order.objects.create(
            user=request.user,
            email=request.POST.get("email"),
            total=total,
        )

        # send invoice email
        email_sent = send_invoice_email(order)

        # warn if email failed
        if not email_sent:
            messages.warning(
                request,
                "Your order was placed successfully, but we could not send the invoice email."
            )

        # clear cart
        request.session["cart"] = {}

        return redirect("ecommerce:home")  # or order success page

    #  GET request → just show page
    return render(request, 'store/checkout.html', {
        'cart_items': cart_items,
        'total': total
    })


# VENDOR DASHBOARD & STORE MANAGEMENT
@login_required
def vendor_dashboard(request):
    # Check if the user is a vendor
    if not hasattr(request.user, 'is_vendor') or not request.user.is_vendor:
        return render(request, 'store/not_vendor.html')
    # Get vendors stores
    try:
        vendor = Vendor.objects.get(user=request.user)
    except Vendor.DoesNotExist:
        # handle case where the user is not a vendor
        vendor = None

    stores = Store.objects.filter(vendor=vendor) if vendor else []

    context = {
        'vendor': request.user,
        'stores': stores,
    }
    return render(request, 'store/vendor_dashboard.html', context)


@login_required
def create_store(request):
    if request.method == "POST":
        form = StoreForm(request.POST, request.FILES)

        if form.is_valid():
            vendor = Vendor.objects.filter(user=request.user).first()

            if not vendor:
                return HttpResponse(
                    "You must be registered as a vendor before creating a store.",
                    status=403
                )

            store = form.save(commit=False)
            store.vendor = vendor
            store.save()

            # Tweet AFTER successful save
            new_store_tweet = (
                f"New store open on Teboho eCommarce!\n"
                f"{store.name}\n\n{store.description}"
            )
            # try:
            Tweet._instance.make_tweet({"text": new_store_tweet})
            # except Exception as e:
                # Log it, but do NOT crash
                # print("Tweet failed:", e)

            return redirect('ecommerce:vendor_dashboard')  # adjust if needed
    else:
        form = StoreForm()

    return render(request, "store/create_store.html", {"form": form})




@login_required
def edit_store(request, store_id):
    vendor = Vendor.objects.get(user=request.user)
    store = get_object_or_404(Store, id=store_id, vendor=vendor)

    if request.method == 'POST':
        store.name = request.POST.get('name')
        store.description = request.POST.get('description')
        store.vendor = vendor
        store.save()  # Save changes that have been made
        messages.success(request, "Store details updated successfully!")
        return redirect('ecommerce:vendor_dashboard')

    return render(request, 'store/edit_store.html', {'store': store})


@login_required
def delete_store(request, store_id):
    vendor = get_object_or_404(Vendor, user=request.user)
    store = get_object_or_404(Store, id=store_id, vendor=vendor)
    store.delete()
    return redirect('ecommerce:vendor_dashboard')


@login_required
def add_product(request, store_id):
    vendor = Vendor.objects.filter(user=request.user).first()
    if not vendor:
        return HttpResponse(
            "You must be registered as a vendor to add products.",
            status=403
        )

    store = get_object_or_404(Store, id=store_id, vendor=vendor)

    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            product = form.save(commit=False)
            product.store = store
            product.save()

            # Tweet AFTER successful save
            new_product_tweet = (
                f"New product just dropped on Teboho eCommarce!\n"
                f"{product.name}\n"
                f"Store: {store.name}"
            )

            Tweet._instance.make_tweet({"text": new_product_tweet})

            return redirect('ecommerce:vendor_dashboard')
    else:
        form = ProductForm()

    return render(
        request,
        'store/add_product.html',
        {
            'form': form,
            'store': store,
        }
    )



@login_required
def edit_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    # Ensure only the store owner can edit
    if product.store.owner != request.user:
        messages.error(
            request, "You don't have permission to edit this product."
            )
        return redirect('vendor_dashboard')

    if request.method == 'POST':
        product.name = request.POST.get('name')
        product.description = request.POST.get('description')
        product.price = request.POST.get('price')
        product.stock = request.POST.get('stock')
        product.save()
        messages.success(request, 'Product updated successfully!')
        return redirect('vendor_dashboard')

    return render(request, 'store/edit_product.html', {'product': product})


@login_required
def store_products(request, store_id):
    vendor = Vendor.objects.get(user=request.user)
    store = get_object_or_404(Store, id=store_id, vendor=vendor)
    products = store.products.all()
    return render(
        request, 'store/store_products.html',
        {'store': store, 'products': products}
        )


@login_required
def delete_product(request, product_id):
    product = get_object_or_404(
        Product, id=product_id, store__owner=request.user
        )
    product.delete()
    return redirect('ecommerce:vendor_dashboard')


# PASSWORD RESET
class CustomPasswordResetView(auth_views.PasswordResetView):
    template_name = "store/password_reset.html"
    email_template_name = "store/password_reset_email.html"
    subject_template_name = "store/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")


class CustomPasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = "store/password_reset_done.html"


class CustomPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "store/password_reset_confirm.html"
    success_url = reverse_lazy("password_reset_complete")


class CustomPasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = "store/password_reset_complete.html"


# Email
def build_email(user, reset_url):
    subject = "Password Reset"
    body = (
        f"Hi {user.username},\n\n"
        f"Click the link below to reset your password:\n"
        f"{reset_url}\n\n"
        f"This link expires in 5 minutes."
    )
    return EmailMessage(
        subject,
        body,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )


def generate_reset_url(request, user):
    token = secrets.token_urlsafe(32)
    hashed_token = sha1(token.encode()).hexdigest()

    # Remove old tokens
    ResetToken.objects.filter(user=user).delete()

    ResetToken.objects.create(
        user=user,
        token=hashed_token,
        expiry_date=timezone.now() + timedelta(minutes=5)
    )

    return request.build_absolute_uri(
        reverse('ecommerce:reset_user_password', args=[token])
    )


User = get_user_model()

def send_password_reset(request):
    user_email = request.POST.get('email')

    user = User.objects.filter(email=user_email).first()
    if user:
        url = generate_reset_url(request, user)
        build_email(user, url).send()

    # Always redirect (prevents email enumeration)
    return HttpResponseRedirect(reverse('ecommerce:login'))


def reset_user_password(request, token):
    hashed_token = sha1(token.encode()).hexdigest()

    reset_token = ResetToken.objects.filter(token=hashed_token).first()
    if not reset_token:
        return render(request, 'password_reset.html', {'token': None})

    if reset_token.expiry_date < timezone.now():
        reset_token.delete()
        return render(request, 'password_reset.html', {'token': None})

    request.session['user'] = reset_token.user.username
    request.session['token'] = token

    return render(request, 'password_reset.html', {'token': token})

    
def change_user_password(username, password):
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return False

    user.set_password(password)
    user.save(update_fields=["password"])
    return True
    

def reset_password(request):
    username = request.session.get('user')
    token = request.session.get('token')

    if not username or not token:
        return HttpResponseRedirect(reverse('ecommerce:password_reset'))

    password = request.POST.get('password')
    password_conf = request.POST.get('password_conf')

    if not password or password != password_conf:
        return HttpResponseRedirect(reverse('ecommerce:password_reset'))

    hashed_token = sha1(token.encode()).hexdigest()

    try:
        reset_token = ResetToken.objects.get(token=hashed_token)
    except ResetToken.DoesNotExist:
        return HttpResponseRedirect(reverse('ecommerce:password_reset'))

    # Change password
    change_user_password(username, password)

    # Invalidate token
    reset_token.delete()

    # Cleanup session
    request.session.pop('user', None)
    request.session.pop('token', None)

    return HttpResponseRedirect(reverse('ecommerce:login'))


def forgot_password(request):
    return render(request, 'store/forgot_password.html')


# ---------------- Vendor Stores ----------------

class StoreViewSet(ModelViewSet):

    queryset = Store.objects.all()
    serializer_class = StoreSerializer
    permission_classes = [IsAuthenticated, IsVendor]

    def get_queryset(self):

        return Store.objects.filter(
            vendor__user=self.request.user
        )

    def perform_create(self, serializer):

        vendor = self.request.user.vendor_profile
        serializer.save(vendor=vendor)


# ---------------- Products ----------------

class ProductViewSet(ModelViewSet):

    queryset = Product.objects.all() 
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated, IsVendor]

    def get_queryset(self):

        return Product.objects.filter(
            store__vendor__user=self.request.user
        )


# ---------------- Reviews (Read Only) ----------------

class ReviewViewSet(ModelViewSet):

    queryset = Product.objects.all() 
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    queryset = Review.objects.all()


# ---------------- Public Browsing ----------------

class VendorStoresView(ListAPIView):

    serializer_class = StoreSerializer

    def get_queryset(self):

        return Store.objects.filter(
            vendor_id=self.kwargs["vendor_id"]
        )


class StoreProductsView(ListAPIView):

    serializer_class = ProductSerializer

    def get_queryset(self):

        return Product.objects.filter(
            store_id=self.kwargs["store_id"]
        )
