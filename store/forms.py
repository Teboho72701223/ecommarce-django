from ast import Store
from django import forms
from .models import Vendor, CustomUser, Store, Review, Product
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

User = get_user_model()


class VendorSignUpForm(forms.ModelForm):
    username = forms.CharField(max_length=150)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = Vendor
        fields = ['store_name', 'phone', 'address']

    def save(self, commit=True):
        # Create the user first
        user = User.objects.create_user(
            username=self.cleaned_data['username'],
            email=self.cleaned_data['email'],
            password=self.cleaned_data['password']
        )
        vendor = super().save(commit=False)
        vendor.user = user
        if commit:
            vendor.save()
        return vendor


class VendorRegisterForm(UserCreationForm):
    # store_name = forms.CharField(max_length=255, required=True)
    phone = forms.CharField(max_length=15, required=False)
    address = forms.CharField(widget=forms.Textarea, required=False)

    class Meta:
        model = User
        fields = [
            'username', 'email', 'password1', 'password2', 'phone', 'address'
                  ]

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already taken.")
        return username


class CustomerRegisterForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']


class StoreForm(forms.ModelForm):
    class Meta:
        model = Store
        fields = ['name', 'description', 'location'] # 'logo']

        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your store name',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Describe what your store offers',
            }),
            'location': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your store location',
            }),
            #'logo': forms.ClearableFileInput(attrs={
                #'class': 'form-control',
            #}),
        }

        labels = {
            'name': 'Store Name',
            'description': 'Store Description',
            'location': 'Store Location',
            'logo': 'Store Logo',
        }


class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ['rating', 'comment']
        widgets = {
            'rating': forms.NumberInput(
                attrs={'min': 1, 'max': 5, 'class': 'form-control'}
                ),
            'comment': forms.Textarea(
                attrs={'class': 'form-control', 'rows': 3}
                ),
        }


class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'description', 'price', 'image']

        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter product name',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Describe the product',
            }),
            'price': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter product price',
                'min': '0',
                'step': '0.01',
            }),
            'image': forms.ClearableFileInput(attrs={
                'class': 'form-control',
            }),
        }

        labels = {
            'name': 'Product Name',
            'description': 'Product Description',
            'price': 'Product Price',
            'image': 'Product Image',
        }
