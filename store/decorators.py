from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required


def role_required(role):
    def decorator(view_func):  # Decorator that will wrap your view function
        @login_required
        # Replaces the original function
        def _wrapped_view(request, *args, **kwargs):
            if hasattr(request.user, 'profile') and request.user.profile.role == role:
                return view_func(request, *args, **kwargs)
            return redirect('login')  # Unauthorized page
        return _wrapped_view
    return decorator
