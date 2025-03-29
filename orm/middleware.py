from django.core.exceptions import PermissionDenied
from django.shortcuts import render

class Custom403Middleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_exception(self, request, exception):
        if isinstance(exception, PermissionDenied):
            return render(request, '403.html', {'message': str(exception)})


from django.shortcuts import render
from django.utils.timezone import now
from orm.models import AppLicense

class LicenseCheckMiddleware:
    """Middleware to enforce app license expiration."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip validation for admin or specific paths
        excluded_paths = ['/admin/', '/license-setup/']
        if any(request.path.startswith(path) for path in excluded_paths):
            return self.get_response(request)

        try:
            license = AppLicense.objects.get(is_active=True)
            if license.has_expired():
                return render(request, 'license_expired.html')  # Show expiration page
        except AppLicense.DoesNotExist:
            return render(request, 'license_not_found.html')  # Handle missing license

        return self.get_response(request)



# orm/middleware.py
from django.utils import timezone
from orm.models import UserActivityLog

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")

class UserActivityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if not request.path.startswith('/admin/'):  # Exclude admin pages
            UserActivityLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                activity_type="page_view",
                timestamp=timezone.now(),
                ip_address=get_client_ip(request),
                page_accessed=request.path,
                user_agent=request.META.get("HTTP_USER_AGENT", "Unknown"),
                session_key=request.session.session_key if hasattr(request, "session") else None,
                referrer=request.META.get("HTTP_REFERER", "Direct Access"),
            )
        return response