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
