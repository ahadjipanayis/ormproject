from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Mitigation, UserProfile

@receiver(post_save, sender=Mitigation)
def add_default_owner(sender, instance, created, **kwargs):
    # Ensure this logic only runs for new mitigations
    if created:
        # Fetch the request user from the instance if available
        request_user = getattr(instance, '_request_user', None)
        if request_user:
            user_profile = UserProfile.objects.filter(user=request_user).first()
            if user_profile and not instance.owners.filter(id=user_profile.id).exists():
                instance.owners.add(user_profile)
from django.db.models.signals import m2m_changed
from django.dispatch import receiver
from django.contrib import messages
from orm.models import Risk

@receiver(m2m_changed, sender=Risk.actions.through)
def check_actions_on_m2m_change(sender, instance, action, **kwargs):
    if action in ['post_add', 'post_remove', 'post_clear']:
        residual_score = instance.residual_likelihood * instance.residual_impact
        targeted_score = instance.targeted_likelihood * instance.targeted_impact

        if targeted_score < residual_score and not instance.actions.exists():
            request = getattr(instance, '_request', None)
            if request:
                messages.warning(
                    request,
                    "Targeted score is lower than residual score, and no actions are associated. Please review your actions."
                )


from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib import messages
from orm.models import Risk  # Replace with the correct import path for your Risk model

@receiver(post_save, sender=Risk)
def check_scores_after_save(sender, instance, created, **kwargs):
    # Calculate scores after the instance has been saved
    residual_score = instance.residual_likelihood * instance.residual_impact
    targeted_score = instance.targeted_likelihood * instance.targeted_impact

    # Check if a warning should be displayed
    if targeted_score < residual_score and not instance.actions.exists():
        # Use the request object if available (from the admin context)
        request = getattr(instance, '_request', None)
        if request:
            messages.warning(
                request,
                "Targeted score is lower than residual score, and no actions are associated. Please review your actions."
            )




from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import DueDiligenceAssessment, AssessmentResponse

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import DueDiligenceAssessment, AssessmentResponse


@receiver(post_save, sender=DueDiligenceAssessment)
def populate_assessment_questions(sender, instance, created, **kwargs):
    if created:
        # Fetch questions from the selected standard
        questions = instance.standard.questions.all()
        # Create responses for each question
        for question in questions:
            AssessmentResponse.objects.create(
                assessment=instance,
                question=question,
                response_value=0  # Default response value (to be updated later)
            )

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils.timezone import now
from .models import UserActivityLog


# orm/signals.py
from django.db.models.signals import m2m_changed
from django.dispatch import receiver
from orm.models import Risk, ApprovalRequest, UserProfile
from django.utils import timezone

@receiver(m2m_changed, sender=Risk.owners.through)
def update_approval_requests(sender, instance, action, pk_set, **kwargs):
    """
    Automatically manage approval requests when owners are added or removed from a Risk.
    """
    risk = instance

    if action == "post_add":
        # Owners added: create approval requests for new owners
        for owner_pk in pk_set:
            owner = UserProfile.objects.get(pk=owner_pk)
            if not ApprovalRequest.objects.filter(risk=risk, user=owner).exists():
                ApprovalRequest.objects.create(
                    risk=risk,
                    user=owner,
                    status='pending',
                    due_date=timezone.now().date()
                )

    elif action == "post_remove":
        # Owners removed: delete approval requests for removed owners
        for owner_pk in pk_set:
            owner = UserProfile.objects.get(pk=owner_pk)
            ApprovalRequest.objects.filter(risk=risk, user=owner).delete()

    elif action == "post_clear":
        # All owners cleared: delete all approval requests for this risk
        ApprovalRequest.objects.filter(risk=risk).delete()
        
        
# orm/signals.py
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from orm.models import UserActivityLog
from orm.middleware import get_client_ip  # Reuse IP helper

@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    UserActivityLog.objects.create(
        user=user,
        activity_type="login",
        timestamp=timezone.now(),
        ip_address=get_client_ip(request),
        page_accessed=request.path,
        user_agent=request.META.get("HTTP_USER_AGENT", "Unknown"),
        session_key=request.session.session_key if hasattr(request, "session") else None,
        referrer=request.META.get("HTTP_REFERER", "Direct Access"),
    )

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    UserActivityLog.objects.create(
        user=user,
        activity_type="logout",
        timestamp=timezone.now(),
        ip_address=get_client_ip(request),
        page_accessed=request.path,
        user_agent=request.META.get("HTTP_USER_AGENT", "Unknown"),
        session_key=request.session.session_key if hasattr(request, "session") else None,
        referrer=request.META.get("HTTP_REFERER", "Direct Access"),
    )