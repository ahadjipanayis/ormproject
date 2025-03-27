from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from ckeditor.fields import RichTextField
from datetime import datetime, timedelta
from tinymce.models import HTMLField
from django.core.exceptions import ValidationError
import logging
from django.utils.html import format_html

from django.contrib import messages
import warnings

def save(self, *args, **kwargs):
    # Call the clean method for basic validation
    self.clean()

    # Save the object first to ensure it has a primary key
    super().save(*args, **kwargs)
    self.create_score_history()

    # Perform many-to-many validation after the object is saved
    residual_score = self.residual_likelihood * self.residual_impact
    targeted_score = self.targeted_likelihood * self.targeted_impact

    # Raise a warning if the condition is met
    if targeted_score < residual_score and not self.actions.exists():
        warnings.warn("Targeted score is lower than residual score, and no actions are associated.", UserWarning)

    # Save again if necessary (optional)
    super().save(*args, **kwargs)
from django.db import models
from django.contrib.auth.models import User

from django.db import models
from django.utils.timezone import now
from django.db import models
from django.utils.timezone import now

from django.db import models
from django.utils.timezone import now

class EmailLog(models.Model):
    recipient_email = models.EmailField()
    subject = models.CharField(max_length=255)
    body = models.TextField()
    sent_at = models.DateTimeField(default=now)
    response_received = models.BooleanField(default=False)
    response_at = models.DateTimeField(null=True, blank=True)
    user_selected_date = models.DateTimeField(null=True, blank=True)  # Store user-selected date
    location = models.CharField(max_length=255, null=True, blank=True)  # ✅ New location field

    def __str__(self):
        return f"Email to {self.recipient_email} - {self.subject}"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=200)
    portfolios = models.ManyToManyField('Portfolio', related_name='user_profiles')
    contact = models.CharField(max_length=100, blank=True, null=True)
    def __str__(self):
        return self.user.username

# class UserProfile2(models.Model):


class Portfolio(models.Model):
    name = models.CharField(max_length=1000)
    description = HTMLField()

    def __str__(self):
        return self.name

class Category(models.Model):
    name = models.CharField(max_length=1000)
    description = HTMLField()

    def __str__(self):
        return self.name

class Mitigation(models.Model):
    title = HTMLField()
    description = HTMLField()
    owners = models.ManyToManyField(UserProfile, related_name='owned_mitigations', blank=False)
    portfolio = models.ForeignKey(Portfolio, on_delete=models.SET_NULL, null=True, blank=False)
    effectiveness = models.CharField(max_length=50, choices=[
        ('not_tested', 'Not Tested'),
        ('ineffective', 'Ineffective'),
        ('partially_effective', 'Partially Effective'),
        ('effective', 'Effective')
    ], default='not_tested')
    updated_at = models.DateTimeField(auto_now=True)      # Automatically set on each update

    
    # def save(self, *args, **kwargs):
    #     # Save the mitigation instance first
    #     super().save(*args, **kwargs)

    #     # Check if the mitigation has at least one associated risk
    #     if not self.risks.exists():
    #         raise ValidationError("Each mitigation must be associated with at least one risk.")
    
    def __str__(self):
        return self.title


from tinymce.models import HTMLField
from django.db import models

from django.db.models.signals import m2m_changed
from django.dispatch import receiver



from django.db import models
from tinymce.models import HTMLField  # Assuming you're using TinyMCE for rich text

class Opportunity(models.Model):
    title = models.CharField(max_length=1000)
    description = models.CharField(max_length=5000, blank=True)
    owner = models.ForeignKey(
        'UserProfile', 
        on_delete=models.CASCADE, 
        related_name='owned_opportunities', 
        null=True, 
        blank=True
    )
    portfolio = models.ForeignKey(
        'Portfolio', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='opportunities'  # Added for reverse lookup
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class Threat(models.Model):
    title = models.CharField(max_length=1000)
    description = models.CharField(max_length=5000, blank=True)
    owner = models.ForeignKey(
        'UserProfile', 
        on_delete=models.CASCADE, 
        related_name='owned_threats', 
        null=True, 
        blank=True
    )
    portfolio = models.ForeignKey(
        'Portfolio', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='threats'  # Added for reverse lookup
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class Action(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed')
    ]
    title = models.CharField(max_length=1000)

    description = HTMLField()
    owner = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='owned_actions', null=True, blank=True)
    portfolio = models.ForeignKey(Portfolio, on_delete=models.SET_NULL, null=True)
    performer = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='performed_actions')
    deadline = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')  # New field for status
    updated_at = models.DateTimeField(auto_now=True)      # Automatically set on each update

    def __str__(self):
        return self.title

class Indicator(models.Model):
    FREQUENCY_CHOICES = [
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('semiannual', 'Semi-Annual'),
        ('annual', 'Annual'),
    ]

    title = models.CharField(max_length=100)
    description = HTMLField()
    field = models.CharField(max_length=100, null=True, blank=True)
    repetition_frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES, null=True, blank=True)
    current_value = models.FloatField()
    reporting_date = models.DateField()
    next_reporting_date = models.DateField(blank=True, null=True)
    owner = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='owned_indicators',blank=True, null=True)
    portfolio = models.ForeignKey(Portfolio, on_delete=models.SET_NULL, null=True)

    def save(self, *args, **kwargs):
        if not self.next_reporting_date:
            self.next_reporting_date = self.calculate_next_reporting_date()
        super().save(*args, **kwargs)
        self.create_value_history()

    def calculate_next_reporting_date(self):
        if self.repetition_frequency == 'weekly':
            return self.reporting_date + timedelta(weeks=1)
        elif self.repetition_frequency == 'monthly':
            return self.reporting_date + timedelta(days=30)
        elif self.repetition_frequency == 'quarterly':
            return self.reporting_date + timedelta(days=90)
        elif self.repetition_frequency == 'semiannual':
            return self.reporting_date + timedelta(days=182)
        elif self.repetition_frequency == 'annual':
            return self.reporting_date + timedelta(days=365)
        return self.reporting_date

    def create_value_history(self):
        IndicatorValueHistory.objects.create(
            indicator=self,
            value=self.current_value,
            timestamp=self.reporting_date
        )

    def __str__(self):
        return self.title

class IndicatorValueHistory(models.Model):
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE, related_name='value_history')
    value = models.FloatField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.indicator.title} - {self.value} at {self.timestamp}"

class Event(models.Model):
    title = models.CharField(max_length=100)
    description = HTMLField()
    date = models.DateField(null=True, blank=True)
    owner = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='owned_events', null=True, blank=True)
    portfolio = models.ForeignKey(Portfolio, on_delete=models.SET_NULL, null=True, blank=True)
    reporter = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='reported_events')

    def save(self, *args, **kwargs):
        if isinstance(self.date, datetime):
            self.date = self.date.date()
        elif isinstance(self.date, str):
            self.date = datetime.fromisoformat(self.date).date()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title


# In models.py (in any app, let's say 'myapp')
from django.db import models

class ReportAndDashboardPermissions(models.Model):
    class Meta:
        permissions = [
            ("can_view_reports", "Can view reports"),
            ("can_view_dashboard", "Can view dashboard"),
        ]

       

 # =====================

from django.db import models

class ITThreat(models.Model):
    # Threat categories from ISO/IEC 27005:2022(E)
    THREAT_CATEGORY_CHOICES = [
        ('physical', 'Physical Threats'),
        ('natural', 'Natural Threats'),
        ('infrastructure', 'Infrastructure Failures'),
        ('technical', 'Technical Failures'),
        ('human', 'Human Actions'),
        ('compromise', 'Compromise of Functions or Services'),
        ('organizational', 'Organizational Threats'),
    ]

    code = models.CharField(
        max_length=10,
        unique=True,
        help_text="Threat code (e.g., TP01)"
    )
    description = models.TextField(help_text="Detailed description of the threat")
    risk_sources = models.CharField(
        max_length=20,
        help_text="Comma-separated risk source types (e.g., 'A, D, E')"
    )
    category = models.CharField(
        max_length=20,
        choices=THREAT_CATEGORY_CHOICES,
        help_text="Category of the threat (ISO/IEC 27005:2022)"
    )

    def __str__(self):
        return f"{self.code} - {self.description[:50]}"
class Vulnerability(models.Model):
    # Vulnerability categories from ISO/IEC 27005:2022(E)
    VULNERABILITY_CATEGORY_CHOICES = [
        ('hardware', 'Hardware'),
        ('software', 'Software'),
        ('network', 'Network'),
        ('personnel', 'Personnel'),
        ('site', 'Site'),
        ('organization', 'Organization'),
    ]

    code = models.CharField(
        max_length=10,
        unique=True,
        help_text="Vulnerability code (e.g., VH01)"
    )
    description = models.TextField(help_text="Detailed description of the vulnerability")
    category = models.CharField(
        max_length=20,
        choices=VULNERABILITY_CATEGORY_CHOICES,
        help_text="Category of the vulnerability"
    )

    # Linking vulnerabilities to IT threats
    threats = models.ManyToManyField(
        ITThreat,
        related_name='vulnerabilities',
        blank=True,
        help_text="IT threats that can exploit this vulnerability"
    )

    def __str__(self):
        return f"{self.code} - {self.get_category_display()}"

class ITAsset(models.Model):
    ASSET_TYPE_CHOICES = [
        ('hardware', 'Hardware'),
        ('software', 'Software'),
        ('network', 'Network Component'),
        ('data', 'Data'),
        ('service', 'Service'),
        ('other', 'Other'),
    ]
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('decommissioned', 'Decommissioned'),
    ]
    CIA_CHOICES = [
        (1, 'Low'),
        (2, 'Medium'),
        (3, 'High'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    asset_type = models.CharField(max_length=50, choices=ASSET_TYPE_CHOICES)
    location = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    criticality = models.PositiveIntegerField(default=1)

    # CIA Ratings
    confidentiality = models.PositiveSmallIntegerField(choices=CIA_CHOICES, default=1)
    integrity = models.PositiveSmallIntegerField(choices=CIA_CHOICES, default=1)
    availability = models.PositiveSmallIntegerField(choices=CIA_CHOICES, default=1)

    # ✅ Adding the missing ForeignKey for Portfolio
    portfolio = models.ForeignKey(
        'Portfolio',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assets',
        help_text="Portfolio associated with this IT asset"
    )

    # ✅ Adding the missing ManyToManyField for Owners
    owners = models.ManyToManyField(
        'UserProfile',
        related_name='owned_assets',
        blank=True,
        help_text="Users who own this IT asset"
    )

    # Linking IT Assets to Vulnerabilities and IT Threats
    vulnerabilities = models.ManyToManyField(
        Vulnerability,
        related_name='assets',
        blank=True,
        help_text="Vulnerabilities affecting this IT asset"
    )
    threats = models.ManyToManyField(
        ITThreat,
        related_name='assets',
        blank=True,
        help_text="IT threats that this IT asset is exposed to"
    )

    date_added = models.DateField(auto_now_add=True)
    last_updated = models.DateField(auto_now=True)

    def __str__(self):
        return self.name

# ========================================================================================================


class Risk(models.Model):
    last_assessed_by = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='last_assessed_risks')
    last_assessed_date = models.DateTimeField(blank=True, null=True)
    next_assessment_date = models.DateTimeField(blank=True, null=True)
    
    last_approval_date = models.DateTimeField(null=True, blank=True)  # New field to track the last approval date
    next_approval_date = models.DateTimeField(blank=True, null=True)
    last_approved_by = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='last_appoved_risks')
    updated_at = models.DateTimeField(auto_now=True)      # Automatically set on each update

    @property
    def reminder_3_months_assessment(self):
        if self.next_assessment_date:
            return self.next_assessment_date - timedelta(days=90)
        return None

    @property
    def reminder_1_month_assessment(self):
        if self.next_assessment_date:
            return self.next_assessment_date - timedelta(days=30)
        return None

    @property
    def reminder_3_months_approval(self):
        if self.next_approval_date:
            return self.next_approval_date - timedelta(days=90)
        return None

    @property
    def reminder_1_month_approval(self):
        if self.next_approval_date:
            return self.next_approval_date - timedelta(days=30)
        return None# existing fields...

    def update_last_assessed(self, user_profile):
        self.last_assessed_by = user_profile
        self.last_assessed_date = timezone.now()
        self.save()


    SCORE_CHOICES = [(i, str(i)) for i in range(1, 6)]
    TREATMENT_CHOICES = [
        ('acceptance', 'Acceptance'),
        ('mitigation', 'Mitigation'),
        ('transfer', 'Transfer'),
        ('avoidance', 'Avoidance')
    ]
    APPROVAL_CYCLE_CHOICES = [
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('biannual', 'Biannual'),  # Default option (6 months)
    ]

    approval_cycle = models.CharField(
        max_length=10,
        choices=APPROVAL_CYCLE_CHOICES,
        default='biannual',
        verbose_name="Approval Cycle"
    )

    def get_approval_cycle_timedelta(self):
        """
        Helper method to get the timedelta based on the approval cycle.
        """
        if self.approval_cycle == 'weekly':
            return timedelta(weeks=1)
        elif self.approval_cycle == 'monthly':
            return timedelta(weeks=4)  # Approximation for months
        elif self.approval_cycle == 'quarterly':
            return timedelta(weeks=12)  # Approximation for quarters
        elif self.approval_cycle == 'biannual':
            return timedelta(weeks=26)  # Approximation for biannual (6 months)
        elif self.approval_cycle == 'annual':
            return timedelta(weeks=52)  # Approximation for annual
        return timedelta(weeks=26)  # Default to biannual (6 months)

    title = HTMLField()
    description = HTMLField()
    owners = models.ManyToManyField(UserProfile, related_name='owned_risks')
    mitigations = models.ManyToManyField(Mitigation, related_name='risks', blank=False)
    actions = models.ManyToManyField(Action, related_name='risks', blank=True)
    indicators = models.ManyToManyField(Indicator, related_name='risks', blank=True)
    events = models.ManyToManyField(Event, related_name='risks', blank=True)
    procedures = models.ManyToManyField('Procedure', related_name='risks', blank=True)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    portfolio = models.ForeignKey(Portfolio, on_delete=models.SET_NULL, null=True)
    inherent_likelihood = models.IntegerField(choices=SCORE_CHOICES, null=True, blank=True,default=5)
    inherent_impact = models.IntegerField(choices=SCORE_CHOICES, null=True, blank=True,default=5)
    residual_likelihood = models.IntegerField(choices=SCORE_CHOICES, null=True, blank=True,default=3)
    residual_impact = models.IntegerField(choices=SCORE_CHOICES, null=True, blank=True,default=3)
    targeted_likelihood = models.IntegerField(choices=SCORE_CHOICES, null=True, blank=True,default=1)
    targeted_impact = models.IntegerField(choices=SCORE_CHOICES, null=True, blank=True,default=1)
    treatment_type = models.CharField(max_length=50, choices=TREATMENT_CHOICES, null=True, blank=True,default='mitigation')
    opportunities = models.ManyToManyField(Opportunity, related_name='risks', blank=True)
    threats = models.ManyToManyField(Threat,related_name='risks',blank=True)

    
    
    
    related_assets = models.ManyToManyField(
        'ITAsset',
        related_name='risks',
        blank=True,
        help_text="IT assets impacted by this risk."
    )
    
    
    def inherent_score(self):
        if self.inherent_likelihood is not None and self.inherent_impact is not None:
            return self.inherent_likelihood * self.inherent_impact
        return None

    def residual_score(self):
        if self.residual_likelihood is not None and self.residual_impact is not None:
            return self.residual_likelihood * self.residual_impact
        return None

    def targeted_score(self):
        if self.targeted_likelihood is not None and self.targeted_impact is not None:
            return self.targeted_likelihood * self.targeted_impact
        return None

    def get_traffic_light(self, score):
        if score is None:
            return 'N/A', '#FFFFFF'  # White for not applicable
        if score > 12:
            return 'HIGH', '#FF0000'
        elif score > 6:
            return 'MEDIUM', '#FFA500'
        else:
            return 'LOW', '#00FF00'

    def inherent_traffic_light(self):
        return self.get_traffic_light(self.inherent_score())

    def residual_traffic_light(self):
        return self.get_traffic_light(self.residual_score())

    def targeted_traffic_light(self):
        return self.get_traffic_light(self.targeted_score())

    


    def __str__(self):
        return self.title

    def inherent_score_display(self):
        score = self.inherent_score()
        traffic_light, color = self.inherent_traffic_light()
        return format_html("<span style='color:{};'>{} x {} = {} ({})</span>", color, self.inherent_likelihood, self.inherent_impact, score, traffic_light) if score else "N/A"
    inherent_score_display.short_description = 'Inherent Score'
    inherent_score_display.allow_tags = True

    def residual_score_display(self):
        score = self.residual_score()
        traffic_light, color = self.residual_traffic_light()
        return format_html("<span style='color:{};'>{} x {} = {} ({})</span>", color, self.residual_likelihood, self.residual_impact, score, traffic_light) if score else "N/A"
    residual_score_display.short_description = 'Residual Score'
    residual_score_display.allow_tags = True

    def targeted_score_display(self):
        score = self.targeted_score()
        traffic_light, color = self.targeted_traffic_light()
        return format_html("<span style='color:{};'>{} x {} = {} ({})</span>", color, self.targeted_likelihood, self.targeted_impact, score, traffic_light) if score else "N/A"
    targeted_score_display.short_description = 'Targeted Score'
    targeted_score_display.allow_tags = True

    def mitigations_list(self):
        return ", ".join(mitigation.title for mitigation in self.mitigations.all())
    mitigations_list.short_description = 'Mitigations'

    def last_approval_info(self):
        description = bleach.clean(description, tags=['p', 'strong', 'em', 'a', 'ul', 'li'])

        latest_approval = self.approval_requests.filter(status='approved').order_by('-response_date').first()
        if latest_approval:
            return f"{latest_approval.user.user.username} on {latest_approval.response_date.strftime('%Y-%m-%d')}"
        return "No approvals"
    last_approval_info.short_description = 'Last Approval Info'

    def approval_flag_color(self):
        latest_approval = self.approval_requests.filter(status='approved').order_by('-response_date').first()
        if latest_approval:
            if latest_approval.response_date >= timezone.now() - timedelta(days=180):
                return '#00FF00'  # Green if within six months
            else:
                return '#FF0000'  # Red if older than six months
        return '#FF0000'  # White if no approvals

    class Meta:
        permissions = [
            ("view_risk_report", "Can view the risk report"),
        ]

    from django.core.exceptions import ValidationError


    from django.utils import timezone
    from django.core.exceptions import ValidationError
    import logging
    import warnings
    import requests
   
   

    def clean(self):
        # Calculate scores
        inherent_score = self.inherent_likelihood * self.inherent_impact
        residual_score = self.residual_likelihood * self.residual_impact
        targeted_score = self.targeted_likelihood * self.targeted_impact

        # Validate residual score <= inherent score
        if residual_score > inherent_score:
            raise ValidationError("Residual score must be equal to or lower than the inherent score.")

        # Validate targeted score <= residual score
        if targeted_score > residual_score:
            raise ValidationError("Targeted score must be equal to or lower than the residual score.")

    def create_score_history(self):
        logger = logging.getLogger(__name__)
        
        logger.info("Entering create_score_history")  # Informative logging

        # Calculate current scores
        inherent = self.inherent_score()
        residual = self.residual_score()
        targeted = self.targeted_score()

        logger.info(f"Inherent score: {inherent}, Residual score: {residual}, Targeted score: {targeted}")

        # Create history records for scores
        RiskScoreHistory.objects.create(risk=self, score_type='inherent', score=inherent, timestamp=timezone.now())
        logger.info("Inherent score history created")
        RiskScoreHistory.objects.create(risk=self, score_type='residual', score=residual, timestamp=timezone.now())
        logger.info("Residual score history created")
        RiskScoreHistory.objects.create(risk=self, score_type='targeted', score=targeted, timestamp=timezone.now())
        logger.info("Targeted score history created")

    def save(self, *args, **kwargs):
    # Call the clean method for validation
        self.clean()

        # Save the object first
        super().save(*args, **kwargs)
        self.create_score_history()

        # Calculate scores for post-save checks
        residual_score = self.residual_likelihood * self.residual_impact
        targeted_score = self.targeted_likelihood * self.targeted_impact

        

        # Save again if needed (optional)
        super().save(*args, **kwargs)

# orm/models.py
from django.db import models
from django.contrib.auth.models import User

class KYCVerification(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('manual_review', 'Manual Review'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    id_photo = models.FileField(upload_to='kyc/id_photos/', blank=False)  # Changed to FileField
    selfie = models.ImageField(upload_to='kyc/selfies/', blank=False)     # Selfie stays as ImageField
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    similarity_score = models.FloatField(null=True, blank=True)

    def __str__(self):
        return f"KYC for {self.user.username} - {self.status}"
from django.db import models

class NetworkScan(models.Model):
    ip_address = models.GenericIPAddressField()
    ports_open = models.TextField()
    scan_date = models.DateTimeField(auto_now_add=True)



class RiskScoreHistory(models.Model):
    risk = models.ForeignKey(Risk, on_delete=models.CASCADE, related_name='score_history')
    score_type = models.CharField(max_length=50)
    score = models.IntegerField()
    timestamp = models.DateTimeField(default=timezone.now)
    # saved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='risk_score_histories')
    def __str__(self):
        return f"{self.risk.title} - {self.score_type} - {self.score} at {self.timestamp}"

class ApprovalRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    rational = HTMLField(blank=True)

    risk = models.ForeignKey(Risk, on_delete=models.CASCADE, related_name='approval_requests')
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES)
    response_date = models.DateTimeField(blank=True, null=True)
    due_date = models.DateField(blank=True, null=True)  # New due_date field

    def __str__(self):
        return f"ApprovalRequest for {self.risk.title} by {self.user.user.username}"

    def approve(self):
        self.status = 'approved'
        self.response_date = timezone.now()
        self.save()

    def reject(self):
        self.status = 'rejected'
        self.response_date = timezone.now()
        self.save()

class Procedure(models.Model):
    code= models.CharField(max_length=100)
    revision= models.CharField(max_length=100)
    title = models.CharField(max_length=100)
    description = HTMLField()
    url = models.URLField(max_length=200, blank=True, null=True)
    owner = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='owned_procedures')
    department = models.CharField(max_length=100)
    portfolio = models.ForeignKey(Portfolio, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.title

# models.py

from django.utils import timezone

class RiskAssessment(models.Model):
    title = models.CharField(max_length=255)
    description = HTMLField()
    risks = models.ManyToManyField(Risk, related_name='assessments')
    assessor = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, related_name='assessments')
    created_by = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, null=True, related_name='created_assessments')
    created_at = models.DateTimeField(auto_now_add=True)
    assessed_at = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('completed', 'Completed')], default='pending')

    def mark_assessed(self):
        self.status = 'completed'
        self.assessed_at = timezone.now()
        self.save()

        # Create the history entry
        history = AssessmentHistory.objects.create(
            risk_assessment=self,
            assessor=self.assessor,
            date=timezone.now()
        )

        # Create snapshots of each risk at this time
        for risk in self.risks.all():
            RiskSnapshot.objects.create(
                title=risk.title[:100],  # Truncate the title to fit within max_length
                description=risk.description,
                inherent_score=risk.inherent_score(),
                residual_score=risk.residual_score(),
                targeted_score=risk.targeted_score(),
                assessment_history=history
            )



class RiskSnapshot(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    inherent_score = models.IntegerField()
    residual_score = models.IntegerField()
    targeted_score = models.IntegerField()
    assessment_history = models.ForeignKey('AssessmentHistory', related_name='risk_snapshots', on_delete=models.CASCADE)

    def __str__(self):
        return f"Snapshot of {self.title} during assessment"

class AssessmentHistory(models.Model):
    risk_assessment = models.ForeignKey('RiskAssessment', on_delete=models.CASCADE, related_name='assessment_history')
    date = models.DateTimeField(default=timezone.now)
    assessor = models.ForeignKey('UserProfile', on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"Assessment on {self.date.strftime('%Y-%m-%d')} by {self.assessor.user.username}"
    


from django.db import models

class SMTPSetting(models.Model):
    smtp_server = models.CharField(max_length=255)
    smtp_port = models.IntegerField()
    smtp_username = models.CharField(max_length=255)
    smtp_password = models.CharField(max_length=255)
    sender_email = models.EmailField()
    admin_email = models.EmailField()  # Admin email to receive notifications

    def __str__(self):
        return f"{self.smtp_server} ({self.sender_email})"  # Make sure to use sender_email, not sender_name


from django.db import models

class BpmnDiagram(models.Model):
    name = models.CharField(max_length=255, unique=True)
    xml_content = models.TextField()  # Store the BPMN XML
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

class StandardControl(models.Model):
    clause= models.CharField(max_length=100)
    standard_name = models.CharField(max_length=1000)  # e.g., "ISO 27002:2022"
    control_id = models.CharField(max_length=10)      # e.g., "5.1", "6.2"
    control_name = models.CharField(max_length=255)   # Name of the control
    description = models.TextField()                 # Full description of the control
    globally_applicable = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.standard_name} - {self.control_id}: {self.control_name}"

class PortfolioControlStatus(models.Model):
    portfolio = models.ForeignKey('Portfolio', on_delete=models.CASCADE, related_name='control_statuses')
    standard_control = models.ForeignKey(StandardControl, on_delete=models.CASCADE, related_name='portfolio_statuses')
    applicable = models.BooleanField(default=True)  # Whether the control is applicable to the portfolio
    rationale = models.TextField(blank=True, null=True)  # Explanation for why it's not applicable or missing

    class Meta:
        unique_together = ('portfolio', 'standard_control')  # Ensure uniqueness per portfolio and control

    def __str__(self):
        return f"{self.portfolio.name} - {self.standard_control.control_id}: {self.rationale or 'N/A'}"


# -------------------------------------------------------------------


from django.db import models
from django.utils.timezone import now

class KYCStandard(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class KYCQuestion(models.Model):
    standard = models.ForeignKey(KYCStandard, on_delete=models.CASCADE, related_name='questions')
    question_text = models.TextField()
    weight = models.FloatField(help_text="Weight of this question in scoring")
    score_1_description = models.TextField(default="Very Low", help_text="Description for score 1")
    score_2_description = models.TextField(default="Low", help_text="Description for score 2")
    score_3_description = models.TextField(default="Medium", help_text="Description for score 3")
    score_4_description = models.TextField(default="High", help_text="Description for score 4")
    score_5_description = models.TextField(default="Very High", help_text="Description for score 5")

    def get_score_choices(self):
        return [
            (1, f"1 - {self.score_1_description}"),
            (2, f"2 - {self.score_2_description}"),
            (3, f"3 - {self.score_3_description}"),
            (4, f"4 - {self.score_4_description}"),
            (5, f"5 - {self.score_5_description}"),
        ]

    def __str__(self):
        return self.question_text


from django.db import models
from django_countries.fields import CountryField

from django.db import models
from django_countries.fields import CountryField


from django_countries.fields import CountryField
from django.db import models


class Counterparty(models.Model):
    ENTITY_TYPES = [
        ('LEGAL_ENTITY', 'Legal Entity'),
        ('INDIVIDUAL', 'Individual'),
    ]
    COUNTERPARTY_TYPES = [
        ('CLIENT', 'Client'),
        ('SUPPLIER', 'Supplier'),
    ]

    name = models.CharField(max_length=255)
    registration_number = models.CharField(max_length=100, unique=True)
    country = CountryField()
    contact_email = models.EmailField(blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    counterparty_type = models.CharField(
        max_length=10,
        choices=COUNTERPARTY_TYPES,
        default='CLIENT',
    )
    entity_type = models.CharField(
        max_length=15,
        choices=ENTITY_TYPES,
        default='LEGAL_ENTITY',
    )
    
    # Address fields
    street_address = models.CharField(max_length=255, blank=True, null=True, help_text="Street and house number")
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    
    # Sanctions-related fields
    is_sanctioned = models.BooleanField(default=False, help_text="Indicates if the counterparty is flagged as sanctioned")
    sanction_source = models.CharField(max_length=255, blank=True, null=True, help_text="The source of the sanction (e.g., OFAC, UNSC, EU)")
    sanction_created_at = models.DateField(blank=True, null=True, help_text="Date the sanction was applied or recorded")

    date_added = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def latest_assessment(self):
        return self.duediligenceassessment_set.order_by('-assessment_date').first()

    def __str__(self):
        return self.name


class DueDiligenceAssessment(models.Model):
    counterparty = models.ForeignKey(Counterparty, on_delete=models.CASCADE)
    standard = models.ForeignKey(KYCStandard, on_delete=models.CASCADE)
    assessment_date = models.DateTimeField(auto_now_add=True)
    last_saved = models.DateTimeField(auto_now=True)
    performed_by = models.ForeignKey('UserProfile', on_delete=models.SET_NULL, null=True, blank=True)
    overall_score = models.FloatField(default=0.0, editable=False)
    classification = models.CharField(
        max_length=50,
        choices=[
            ('Low Risk', 'Low Risk'),
            ('Medium Risk', 'Medium Risk'),
            ('High Risk', 'High Risk'),
        ],
        blank=True,
        null=True,
    )
    status = models.CharField(
        max_length=50,
        choices=[
            ('Pending', 'Pending'),
            ('Completed', 'Completed'),
        ],
        default='Pending',
    )

    def calculate_overall_score(self):
        responses = self.responses.all()
        total_score = sum(response.response_value * response.question.weight for response in responses)
        self.overall_score = total_score

        if total_score <= 20:
            self.classification = 'Low Risk'
        elif total_score <= 50:
            self.classification = 'Medium Risk'
        else:
            self.classification = 'High Risk'

        self.save()

    def __str__(self):
        return f"Assessment for {self.counterparty.name} - {self.standard.name}"


class AssessmentResponse(models.Model):
    assessment = models.ForeignKey(DueDiligenceAssessment, on_delete=models.CASCADE, related_name='responses')
    question = models.ForeignKey(KYCQuestion, on_delete=models.CASCADE)
    response_value = models.IntegerField(help_text="Select a response score")


class AppLicense(models.Model):
    expiration_date = models.DateField()
    is_active = models.BooleanField(default=True)

    def has_expired(self):
        return now().date() > self.expiration_date

    def __str__(self):
        return f"License active: {self.is_active}, Expires: {self.expiration_date}"

from django.db import models

class SanctionList(models.Model):
    name = models.CharField(max_length=255)
    ref_id = models.CharField(max_length=50, unique=True)
    source_url = models.URLField()
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class ReferenceValue(models.Model):
    ref_id = models.CharField(max_length=50)
    type = models.CharField(max_length=255)
    value = models.TextField()

    def __str__(self):
        return f"{self.type}: {self.value}"


class CounterpartySanctionCheck(models.Model):
    counterparty = models.ForeignKey('Counterparty', on_delete=models.CASCADE, related_name='sanction_checks')
    sanction_list = models.ForeignKey(SanctionList, on_delete=models.CASCADE)
    status = models.CharField(max_length=50, choices=[('Not Found', 'Not Found'), ('Listed', 'Listed')], default='Not Found')
    check_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.counterparty.name} - {self.sanction_list.name} ({self.status})"







# -------------------------------------------------------------------

from django.db import models

class LikelihoodImpactDescription(models.Model):
    CATEGORY_CHOICES = [
        ('likelihood', 'Likelihood'),
        ('impact', 'Impact'),
    ]
    category = models.CharField(
        max_length=10,
        choices=CATEGORY_CHOICES,
        help_text="Specify whether this description is for likelihood or impact."
    )
    score = models.IntegerField(
        choices=[(i, str(i)) for i in range(1, 6)],
        help_text="Score value (1-5)."
    )
    description = models.TextField(help_text="Description for the score.")

    class Meta:
        unique_together = ('category', 'score')  # Ensure unique descriptions per score and category
        verbose_name = "Likelihood/Impact Description"
        verbose_name_plural = "Likelihood/Impact Descriptions"

    def __str__(self):
        return f"{self.get_category_display()} Score {self.score}: {self.description}"



from django.db import models
from django.contrib.auth.models import User

from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now

class UserActivityLog(models.Model):
    ACTIVITY_CHOICES = [
        ("login", "Login"),
        ("logout", "Logout"),
        ("page_view", "Page View"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="activities")
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    page_accessed = models.CharField(max_length=300, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)
    referrer = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} {self.activity_type} at {self.timestamp}"
    
from django.db import models
from django.contrib.auth.models import User

class Folder(models.Model):
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    created_at = models.DateTimeField(auto_now_add=True)

    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='subfolders')

    def __str__(self):
        return self.name


class Document(models.Model):
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to="documents/")
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True, null=True)
    portfolio = models.ForeignKey(Portfolio, on_delete=models.CASCADE)
    folder = models.ForeignKey(Folder, null=True, blank=True, on_delete=models.CASCADE)  # 🔹 New folder field

    def __str__(self):
        return self.title

class DocumentVersion(models.Model):
    document = models.ForeignKey(Document, related_name="versions", on_delete=models.CASCADE)
    file = models.FileField(upload_to="documents/versions/")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    version_number = models.IntegerField()

    def __str__(self):
        return f"Version {self.version_number} of {self.document.title}"

# models.py
from django.db import models
import math

class Loan(models.Model):
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, help_text="Annual interest rate in %")
    period = models.PositiveIntegerField(help_text="Loan duration in months")

    def calculate_installment(self):
        """Calculate monthly installment using the annuity formula."""
        P = float(self.amount)
        r = float(self.interest_rate) / 100 / 12  # Monthly interest rate
        n = self.period

        if r == 0:
            return P / n
        
        installment = (P * r) / (1 - (1 + r) ** -n)
        return round(installment, 2)

    def generate_schedule(self):
        """Generate a detailed payment schedule."""
        P = float(self.amount)
        r = float(self.interest_rate) / 100 / 12  # Monthly interest rate
        n = self.period
        monthly_payment = self.calculate_installment()

        schedule = []
        remaining_balance = P

        for month in range(1, n + 1):
            interest_payment = remaining_balance * r
            capital_payment = monthly_payment - interest_payment
            remaining_balance -= capital_payment

            # Handle final payment adjustment
            if month == n and remaining_balance > 0:
                capital_payment += remaining_balance
                monthly_payment = capital_payment + interest_payment
                remaining_balance = 0

            schedule.append({
                'month': month,
                'payment': round(monthly_payment, 2),
                'interest': round(interest_payment, 2),
                'capital': round(capital_payment, 2),
                'balance': max(round(remaining_balance, 2), 0),
            })

        return schedule

    def __str__(self):
        return f"Loan: {self.amount}€ at {self.interest_rate}% for {self.period} months"
    
    
    