from django import forms
from .models import Event

from django import forms
from .models import Event, Risk

class EventForm(forms.ModelForm):
    risks = forms.ModelMultipleChoiceField(
        queryset=Risk.objects.all(),  # Fetch all risks
        widget=forms.SelectMultiple(attrs={'class': 'form-control'}),
        required=False,  # Optional: Set to True if risks must be selected
        label="Related Risks"
    )

    class Meta:
        model = Event
        fields = ['title', 'description', 'date', 'owner', 'portfolio', 'reporter', 'risks']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control'}),
            'date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'owner': forms.Select(attrs={'class': 'form-select'}),
            'portfolio': forms.Select(attrs={'class': 'form-select'}),
            'reporter': forms.Select(attrs={'class': 'form-select'}),
        }

from django import forms
from django.utils.html import strip_tags
from .models import Risk, Mitigation, Portfolio, UserProfile

from django import forms
from django.utils.html import strip_tags
from .models import Risk

from django import forms
from django.utils.html import strip_tags
from .models import Risk

from django import forms
from django.utils.html import strip_tags
from .models import Risk

from django import forms
from django.core.exceptions import ValidationError
from .models import Risk
from django import forms
from .models import ITAsset

from django import forms
from .models import ITAsset

from django import forms
from .models import ITAsset

from django import forms
from .models import ITAsset

from django import forms
from .models import ITAsset

class ITAssetForm(forms.ModelForm):
    class Meta:
        model = ITAsset
        fields = [
            'name', 'description', 'asset_type', 'location', 'status', 'criticality',
            'confidentiality', 'integrity', 'availability', 'portfolio'
        ]

from django import forms
from .models import Portfolio
from django import forms
from .models import ApprovalRequest

class ApprovalRequestForm(forms.ModelForm):
    class Meta:
        model = ApprovalRequest
        fields = ['rational', 'risk', 'user', 'status', 'due_date']
        widgets = {
            'rational': forms.Textarea(attrs={'rows': 3}),
            'due_date': forms.DateInput(attrs={'type': 'date'}),
        }
from django import forms
from .models import Indicator  # Import the Indicator model

from django import forms
from .models import Indicator

class IndicatorForm(forms.ModelForm):
    class Meta:
        model = Indicator  # Use the Indicator model here
        fields = [
            'title', 'description', 'field', 'repetition_frequency',
            'current_value', 'reporting_date', 'owner', 'portfolio'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3, 'id': 'id_description', 'class': 'form-control full-width'}),
            'title': forms.TextInput(attrs={'class': 'form-control full-width'}),
            'reporting_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'repetition_frequency': forms.Select(attrs={'class': 'form-control'}),
            # Add more widgets for other fields as needed
        }



from django import forms
from .models import Threat


from django import forms
from .models import Threat

class ThreatForm(forms.ModelForm):
    class Meta:
        model = Threat
        fields = ['title', 'description', 'owner', 'portfolio']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Enter threat title'}),
            'description': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter description'}),
        }

from django import forms
from .models import Procedure
from django import forms
from .models import Procedure

class ProcedureForm(forms.ModelForm):
    class Meta:
        model = Procedure
        fields = ['code', 'title', 'revision', 'description', 'url', 'owner', 'department', 'portfolio']
        widgets = {
            'code': forms.TextInput(attrs={'class': 'form-control'}),
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'revision': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'url': forms.URLInput(attrs={'class': 'form-control'}),
            'owner': forms.Select(attrs={'class': 'form-select'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
            'portfolio': forms.Select(attrs={'class': 'form-select'}),
        }

from django import forms
from django.utils.html import strip_tags
from html import unescape
from .models import Portfolio

class PortfolioForm(forms.ModelForm):
    class Meta:
        model = Portfolio
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'Enter portfolio name'}),
            'description': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter portfolio description'}),
        }

    def clean_name(self):
        name = self.cleaned_data.get('name', '')
        return unescape(strip_tags(name))  # Remove HTML tags and decode entities

    def clean_description(self):
        description = self.cleaned_data.get('description', '')
        return unescape(strip_tags(description))  # Remove HTML tags and decode entities




from django import forms
from .models import Opportunity


from django import forms
from .models import Category

class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'Enter category name'}),
            'description': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter description'}),
        }

from django import forms
from .models import Opportunity


from django import forms
from .models import Opportunity

from django import forms
from .models import Opportunity

from django import forms
from .models import Opportunity

from django import forms
from .models import Opportunity

from django import forms
from django.utils.translation import gettext_lazy as _

class OpportunityForm(forms.ModelForm):
    class Meta:
        model = Opportunity  # Replace with your actual model
        fields = ['title', 'description']
        labels = {
            'title': _("Title"),
            'description': _("Description"),
        }

# forms.py
from django.contrib.auth.forms import PasswordResetForm
from django.template.loader import render_to_string
# from orm.tasks import send_email  # Import your custom send_email function

from django.contrib.auth.forms import PasswordResetForm
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from orm.models import SMTPSetting



from django import forms
from django.contrib.auth.forms import PasswordResetForm
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.html import strip_tags
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
from orm.models import SMTPSetting  # Adjust the import based on your app structure


def send_email(subject, message, recipient_list, bcc=None):
    smtp_settings = SMTPSetting.objects.first()

    if not smtp_settings:
        logging.error("SMTP settings are not configured.")
        return
    
    msg = MIMEMultipart()
    msg['From'] = smtp_settings.sender_email
    msg['To'] = ', '.join(recipient_list)
    msg['Subject'] = subject
    
    # Add BCC recipients
    if bcc:
        msg['Bcc'] = ', '.join(bcc)
        recipient_list += bcc  # Ensure BCC recipients receive the email

    # Attach the HTML message
    msg.attach(MIMEText(message, 'html'))

    # SMTP server configuration
    smtp_host = smtp_settings.smtp_server
    smtp_port = smtp_settings.smtp_port
    smtp_user = smtp_settings.smtp_username
    smtp_password = smtp_settings.smtp_password

    # Encode username and password in Base64
    encoded_user = base64.b64encode(smtp_user.encode()).decode()
    encoded_password = base64.b64encode(smtp_password.encode()).decode()

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(1)  # Enable debug output
        server.ehlo()
        server.starttls()  # Secure the connection
        server.ehlo()

        # Perform AUTH LOGIN manually
        server.docmd("AUTH LOGIN", encoded_user)
        server.docmd(encoded_password)

        # Send the email
        server.sendmail(msg['From'], recipient_list, msg.as_string())
        server.quit()
        logging.info(f"Email sent successfully to {', '.join(recipient_list)}")
    except smtplib.SMTPException as e:
        logging.error(f"Failed to send email: {e}")
        raise

# Custom Password Reset Form
class CustomPasswordResetForm(PasswordResetForm):
    def send_mail(self, subject_template_name, email_template_name, context, from_email, to_email, html_email_template_name=None):
        # Render the email subject and body
        subject = render_to_string(subject_template_name, context).strip()
        message = render_to_string(email_template_name, context)

        # Call the local `send_email` function
        send_email(subject, message, [to_email])

class RiskAdminForm(forms.ModelForm):
    class Meta:
        model = Risk
        fields = '__all__'

    def clean(self):
        cleaned_data = super().clean()
        inherent_likelihood = cleaned_data.get('inherent_likelihood')
        inherent_impact = cleaned_data.get('inherent_impact')
        residual_likelihood = cleaned_data.get('residual_likelihood')
        residual_impact = cleaned_data.get('residual_impact')
        targeted_likelihood = cleaned_data.get('targeted_likelihood')
        targeted_impact = cleaned_data.get('targeted_impact')

        if inherent_likelihood and inherent_impact and residual_likelihood and residual_impact:
            inherent_score = inherent_likelihood * inherent_impact
            residual_score = residual_likelihood * residual_impact
            if residual_score > inherent_score:
                raise ValidationError("Residual score must be equal to or lower than the inherent score.")

        if residual_likelihood and residual_impact and targeted_likelihood and targeted_impact:
            residual_score = residual_likelihood * residual_impact
            targeted_score = targeted_likelihood * targeted_impact
            if targeted_score > residual_score:
                raise ValidationError("Targeted score must be equal to or lower than the residual score.")

            # Check for associated actions if targeted score is lower
            if targeted_score < residual_score and not self.instance.actions.exists():
                raise ValidationError("There must be at least one associated action when the targeted score is lower than the residual score.")

        return cleaned_data


class MitigationAdminForm(forms.ModelForm):
    class Meta:
        model = Mitigation
        fields = '__all__'
        widgets = {
            'title': forms.Textarea(attrs={
                'rows': 4,
                'style': 'width: 100%; max-width: 100%; box-sizing: border-box; resize: both;'
            })
        }

    def __init__(self, *args, **kwargs):
        request = kwargs.pop('request', None)  # Retrieve the request object
        super(MitigationAdminForm, self).__init__(*args, **kwargs)

        # Filter portfolios based on user's access
        if request and not request.user.is_superuser:
            user_profile = UserProfile.objects.filter(user=request.user).first()
            if user_profile:
                user_portfolios = user_profile.portfolios.all()
                self.fields['portfolio'].queryset = Portfolio.objects.filter(id__in=user_portfolios)
            else:
                self.fields['portfolio'].queryset = Portfolio.objects.none()  # No portfolios if no UserProfile

    def clean_title(self):
        title = self.cleaned_data.get("title")
        cleaned_title = strip_tags(title)  # Remove any HTML tags
        return cleaned_title

from django import forms
from orm.models import Counterparty

from django import forms
from .models import Counterparty

class CounterpartyForm(forms.ModelForm):
    class Meta:
        model = Counterparty
        fields = [
            'name', 'registration_number', 'counterparty_type', 'country',
            'street_address', 'city', 'state', 'postal_code',
            'contact_email', 'contact_phone', 'entity_type', 'is_active',
        ]  # Explicitly list all fields including is_active
        widgets = {
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            # Optionally customize other fields if needed
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'registration_number': forms.TextInput(attrs={'class': 'form-control'}),
            'counterparty_type': forms.TextInput(attrs={'class': 'form-control'}),
            'country': forms.TextInput(attrs={'class': 'form-control'}),
            'street_address': forms.TextInput(attrs={'class': 'form-control'}),
            'city': forms.TextInput(attrs={'class': 'form-control'}),
            'state': forms.TextInput(attrs={'class': 'form-control'}),
            'postal_code': forms.TextInput(attrs={'class': 'form-control'}),
            'contact_email': forms.EmailInput(attrs={'class': 'form-control'}),
            'contact_phone': forms.TextInput(attrs={'class': 'form-control'}),
            'entity_type': forms.TextInput(attrs={'class': 'form-control'}),
        }

from django import forms
from .models import RiskAssessment, Risk

class RiskAssessmentForm(forms.ModelForm):
    class Meta:
        model = RiskAssessment
        fields = ['title', 'description', 'risks', 'assessor']  # Include the fields you want in the form
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Enter assessment title', 'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 4, 'cols': 40, 'class': 'form-control'}),
            'risks': forms.CheckboxSelectMultiple(attrs={'class': 'form-control'}),
            'assessor': forms.Select(attrs={'class': 'form-control'}),
        }


from django import forms
from django.contrib.auth.models import User
from orm.models import Portfolio

class EmailForm(forms.Form):
    users = forms.ModelChoiceField(queryset=User.objects.all(), label="Select User")

    portfolios = forms.ModelMultipleChoiceField(
        queryset=Portfolio.objects.all(),
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-check-input'}),
        label="Επιλέξτε Χαρτοφυλάκια"
    )
 
    response_deadline = forms.DateField(
        widget=forms.DateInput(attrs={
            'type': 'date', 
            'class': 'form-control'
        }),
        label="Προθεσμία Επιβεβαίωσης"
    )

from django import forms
from .models import Document, Folder
from django import forms
from .models import Document, Folder

class DocumentForm(forms.ModelForm):
    folder = forms.ModelChoiceField(
        queryset=Folder.objects.all(),
        required=False,
        empty_label="No Folder",
        widget=forms.Select(attrs={'class': 'form-control w-100'})
    )

    class Meta:
        model = Document
        fields = ['title', 'file', 'description', 'portfolio', 'folder']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control w-100'}),
            'file': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control w-100', 'rows': 4}),
            'portfolio': forms.Select(attrs={'class': 'form-control w-100'}),
        }

class FolderForm(forms.ModelForm):
    class Meta:
        model = Folder
        fields = ['name', 'parent']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control w-100'}),
            'parent': forms.Select(attrs={'class': 'form-control w-100'}),
        }
