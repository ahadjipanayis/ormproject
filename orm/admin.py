import matplotlib
matplotlib.use('Agg')  # Use 'Agg' backend for non-interactive plots
from django.db.models import Q  # Import Q for combining conditions

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin, GroupAdmin
from django.contrib.auth.models import User, Group
from django import forms
from django.core.exceptions import ValidationError
from django.utils.html import format_html, mark_safe, strip_tags
from django.http import HttpResponse, HttpResponseForbidden
from django.urls import path, reverse
from django.template.loader import render_to_string
import io
import base64
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from import_export import resources, fields
from import_export.widgets import ForeignKeyWidget
from .models import UserProfile, Risk, Portfolio, Category, Mitigation, Action, Indicator, Event, ApprovalRequest, RiskScoreHistory, IndicatorValueHistory, Procedure,AssessmentHistory,RiskAssessment,RiskSnapshot,SMTPSetting,StandardControl,PortfolioControlStatus
from django.utils import timezone
import logging
from django.contrib import messages
from .forms import RiskAdminForm,MitigationAdminForm
from django.db import transaction
import json

from django.shortcuts import redirect

class AssessmentHistoryInline(admin.TabularInline):
    model = AssessmentHistory
    extra = 0
    readonly_fields = ('date', 'assessor',)



# Define resources for import-export
class UserProfileResource(resources.ModelResource):
    class Meta:
        model = UserProfile
        encoding = 'utf-8'

class PortfolioResource(resources.ModelResource):
    class Meta:
        model = Portfolio
        export_order = ('id', 'name', 'description')
        encoding = 'utf-8'

class CategoryResource(resources.ModelResource):
    class Meta:
        model = Category
        export_order = ('id', 'name', 'description')
        encoding = 'utf-8'

class MitigationResource(resources.ModelResource):
    owner = fields.Field(column_name='owner', attribute='owner', widget=ForeignKeyWidget(UserProfile, 'user__username'))

    class Meta:
        model = Mitigation
        export_order = ('id', 'title', 'description', 'owner', 'portfolio', 'effectiveness')
        encoding = 'utf-8'

class ActionResource(resources.ModelResource):
    owner = fields.Field(column_name='owner', attribute='owner', widget=ForeignKeyWidget(UserProfile, 'user__username'))
    performer = fields.Field(column_name='performer', attribute='performer', widget=ForeignKeyWidget(UserProfile, 'user__username'))

    class Meta:
        model = Action
        export_order = ('id', 'title', 'description', 'owner', 'performer', 'deadline', 'portfolio')
        encoding = 'utf-8'

class IndicatorResource(resources.ModelResource):
    class Meta:
        model = Indicator
        encoding = 'utf-8'

class EventResource(resources.ModelResource):
    class Meta:
        model = Event
        encoding = 'utf-8'

class RiskResource(resources.ModelResource):
    class Meta:
        model = Risk
        encoding = 'utf-8'

class IndicatorValueHistoryResource(resources.ModelResource):
    class Meta:
        model = IndicatorValueHistory
        encoding = 'utf-8'

class RiskScoreHistoryResource(resources.ModelResource):
    class Meta:
        model = RiskScoreHistory
        encoding = 'utf-8'

class ApprovalRequestResource(resources.ModelResource):
    class Meta:
        model = ApprovalRequest
        encoding = 'utf-8'

class ProcedureResource(resources.ModelResource):
    class Meta:
        model = Procedure
        encoding = 'utf-8'

# Custom admin site
class CustomAdminSite(admin.AdminSite):
    site_header = ''
    site_title = ''
    index_title = 'Welcome'
    
    class Media:
        css = {
            'all': (
                #  'orm/css/custom_admin.css',  # Load custom CSS first
            ),
        }
    
    def each_context(self, request):
            # Get the default context
            context = super().each_context(request)
            # Add the CSS files to the context
            context['custom_css'] = '/static/css/custom_admin.css'
            return context

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('approvalrequest/<int:pk>/change/', self.admin_view(self.change_approval_request), name='approvalrequest_change'),
        ]
        return custom_urls + urls


    def change_approval_request(self, request, pk):
        return self.admin_view(self.approval_request_change_view)(request, pk)

    def approval_request_change_view(self, request, pk):
        approval_request = ApprovalRequest.objects.get(pk=pk)
        return self.change_view(request, object_id=str(pk), model=ApprovalRequest, extra_context={'approval_request': approval_request})

admin_site = CustomAdminSite(name='orm_admin')


class MitigationInlineForm(forms.ModelForm):
    class Meta:
        model = Risk.mitigations.through  # Adjust this to your actual model connection
        fields = ['mitigation']  # Only include the mitigation field (dropdown)

from django.contrib import admin
from django.utils.html import format_html
from .models import Risk, Mitigation

from django.contrib import admin
from django.utils.html import format_html
from .models import Risk, Mitigation, UserProfile

from django.utils.html import format_html
from django.utils.safestring import mark_safe  # Allows safely marking the HTML

from django.db.models import F
from django.utils.html import strip_tags

from django import forms
from django.utils.html import strip_tags

class MitigationInline(admin.TabularInline):
    model = Risk.mitigations.through
    form = MitigationInlineForm

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == "mitigation":
            # Cache UserProfile for the current request
            user_profile = getattr(request, '_cached_user_profile', None)
            if not user_profile:
                user_profile = UserProfile.objects.filter(user=request.user).select_related('user').first()
                setattr(request, '_cached_user_profile', user_profile)
            
            # Cache Portfolios for the current request
            if user_profile:
                user_portfolios = getattr(request, '_cached_user_portfolios', None)
                if not user_portfolios:
                    user_portfolios = user_profile.portfolios.all()
                    setattr(request, '_cached_user_portfolios', user_portfolios)
                
                kwargs["queryset"] = Mitigation.objects.filter(portfolio__in=user_portfolios).select_related('portfolio')
            else:
                kwargs["queryset"] = Mitigation.objects.none()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)
class ActionInlineForm(forms.ModelForm):
    class Meta:
        model = Risk.actions.through  # Adjust to your actual model connection
        fields = ['action']  # Only include the action field (dropdown)

class ActionInline(admin.TabularInline):
    model = Risk.actions.through  # Adjust this to your actual model connection
    form = ActionInlineForm
    extra = 0
    fields = ('action', 'formatted_description')
    readonly_fields = ('formatted_description',)
    verbose_name_plural = "ACTIONS"

    def formatted_description(self, obj):
        if obj and obj.action and obj.action.description:
            return format_html(obj.action.description)
        return ""
    formatted_description.short_description = 'Action Description'

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == "action":  # The foreign key field to filter
            if request.user.is_superuser:
                # Superusers see all actions
                kwargs["queryset"] = Action.objects.all()
            else:
                # Get the user's portfolios from UserProfile
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Action.objects.filter(portfolio__in=user_portfolios)
                else:
                    kwargs["queryset"] = Action.objects.none()  # No access if no UserProfile
        return super().formfield_for_foreignkey(db_field, request, **kwargs)



class IndicatorInlineForm(forms.ModelForm):
    class Meta:
        model = Risk.indicators.through  # Adjust this to your actual model connection
        fields = ['indicator']  # Only include the indicator field (dropdown)

class IndicatorInline(admin.TabularInline):
    model = Risk.indicators.through
    form = IndicatorInlineForm
    extra = 0
    fields = ('indicator', 'formatted_description')
    readonly_fields = ('formatted_description',)
    verbose_name_plural = "INDICATORS"

    def formatted_description(self, obj):
        if obj and obj.indicator and obj.indicator.description:
            return format_html(obj.indicator.description)
        return ""
    formatted_description.short_description = 'Indicator Description'

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == "indicator":  # The foreign key field to filter
            if request.user.is_superuser:
                # Superusers see all indicators
                kwargs["queryset"] = Indicator.objects.all()
            else:
                # Get the user's portfolios from UserProfile
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Indicator.objects.filter(portfolio__in=user_portfolios)
                else:
                    kwargs["queryset"] = Indicator.objects.none()  # No access if no UserProfile
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

class EventInlineForm(forms.ModelForm):
    class Meta:
        model = Risk.events.through  # Adjust this to your actual model connection
        fields = ['event']  # Only include the event field (dropdown)

class EventInline(admin.TabularInline):
    model = Risk.events.through
    form = EventInlineForm
    extra = 0
    fields = ('event', 'formatted_description')
    readonly_fields = ('formatted_description',)
    verbose_name_plural = "EVENTS"

    def formatted_description(self, obj):
        if obj and obj.event and obj.event.description:
            return format_html(obj.event.description)
        return ""

    formatted_description.short_description = 'Event Description'

class ProcedureInlineForm(forms.ModelForm):
    class Meta:
        model = Risk.procedures.through  # Adjust this to your actual model connection
        fields = ['procedure']  # Only include the procedure field (dropdown)

class ProcedureInline(admin.TabularInline):
    model = Risk.procedures.through
    form = ProcedureInlineForm
    extra = 0
    fields = ('procedure', 'formatted_description')
    readonly_fields = ('formatted_description',)
    verbose_name_plural = "PROCEDURES"

    def formatted_description(self, obj):
        if obj and obj.procedure and obj.procedure.description:
            return format_html(obj.procedure.description)
        return ""

    formatted_description.short_description = 'Procedure Description'

class UserProfileInlineForm(forms.ModelForm):
    class Meta:
        model = Risk.owners.through  # Adjust this to your actual model connection
        fields = ['userprofile']  # Only include the userprofile field (dropdown)


class UserProfileInline(admin.TabularInline):
    model = Risk.owners.through
    form = UserProfileInlineForm
    extra = 0
    fields = ('userprofile', 'formatted_role')
    readonly_fields = ('formatted_role',)
    verbose_name_plural = "OWNERS"

    def formatted_role(self, obj):
        if obj and obj.userprofile:
            role = obj.userprofile.role  # Assuming 'role' is a field in the UserProfile model
            return format_html("<strong>{}</strong>", role) if role else "No role assigned"
        return ""

    formatted_role.short_description = 'Role'


class RiskInline(admin.TabularInline):
    model = Procedure.risks.through
    extra = 0

from django.contrib import admin
from .models import Mitigation, Risk, UserProfile

from django.contrib import admin
from .models import Mitigation, Risk, UserProfile

from django.contrib import admin
from .models import Mitigation, Risk, UserProfile

from django.utils.html import strip_tags

class MitigationRiskInline(admin.TabularInline):
    model = Mitigation.risks.through  # Assuming "Mitigation" has a ManyToMany relation to "Risk" through a "through" model
    extra = 0  # No extra blank rows by default

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "risk":  # Adjust if the foreign key field is named differently
            if request.user.is_superuser:
                # Superusers see all risks
                kwargs["queryset"] = Risk.objects.all()
            else:
                # Fetch the user's portfolios from UserProfile
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    # Filter risks by the portfolios assigned to the user
                    kwargs["queryset"] = Risk.objects.filter(portfolio__in=user_portfolios)
                else:
                    # If the user has no UserProfile, show an empty queryset
                    kwargs["queryset"] = Risk.objects.none()

            # Create a custom ModelChoiceField to display cleaned titles in the dropdown
            form_field = super().formfield_for_foreignkey(db_field, request, **kwargs)
            form_field.label_from_instance = lambda obj: strip_tags(obj.title)  # Clean the title
            return form_field

        # Filter available portfolios by user's access
        elif db_field.name == "portfolio":  # Assuming "portfolio" is the field name
            if request.user.is_superuser:
                # Superusers see all portfolios
                kwargs["queryset"] = Portfolio.objects.all()
            else:
                # Regular users only see their assigned portfolios
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Portfolio.objects.filter(id__in=user_portfolios)
                else:
                    kwargs["queryset"] = Portfolio.objects.none()  # No access if no UserProfile

        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class ActionRiskInline(admin.TabularInline):
    model = Action.risks.through
    extra = 0
    class Media:
        css = {
            'all': (
                'orm/css/custom_admin.css',  # Load custom CSS first
            ),
        }

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == "risk":  # The foreign key field to filter
            if request.user.is_superuser:
                # Superusers see all risks
                kwargs["queryset"] = Risk.objects.all()
            else:
                # Get the user's portfolios from UserProfile
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Risk.objects.filter(portfolio__in=user_portfolios)
                else:
                    kwargs["queryset"] = Risk.objects.none()  # No access if no UserProfile
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class IndicatorRiskInline(admin.TabularInline):
    model = Indicator.risks.through
    extra = 0
    class Media:
        css = {
            'all': (
                'orm/css/custom_admin.css',  # Load custom CSS first
            ),
        }

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == "risk":  # The foreign key field to filter
            if request.user.is_superuser:
                # Superusers see all risks
                kwargs["queryset"] = Risk.objects.all()
            else:
                # Get the user's portfolios from UserProfile
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Risk.objects.filter(portfolio__in=user_portfolios)
                else:
                    kwargs["queryset"] = Risk.objects.none()  # No access if no UserProfile
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


from django.utils.html import strip_tags

class EventRiskInline(admin.TabularInline):
    model = Event.risks.through
    extra = 0

    # Custom display for risks in the inline
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Annotate or modify the queryset as necessary
        return qs

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == "risk":  # Ensure this matches the field name in your "through" model
            form_field = super().formfield_for_foreignkey(db_field, request, **kwargs)
            # Customize the label to strip HTML tags from the Risk title
            form_field.label_from_instance = lambda obj: strip_tags(obj.title)
            return form_field
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class IndicatorValueHistoryInline(admin.TabularInline):
    
    model = IndicatorValueHistory
    extra = 0

class RiskScoreHistoryInline(admin.TabularInline):
    model = RiskScoreHistory
    extra = 0

class ApprovalRequestInline(admin.TabularInline):
    model = ApprovalRequest
    extra = 0
    




class RiskAdminForm(forms.ModelForm):
    
   
         
    
    class Meta:
        model = Risk
        fields = [ 'description', 'category', 'portfolio', 'inherent_likelihood', 'inherent_impact', 'residual_likelihood', 'residual_impact', 'targeted_likelihood', 'targeted_impact', 'treatment_type']
        widgets = {
                    'title': forms.Textarea(attrs={'rows': 4, 'cols': 100}),
                }  
    
    def clean(self):
        cleaned_data = super().clean()
        inherent_score = cleaned_data.get('inherent_likelihood') * cleaned_data.get('inherent_impact')
        residual_score = cleaned_data.get('residual_likelihood') * cleaned_data.get('residual_impact')
        targeted_score = cleaned_data.get('targeted_likelihood') * cleaned_data.get('targeted_impact')

        if not (targeted_score <= residual_score <= inherent_score):
            raise ValidationError("Targeted score must be less than or equal to residual score, and residual score must be less than or equal to inherent score.")

        return cleaned_data

class OwnershipAdminMixin:
    def has_change_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        if obj is not None and hasattr(obj, 'owners') and request.user.userprofile not in obj.owners.all():
            return False
        elif obj is not None and hasattr(obj, 'owner') and request.user.userprofile != obj.owner:
            return False
        return True

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        if obj is not None and hasattr(obj, 'owners') and request.user.userprofile not in obj.owners.all():
            return False
        elif obj is not None and hasattr(obj, 'owner') and request.user.userprofile != obj.owner:
            return False
        return True

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            if hasattr(self.model, 'portfolio'):
                return qs.filter(portfolio__in=user_profile.portfolios.all())
            elif hasattr(self.model, 'owners'):
                return qs.filter(owners=user_profile)
            elif hasattr(self.model, 'owner'):
                return qs.filter(owner=user_profile)
            else:
                return qs.none()
        except UserProfile.DoesNotExist:
            return qs.none()

from orm.models import Risk, Opportunity  # Import both models
# Inline for Opportunity in Risk admin

# Inline for linking opportunities with risks
class OpportunityRiskInline(admin.TabularInline):
    model = Risk.opportunities.through  # Through table for the ManyToMany relationship
    extra = 1
    verbose_name_plural = "OPPORTUNITYS"



from django.utils.html import format_html, strip_tags
from orm.models import Opportunity, Risk,Threat
from django.contrib import admin

@admin.register(Opportunity, site=admin_site)
class OpportunityAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    list_display = ('title', 'owner', 'portfolio', 'related_risks', 'formatted_description')  # Display opportunity details
    list_filter = ('title', 'owner', 'portfolio', 'risks')  # Add filters for easy searching
    search_fields = ('title', 'owner__user__username', 'portfolio__name')  # Add search fields

    class Media:
        css = {
            'all': ('orm/css/custom_admin.css',)  # Custom CSS for styling
        }

    def formatted_description(self, obj):
        if obj and obj.description:
            return format_html(obj.description)  # Render HTML as is without sanitization
        return ""
    formatted_description.short_description = 'Description'

    def related_risks(self, obj):
        return ", ".join([risk.title for risk in obj.risks.all()])  # List related risks
    related_risks.short_description = 'Related Risks'
    
    inlines = [OpportunityRiskInline]  # Inline for linking to related risks

from django.contrib import admin
from django.utils.html import format_html

@admin.register(Threat, site=admin_site)
class ThreatAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    list_display = ('title', 'owner', 'portfolio', 'related_risks', 'formatted_description')  # Display threat details
    list_filter = ('title', 'owner', 'portfolio', 'risks')  # Add filters for easy searching
    search_fields = ('title', 'owner__user__username', 'portfolio__name')  # Add search fields

    class Media:
        css = {
            'all': ('orm/css/custom_admin.css',)  # Custom CSS for styling
        }

    def formatted_description(self, obj):
        if obj and obj.description:
            return format_html(obj.description)  # Render HTML as is without sanitization
        return ""
    formatted_description.short_description = 'Description'

    def related_risks(self, obj):
        return ", ".join([risk.title for risk in obj.risks.all()])  # List related risks
    related_risks.short_description = 'Related Risks'
    
    # Add inline if you plan to use it for linking to related risks
    # inlines = [ThreatRiskInline]  # Replace with the appropriate inline class


from django.contrib import admin
from .models import Risk
from .services import generate_risk_proposals  # Import your proposal generation function

@admin.action(description='Generate Proposals for Selected Risks')
def generate_risk_proposals_action(modeladmin, request, queryset):
    for risk in queryset:
        # Call your proposal generation function
        proposals = generate_risk_proposals(risk)
        # Provide feedback to the user in the admin interface
        modeladmin.message_user(request, f"Proposals generated for '{risk.title}': {', '.join(proposals)}")



class RelatedITAssetInline(admin.TabularInline):
    model = Risk.related_assets.through
    extra = 1
    verbose_name = "Related IT Asset"
    verbose_name_plural = "Related IT Assets"

from django.contrib import admin
from orm.models import Threat

class ThreatInline(admin.TabularInline):
    model = Threat.risks.through  # Use the through model for the ManyToMany relationship
    extra = 1  # Number of empty forms to display
    verbose_name = "Threat"
    verbose_name_plural = "Threats"





from .models import SMTPSetting
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string  
import base64
from datetime import date  # Add this import
import bleach

@admin.register(Risk, site=admin_site)
class RiskAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    
 
    resource_class = RiskResource
    
    fieldsets = (
    ('Description', {
        'fields': ('title', 'description'),
    }),
    ('Owner(s)', {
        'fields': ('owners', 'category', 'portfolio', 'approval_cycle'),
    }),
    ('Scores', {
        'fields': (
            'inherent_likelihood', 'inherent_impact', 'inherent_score_display',
            'residual_likelihood', 'residual_impact', 'residual_score_display',
            'targeted_likelihood', 'targeted_impact', 'targeted_score_display',
        ),
    }),
  
)
    


#     fieldsets = (
#     ('Description', {
#         'fields': ('title', 'description'),
#     }),
#     ('                 Owner(s)', {
#         'fields': ('owners','category', 'portfolio', 'approval_cycle'),
#     }),
#     # ('   Owners', {
#     #     # 'fields': ('owners',),  # Assuming 'owners' is the field name for the many-to-many relation
#     # }),
#     ('   Scores', {
#         'fields': (
#             'inherent_likelihood', 'inherent_impact', 'inherent_score_display',
#             'residual_likelihood', 'residual_impact', 'residual_score_display',
#             'targeted_likelihood', 'targeted_impact', 'targeted_score_display',
#             # 'stacked_visualization',
#         ),
        
#     }),
#     # ('   Visuals', {
#     #     'fields': ('stacked_visualization',),
#     # }),
# )
    filter_vertical = ('mitigations','opportunities', 'threats')  # Vertical filter for related items

    def formatted_opportunities(self, obj):
            return ", ".join([opportunity.title for opportunity in obj.opportunities.all()])
    formatted_opportunities.short_description = 'Opportunities'

    def formatted_threats(self, obj):
        return ", ".join([threat.title for threat in obj.threats.all()])
    formatted_threats.short_description = 'Threats'

    inlines = [
        # UserProfileInline,
        MitigationInline,
        ActionInline,
        IndicatorInline,
        EventInline,
        ProcedureInline,
        OpportunityRiskInline,
        ThreatInline,

        RelatedITAssetInline,
        # RiskScoreHistoryInline,
        # ApprovalRequestInline,
    ]

    def has_add_permission(self, request, obj=None):
        # Disable for non-superusers
        return request.user.is_superuser

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
            if db_field.name == "portfolio":  # Assuming "portfolio" is the field name
                if request.user.is_superuser:
                    # Superusers see all portfolios
                    kwargs["queryset"] = Portfolio.objects.all()
                else:
                    # Regular users only see their assigned portfolios
                    user_profile = UserProfile.objects.filter(user=request.user).first()
                    if user_profile:
                        user_portfolios = user_profile.portfolios.all()
                        kwargs["queryset"] = Portfolio.objects.filter(id__in=user_portfolios)
                    else:
                        kwargs["queryset"] = Portfolio.objects.none()  # No access if no UserProfile
            return super().formfield_for_foreignkey(db_field, request, **kwargs)

        

    readonly_fields = (
        'stacked_visualization', 'inherent_score_display', 'residual_score_display', 'targeted_score_display' ,'last_assessed_by',  # Make this field read-only
        'last_assessed_date',  # Make this field read-only
        'last_approval_info',  # Make this field read-only
        'approval_flag_color_display',  # Make this field read-only
        'assessment_flag_color_display',
        )

    # actions = ['create_approval_requests']

    list_display = (
        'get_cleaned_title',  'get_owners','portfolio','category','inherent_score_display', 'residual_score_display', 'targeted_score_display',
        'approval_cycle','last_approval_date','next_approval_date','approval_flag_color_display', 
        'last_assessed_date','next_assessment_date','assessment_flag_color_display',
        # 'get_short_description',
    )

   
    # list_editable = ('approval_cycle','category')

  

    list_filter = ('title','category', 'owners','portfolio')


    @admin.action(description='Generate Proposals for Selected Risks')
    def generate_risk_proposals_action(self, request, queryset):
            proposals_data = {}
            for risk in queryset:
                proposals = generate_risk_proposals(risk)
                proposals_data[risk.pk] = {
                    'title': risk.title,
                    'description': risk.description,
                    'proposals': proposals
                }

            request.session['generated_proposals_data'] = proposals_data
            return redirect(reverse('risk_proposals_page'))  
    actions = [generate_risk_proposals_action]
    
    
    
    from orm.models import Opportunity  # Ensure that Opportunity is imported
    admin.site.register(Opportunity)
     
    def get_owners(self, obj):
        return ", ".join([owner.role for owner in obj.owners.all()])
    get_owners.short_description = 'Owners'   
    
    from django.utils import timezone

   

    def get_cleaned_title(self, obj):
        # Strip HTML tags for display in the admin list view
        return mark_safe(strip_tags(obj.title))

    get_cleaned_title.short_description = 'Title'  # Set the column header in the admin list view

    def assessment_flag_color(self, obj):
        # Check if next_assessment_date is in the future or not
        if obj.next_assessment_date and obj.next_assessment_date.date() >= date.today():
            return "#00FF00"  # Next assessment date is valid
        else:
            return "#FF0000"  # Next assessment date has lapsed


    def assessment_flag_color_display(self, obj):
            color = self.assessment_flag_color(obj)
            return format_html("<span style='color:{};'>●</span>", color)
        
    assessment_flag_color_display.short_description = 'Assessment Flag'
   




    def change_view(self, request, object_id, form_url='', extra_context=None):
        # Fetch the Risk instance
        risk = self.get_object(request, object_id)
        if risk:
            # Generate a URL for your custom logic (you can use '#' for a placeholder)
            custom_url = reverse('admin:risk_proposals_view', args=[risk.pk])
            custom_button = format_html(
                '<div style="margin: 10px 0;">'
                '<a class="button" href="{}" style="background-color: #007bff; color: white; padding: 5px 10px; text-decoration: none; border-radius: 3px;">'
                'Generate Proposals</a>'
                '</div>',
                custom_url
            )
            # Inject the button into extra_context
            extra_context = extra_context or {}
            extra_context['custom_button'] = custom_button

        return super().change_view(request, object_id, form_url, extra_context=extra_context)


    def get_urls(self):
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            # Your custom view URL
            path(
                '<int:risk_id>/proposals/',
                self.admin_site.admin_view(self.risk_proposals_view),
                name='risk_proposals_view',
            ),
        ]
        return custom_urls + urls
    # admin.py
    from orm.services import generate_risk_proposals

    def risk_proposals_view(self, request, risk_id):
        # Your logic to generate and display proposals
        risk = Risk.objects.get(pk=risk_id)
        proposals = generate_risk_proposals(risk)
        self.message_user(request, f"Proposals generated for '{risk.title}': {proposals}")
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/admin/'))


    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import base64
    from django.template.loader import render_to_string
    import logging
    

    
    def inherent_score_display(self, obj):
        score = obj.inherent_score()
        traffic_light, color = obj.inherent_traffic_light()
        return format_html("<span style='color:{};'>{} x {} = {} ({})</span>", color, obj.inherent_likelihood, obj.inherent_impact, score, traffic_light) if score else "N/A"
    inherent_score_display.short_description = 'Inherent Score'

    def residual_score_display(self, obj):
        score = obj.residual_score()
        traffic_light, color = obj.residual_traffic_light()
        return format_html("<span style='color:{};'>{} x {} = {} ({})</span>", color, obj.residual_likelihood, obj.residual_impact, score, traffic_light) if score else "N/A"
    residual_score_display.short_description = 'Residual Score'

    def targeted_score_display(self, obj):
        score = obj.targeted_score()
        traffic_light, color = obj.targeted_traffic_light()
        return format_html("<span style='color:{};'>{} x {} = {} ({})</span>", color, obj.targeted_likelihood, obj.targeted_impact, score, traffic_light) if score else "N/A"
    targeted_score_display.short_description = 'Targeted Score'

    
    
    
    from datetime import date, timedelta
    from django.utils.html import format_html

    def approval_flag_color_display(self, obj):
        # Check if last_assessed_date is available
        if obj.last_approval_date:
            # Convert last_assessed_date to date
            last_approval_date = obj.last_approval_date.date()
            # Calculate the threshold date for six months ago
            six_months_ago = date.today() - timedelta(days=180)
            if last_approval_date >= six_months_ago:
                return format_html("<span style='color:{};'>●</span>", "#00FF00")  # Green if assessed in the last six months
            else:
                return format_html("<span style='color:{};'>●</span>", "#FF0000")  # Red if older than six months
        else:
            # If no last_assessed_date is set, show red flag
            return format_html("<span style='color:{};'>●</span>", "#FF0000")

# -----------------------------------

    import json
    from django.utils.safestring import mark_safe

    def score_trend_graph(self, obj):
        return format_html(
            """
            <div id="scoreTrendContainer{obj_id}" style="width: 100%; max-width: 400px; height: 300px; margin: 0 auto; text-align: center;">
                <button onclick="loadScoreTrendChart('{obj_id}')" style="margin-top: 10px; padding: 5px 10px; background: #007bff; color: white; border: none; border-radius: 4px;">
                    Load Graph
                </button>
                <canvas id="scoreTrendChart{obj_id}" style="display: none; width: 100%; height: 100%;"></canvas>
            </div>
            <script>
                function loadScoreTrendChart(objId) {{
                    const canvas = document.getElementById('scoreTrendChart' + objId);
                    const container = document.getElementById('scoreTrendContainer' + objId);
                    canvas.style.display = 'block';
                    const ctx = canvas.getContext('2d');
                    
                    new Chart(ctx, {{
                        type: 'line',
                        data: {{
                            labels: {labels_json},
                            datasets: [
                                {{
                                    label: "Inherent",
                                    data: {inherent_values_json},
                                    borderColor: "#1f77b4",
                                    fill: false
                                }},
                                {{
                                    label: "Residual",
                                    data: {residual_values_json},
                                    borderColor: "#9467bd",
                                    fill: false
                                }},
                                {{
                                    label: "Targeted",
                                    data: {targeted_values_json},
                                    borderColor: "#8c564b",
                                    fill: false
                                }}
                            ]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {{
                                x: {{
                                    title: {{
                                        display: true,
                                        text: "Date"
                                    }}
                                }},
                                y: {{
                                    title: {{
                                        display: true,
                                        text: "Score"
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}
            </script>
            """,
            obj_id=obj.id,
            labels_json=json.dumps([score.timestamp.strftime('%Y-%m-%d') for score in obj.score_history.filter(score_type='inherent').order_by('timestamp')]),
            inherent_values_json=json.dumps([score.score for score in obj.score_history.filter(score_type='inherent').order_by('timestamp')]),
            residual_values_json=json.dumps([score.score for score in obj.score_history.filter(score_type='residual').order_by('timestamp')]),
            targeted_values_json=json.dumps([score.score for score in obj.score_history.filter(score_type='targeted').order_by('timestamp')])
        )
    score_trend_graph.short_description = 'Score Graph'

 
        # Define consistent colors for score types
    # Centralized color scheme
    SCORE_COLORS = {
        'inherent': '#1f77b4',  # Same blue across both graphs
        'residual': '#9467bd',  # Same purple across both graphs
        'targeted': '#8c564b'   # Same brown across both graphs
    }


    from django.utils.html import format_html
    from django.utils.safestring import mark_safe

    def generate_heatmap(self, obj):
        # Define risk color based on score
        def risk_color(score):
            if 1 <= score <= 6:
                return 'green'
            elif 8 <= score <= 12:
                return 'orange'
            elif 15 <= score <= 25:
                return 'red'
            return 'white'

        # Wrapper div for the heatmap grid
        heatmap_html = f"""
            <div style="text-align: center; width: 100%; max-width: 500px; aspect-ratio: 5 / 4; padding: 10px; margin: 0 auto;">
                <h4 style='font-size: 14px; margin-bottom: 10px;'>Heatmap: {obj.title}</h4>
                <table style="width: 100%; height: 100%; border-collapse: separate; table-layout: fixed; font-size: 14px; text-align: center;">
        """

        # Construct the grid with fixed cell sizes and colors
        for likelihood in range(5, 0, -1):  # Likelihood (5 to 1, top to bottom)
            heatmap_html += "<tr>"
            for impact in range(1, 6):  # Impact (1 to 5, left to right)
                score = likelihood * impact
                cell_color = risk_color(score)
                cell_content = ""

                # Collect short labels for each score type sharing the same position
                labels = []
                for score_type, short_label in zip(['inherent', 'residual', 'targeted'], ['I', 'R', 'T']):
                    if getattr(obj, f"{score_type}_likelihood") == likelihood and getattr(obj, f"{score_type}_impact") == impact:
                        color = self.SCORE_COLORS[score_type]
                        labels.append(f"<div style='background:{color}; padding:3px 5px; color:white; border-radius:5px; font-weight:bold; margin:2px;'>{short_label}</div>")

                # Center labels if there are multiple in the same cell
                # Center labels if there are multiple in the same cell
                if labels:
                    cell_content = "<div style='display: flex; flex-direction: row; align-items: center; justify-content: center; gap: 4px;'>" + "".join(labels) + "</div>"

                # Add each cell with color, fixed dimensions, and rounded corners
                heatmap_html += f"<td style='background-color:{cell_color}; border-radius:10px; width:20%; height:20%; padding:10px;'>{cell_content}</td>"
            heatmap_html += "</tr>"
        heatmap_html += "</table></div>"

        return format_html(mark_safe(heatmap_html))

    generate_heatmap.short_description = 'Heatmap'













    def stacked_visualization(self, obj):
        heatmap_html = self.generate_heatmap(obj)
        score_trend_html = self.score_trend_graph(obj)

        return format_html(
            """
            <div class='graph-container' style='margin-bottom: 20px;'>{}</div>
            <div class='graph-container'>{}</div>
            """,
            heatmap_html,
            score_trend_html,
        )

    stacked_visualization.short_description = ''

    def get_short_description(self, obj):
        return mark_safe(strip_tags(obj.description)[:100] + ('...' if len(strip_tags(obj.description)) > 20 else ''))
    get_short_description.short_description = 'Description'


        # Custom action to create a risk assessment
    def create_risk_assessment(self, request, queryset):
        if queryset:
            # Assuming the assessor is the current logged-in user
            title = f"Risk Assessment - {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
            assessor = UserProfile.objects.get(user=request.user)
            # Create a new risk assessment with selected risks
            risk_assessment = RiskAssessment.objects.create(assessor=assessor, created_by=assessor,title=title)
            risk_assessment.risks.set(queryset)
            risk_assessment.save()
            # Display a success message
            self.message_user(request, f"New Risk Assessment was created with {queryset.count()} risks.", messages.SUCCESS)
        else:
            self.message_user(request, "No risks selected.", messages.WARNING)

    create_risk_assessment.short_description = "ASSESMENT"

    # Register the action
    actions = ['create_risk_assessment','generate_risk_proposals_action']

    def save_model(self, request, obj, form, change):
        # Initial save to persist main model data
        super().save_model(request, obj, form, change)

        # Save ManyToMany relationships by re-saving the object
        form.save_m2m()  # This ensures all ManyToMany relationships are saved

        # Now that ManyToMany relationships are saved, re-fetch related data
        obj.refresh_from_db()

        # Calculate scores after ensuring all related data is saved
        residual_score = obj.residual_likelihood * obj.residual_impact
        targeted_score = obj.targeted_likelihood * obj.targeted_impact

        # Display warning if conditions are met
        if targeted_score < residual_score and not obj.actions.exists():
            self.message_user(
                request,
                "Targeted score is lower than residual score, and no actions are associated. Please review scores and/or actions.",
                level=messages.WARNING
            )


from django import forms
from django.utils.html import strip_tags
from .models import ApprovalRequest  # Adjust import based on your app structure

class ApprovalRequestAdminForm(forms.ModelForm):
    class Meta:
        model = ApprovalRequest
        fields = '__all__'

    def clean_description(self):
        # Assuming the ApprovalRequest model has a 'description' field
        description = self.cleaned_data.get('description', '')
        cleaned_description = strip_tags(description)  # Remove HTML tags
        return cleaned_description


import concurrent.futures
from django.core.mail import send_mail
from django.template.loader import render_to_string
import logging

from django.utils.html import strip_tags, mark_safe

@admin.register(ApprovalRequest, site=admin_site)
class ApprovalRequestAdmin(admin.ModelAdmin):
    resource_class = ApprovalRequestResource
    form = ApprovalRequestAdminForm
    list_display = ('get_cleaned_risk_title', 'user', 'status', 'due_date')
    actions = ['approve_requests', 'reject_requests']

    def get_cleaned_risk_title(self, obj):
        # Clean and strip HTML tags from the related risk's title
        if obj.risk and obj.risk.title:
            return strip_tags(obj.risk.title)
        return "N/A"
    get_cleaned_risk_title.short_description = 'Risk'

    def get_queryset(self, request):
        """
        Filters the queryset so that users can only see pending approval requests related to their profile.
        Superusers will see all pending approval requests.
        """
        qs = super().get_queryset(request).filter(status='pending')  # Only show pending approval requests
        
        if request.user.is_superuser:
            return qs  # Superusers can see all pending approval requests
        
        # Get the current user's profile
        current_user_profile = UserProfile.objects.get(user=request.user)

        # Filter approval requests where the current user is the owner and the status is 'pending'
        return qs.filter(user=current_user_profile)

    def save_model(self, request, obj, form, change):
        """
        Overrides the default save behavior to trigger approval actions when the
        approval request status is set to 'approved'.
        """
        # Check if the approval request is being set to 'approved'
        if obj.status == 'approved' and not obj.response_date:
            # Set the response date to now
            obj.response_date = timezone.now()

            # Call the function to handle approval logic
            self.approve_requests(request, ApprovalRequest.objects.filter(id=obj.id))
        
        # Call the default save method to save the model
        super().save_model(request, obj, form, change)

    def send_email(self, subject, message, recipient_list):
        smtp_settings = SMTPSetting.objects.first()

        msg = MIMEMultipart()
        msg['From'] = smtp_settings.sender_email
        msg['To'] = smtp_settings.admin_email
        msg['Subject'] = subject

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
            server.set_debuglevel(1)
            server.ehlo()
            server.starttls()
            server.ehlo()

            # Perform AUTH LOGIN manually
            server.docmd("AUTH LOGIN", encoded_user)
            server.docmd(encoded_password)

            # Send the email
            server.sendmail(msg['From'], recipient_list, msg.as_string())
            server.quit()
            logging.info("Email sent successfully")
        except smtplib.SMTPException as e:
            logging.error(f"Failed to send email: {e}")

    # def send_approval_confirmation_email(self, approval_request):
    #     smtp_settings = SMTPSetting.objects.first()

    #     subject = f"Approval Request Approved: {approval_request.risk.title}"
    #     message = render_to_string('emails/approval_confirmation_email.html', {
    #         'user': approval_request.user.user,
    #         'risk': approval_request.risk,
    #         'approving_user': approval_request.user.user,
    #     })

    #     try:
    #         self.send_email(subject, message, [smtp_settings.admin_email])
    #     except Exception as e:
    #         logging.error(f"Failed to send email to {smtp_settings.admin_email}: {e}")

    def approve_request_on_save(self, request, approval_request):
        queryset = ApprovalRequest.objects.filter(id=approval_request.id)

        self.approve_requests(request, queryset)

        # self.send_approval_confirmation_email(approval_request)

        return approval_request

    def approve_requests(self, request, queryset):
        for approval_request in queryset:
            current_user_profile = UserProfile.objects.get(user=request.user)

            if approval_request.user != current_user_profile and not request.user.is_superuser:
                print(f"User {request.user.username} does not have permission to approve request {approval_request.id}.")
                continue

            approval_request.status = 'approved'
            approval_request.response_date = timezone.now()
            approval_request.save()

            risk = approval_request.risk
            risk.last_approval_date = approval_request.response_date
            risk.next_approval_date = risk.last_approval_date + risk.get_approval_cycle_timedelta()
            risk.last_approved_by = approval_request.user
            risk.save()

            new_approval_request = ApprovalRequest.objects.create(
                risk=risk,
                user=approval_request.user,
                status='pending',
                rational="Automatically generated approval request",
                due_date=timezone.now().date() + risk.get_approval_cycle_timedelta()
            )

            # self.send_approval_confirmation_email(approval_request)

        return None

class CustomUserAdmin(BaseUserAdmin):
    readonly_fields = ('password',)
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')

class CustomGroupAdmin(GroupAdmin):
    list_filter = ('name',)

# Register User and Group with the custom admin site
admin_site.register(User, CustomUserAdmin)
admin_site.register(Group, CustomGroupAdmin)


from django.contrib import admin
from orm.models import UserProfile, Portfolio

class PortfolioInline(admin.TabularInline):  # You can also use admin.StackedInline
    model = UserProfile.portfolios.through  # Assuming a ManyToMany relationship
    extra = 1  # Number of empty forms to display



@admin.register(UserProfile, site=admin_site)
class UserProfileAdmin(admin.ModelAdmin):
    resource_class = UserProfileResource
    list_display = ('role', 'user')
    filter_horizontal = ('portfolios',)  # Use filter_horizontal for a horizontal multi-select widget
    # OR
    # filter_vertical = ('portfolios',)  # Use this for a vertical multi-select widget



@admin.register(AssessmentHistory, site=admin_site)
class AssessmentHistoryAdmin(admin.ModelAdmin):
    
    def has_add_permission(self, request, obj=None):
        # Disable for non-superusers
        return request.user.is_superuser
    resource_class = AssessmentHistory


from django.contrib.auth.models import User

from django.contrib.auth.models import User

@admin.register(Portfolio, site=admin_site)
class PortfolioAdmin(admin.ModelAdmin):
    list_display = ('name', 'get_clean_description')
    search_fields = ('name', 'description')  # Ensure the fields exist in the Portfolio model
    resource_class = PortfolioResource

    def get_clean_description(self, obj):
        return strip_tags(obj.description)
    get_clean_description.short_description = 'Description'

    def save_model(self, request, obj, form, change):
        # Save the portfolio first
        super().save_model(request, obj, form, change)

        # Get or create the user's profile (the creator)
        user_profile, _ = UserProfile.objects.get_or_create(user=request.user)

        # Add the new portfolio to the creating user's profile if not already assigned
        if obj not in user_profile.portfolios.all():
            user_profile.portfolios.add(obj)

        # Retrieve the admin email from the first SMTPSetting record
        admin_email = SMTPSetting.objects.values_list('admin_email', flat=True).first()
        if admin_email:
            # Find the admin user by email
            admin_user = User.objects.filter(email=admin_email).first()
            if admin_user:
                # Get or create the admin user's profile
                admin_profile, _ = UserProfile.objects.get_or_create(user=admin_user)
                
                # Assign the portfolio to the admin user's profile if not already assigned
                if obj not in admin_profile.portfolios.all():
                    admin_profile.portfolios.add(obj)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)

        # Check if the user has a UserProfile with assigned portfolios
        user_profile = UserProfile.objects.filter(user=request.user).first()

        if user_profile:
            # Return only portfolios associated with the user's profile
            return queryset.filter(user_profiles=user_profile)

        # If no UserProfile or portfolios are assigned, return an empty queryset
        return queryset.none()


@admin.register(Category, site=admin_site)
class CategoryAdmin(admin.ModelAdmin):
    resource_class = CategoryResource

@admin.register(IndicatorValueHistory, site=admin_site)
class IndicatorValueHistoryAdmin(admin.ModelAdmin):
    def has_add_permission(self, request, obj=None):
        # Disable for non-superusers
        return request.user.is_superuser
    
    resource_class = IndicatorValueHistoryResource
    
    

@admin.register(SMTPSetting, site=admin_site)  # Register the model with your custom admin site
class SmtpSettingAdmin(admin.ModelAdmin):
    # list_display = ('smtp_server', 'smtp_port', 'smtp_username', 'sender_email')  # Customize fields to display
    search_fields = ('smtp_server', 'smtp_username')  # Fields to include in the search bar



@admin.register(RiskScoreHistory, site=admin_site)
class RiskScoreHistoryAdmin(admin.ModelAdmin):
            
    resource_class = RiskScoreHistoryResource

@admin.register(Procedure, site=admin_site)
class ProcedureAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    resource_class = ProcedureResource
    search_fields = ('title', 'description', 'department', 'owner__user__username')
    
    # Matching list_display more closely with MitigationAdmin
    list_display = ('title', 'get_short_description', 'department', 'owner')
    
    # Inline models if applicable, similar to MitigationAdmin
    inlines = [RiskInline]

    def get_short_description(self, obj):
        return format_html(
            '<div>{}</div>', 
            mark_safe(strip_tags(obj.description)[:200] + ('...' if len(strip_tags(obj.description)) > 20 else ''))
        )
    get_short_description.short_description = 'Description'

    def get_queryset(self, request):
        """
        Override to show all procedures to all users.
        """
        # Get the full queryset
        queryset = Procedure.objects.all()
        
        # Log for debugging, if needed
        # if not request.user.is_superuser:
        #     print(f"Non-superuser {request.user.username} accessing all procedures.")
        
        return queryset  # Return all procedures, unfiltered






from django.contrib.admin import filters

from django.utils.html import strip_tags, mark_safe

@admin.register(Mitigation, site=admin_site)
class MitigationAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    resource_class = MitigationResource
    list_display = ('get_cleaned_title', 'get_owners', 'portfolio', 'get_cleaned_related_risks', 'effectiveness', 'get_short_description')
    list_filter = ('title', ('owners', filters.RelatedOnlyFieldListFilter), 'portfolio', 'risks', 'effectiveness')
    inlines = [MitigationRiskInline]
    def has_add_permission(self, request, obj=None):
        # Disable for non-superusers
        return request.user.is_superuser
    def get_cleaned_related_risks(self, obj):
        # Assuming obj.related_risks is a queryset or list of related risks
        related_risks = obj.risks.all()  # Adjust this if related_risks is accessed differently
        cleaned_risks = []

        for risk in related_risks:
            # Clean the title of each related risk by stripping HTML tags
            cleaned_title = strip_tags(risk.title)  # Remove HTML tags
            cleaned_risks.append(cleaned_title)

        # Join cleaned titles with a comma separator and mark as safe to prevent escaping
        return mark_safe(", ".join(cleaned_risks))

    get_cleaned_related_risks.short_description = 'Related Risks'

    def get_cleaned_title(self, obj):
        # Strip HTML tags for display in the admin list view
        return mark_safe(strip_tags(obj.title))

    get_cleaned_title.short_description = 'Title'

    def get_short_description(self, obj):
        return format_html('<div>{}</div>', mark_safe(strip_tags(obj.description)[:200] + ('...' if len(strip_tags(obj.description)) > 200 else '')))
    get_short_description.short_description = 'Description'

    def get_owners(self, obj):
        return ", ".join([owner.role for owner in obj.owners.all()])
    get_owners.short_description = 'Owners'

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "portfolio":
            if request.user.is_superuser:
                kwargs["queryset"] = Portfolio.objects.all()
            else:
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Portfolio.objects.filter(id__in=user_portfolios)
                else:
                    kwargs["queryset"] = Portfolio.objects.none()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

from django.contrib import admin
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from django.utils.html import format_html
from datetime import timedelta  # Ensure this import is present
from .models import Indicator, IndicatorValueHistory
import os  # Add this import at the beginning of your file
import matplotlib.pyplot as plt
import io
import base64
from django.utils.html import format_html
from datetime import timedelta

from django.utils import timezone

from django.utils.html import strip_tags, mark_safe

@admin.register(Indicator, site=admin_site)
class IndicatorAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    resource_class = IndicatorResource
    list_display = ('title', 'get_cleaned_related_risks', 'owner', 'repetition_frequency', 'get_short_description')
    list_filter = ('title', 'owner', 'portfolio', 'field', 'repetition_frequency')
    readonly_fields = ('indicator_value_graph',)
    inlines = [IndicatorValueHistoryInline, IndicatorRiskInline]

    def has_add_permission(self, request, obj=None):
        # Disable for non-superusers
        return request.user.is_superuser

    def get_short_description(self, obj):
        return format_html('<div>{}</div>', mark_safe(strip_tags(obj.description)[:200] + ('...' if len(strip_tags(obj.description)) > 200 else '')))
    get_short_description.short_description = 'Description'

    def get_cleaned_related_risks(self, obj):
        related_risks = obj.risks.all()
        cleaned_risks = [strip_tags(risk.title) for risk in related_risks]
        return mark_safe(", ".join(cleaned_risks))
    get_cleaned_related_risks.short_description = 'Related Risks'

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        if db_field.name == "portfolio":
            if request.user.is_superuser:
                kwargs["queryset"] = Portfolio.objects.all()
            else:
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Portfolio.objects.filter(id__in=user_portfolios)
                else:
                    kwargs["queryset"] = Portfolio.objects.none()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def save_model(self, request, obj, form, change):
        user_profile = UserProfile.objects.filter(user=request.user).first()
        if user_profile and not obj.owner:
            obj.owner = user_profile
        super().save_model(request, obj, form, change)

    def indicator_value_graph(self, obj):
        value_history = IndicatorValueHistory.objects.filter(indicator=obj).order_by('timestamp')
        timestamps = [vh.timestamp.strftime('%Y-%m-%d') for vh in value_history]
        values = [vh.value for vh in value_history]

        if not timestamps or not values:
            return mark_safe('<strong>No data available to display the graph.</strong>')

        # Convert data to JSON
        timestamps_json = json.dumps(timestamps)
        values_json = json.dumps(values)

        # Generate HTML and JavaScript for Chart.js
        chart_html = mark_safe(f"""
            <div style="width: 100%; max-width: 800px; height: 400px; margin: 0 auto;">
                <h4 style="text-align: center;">Indicator Value Trends: {obj.title}</h4>
                <canvas id="indicatorGraph{obj.id}" style="width: 100%; height: 100%;"></canvas>
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <script>
                    const ctx = document.getElementById('indicatorGraph{obj.id}').getContext('2d');
                    new Chart(ctx, {{
                        type: 'line',
                        data: {{
                            labels: {timestamps_json},
                            datasets: [
                                {{
                                    label: "Indicator Value",
                                    data: {values_json},
                                    borderColor: "rgba(54, 162, 235, 1)",
                                    backgroundColor: "rgba(54, 162, 235, 0.2)",
                                    borderWidth: 2,
                                    pointRadius: 4,
                                    pointBackgroundColor: "rgba(54, 162, 235, 1)"
                                }}
                            ]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {{
                                x: {{
                                    title: {{
                                        display: true,
                                        text: 'Date',
                                        font: {{ size: 12 }}
                                    }},
                                    ticks: {{ font: {{ size: 10 }} }}
                                }},
                                y: {{
                                    title: {{
                                        display: true,
                                        text: 'Value',
                                        font: {{ size: 12 }}
                                    }},
                                    ticks: {{ font: {{ size: 10 }} }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    display: true,
                                    labels: {{ font: {{ size: 10 }} }}
                                }}
                            }}
                        }}
                    }});
                </script>
            </div>
        """)

        return chart_html

    indicator_value_graph.short_description = 'Indicator Graph'



import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging

@admin.register(Event, site=admin_site)
class EventAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    resource_class = EventResource
    list_display = ('title', 'get_short_description', 'related_risks', 'owner', 'reporter', 'portfolio')

    def get_short_description(self, obj):
        return format_html('<div>{}</div>', mark_safe(strip_tags(obj.description)[:200] + ('...' if len(strip_tags(obj.description)) > 20 else '')))
    get_short_description.short_description = 'Description'

    def related_risks(self, obj):
        return ", ".join([risk.title for risk in obj.risks.all()])
    related_risks.short_description = 'Related Risks'

    list_filter = ('title', 'owner', 'reporter', 'portfolio', 'date')
    inlines = [EventRiskInline]

    def save_model(self, request, obj, form, change):
        # Automatically assign the current user's UserProfile as the reporter if not set
        if not obj.reporter:
            try:
                # Get the UserProfile associated with the current user
                obj.reporter = request.user.userprofile
            except UserProfile.DoesNotExist:
                logging.error(f"UserProfile for user {request.user} does not exist.")
                return  # You may want to handle this case differently

        # Save the object after setting the reporter
        super().save_model(request, obj, form, change)

        # Send an email after saving the event
        self.send_event_created_email(request, obj)

    def send_event_created_email(self, request, event):
        """
        Send an email to the admin notifying them that a new event has been created.
        """
        subject = f"New Event Created: '{event.title}'"
        message = f"""
        <html>
            <body>
                <p>A new event <strong>'{event.title}'</strong> has been created by {event.reporter}.<br>
                Here are the details:<br><br>
                <strong>Title:</strong> {event.title}<br>
                <strong>Description:</strong> {event.description}<br>
                <strong>Owner:</strong> {event.owner}<br>
                <strong>Portfolio:</strong> {event.portfolio}<br>
                <strong>Reporter:</strong> {event.reporter}
                </p>
                <p>Thank you ermapp.avax.gr (admin) </p>
            </body>
        </html>
        """
        
        # Fetch SMTP settings from the database, including the admin email
        smtp_settings = SMTPSetting.objects.first()

        if smtp_settings and smtp_settings.admin_email:
            recipient_list = [smtp_settings.admin_email]
            self.send_email(subject, message, recipient_list)
        else:
            logging.error("Admin email not configured in SMTP settings.")

    def send_email(self, subject, message, recipient_list):
        smtp_settings = SMTPSetting.objects.first()

        if not smtp_settings:
            logging.error("SMTP settings not configured.")
            return

        msg = MIMEMultipart()
        msg['From'] = smtp_settings.sender_email
        msg['To'] = ', '.join(recipient_list)
        msg['Subject'] = subject

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
            logging.info(f"Email sent successfully to {recipient_list}")
        except smtplib.SMTPException as e:
            logging.error(f"Failed to send email: {e}")

from django.utils.html import strip_tags, mark_safe

@admin.register(Action, site=admin_site)
class ActionAdmin(OwnershipAdminMixin, admin.ModelAdmin):
    resource_class = ActionResource
    list_display = ('title', 'portfolio', 'get_cleaned_related_risks', 'status', 'owner', 'performer', 'deadline', 'get_short_description')
    list_filter = ('title', 'risks', 'performer', 'deadline', 'status', 'owner', 'portfolio')
    inlines = [ActionRiskInline]
    def has_add_permission(self, request, obj=None):
        # Disable for non-superusers
        return request.user.is_superuser
    def get_short_description(self, obj):
        return format_html('<div>{}</div>', mark_safe(strip_tags(obj.description)[:200] + ('...' if len(strip_tags(obj.description)) > 200 else '')))
    get_short_description.short_description = 'Description'

    def get_cleaned_related_risks(self, obj):
        # Clean and strip HTML tags from related risks' titles
        related_risks = obj.risks.all()
        cleaned_risks = [strip_tags(risk.title) for risk in related_risks]
        return mark_safe(", ".join(cleaned_risks))
    get_cleaned_related_risks.short_description = 'Related Risks'

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        # Filter portfolio field based on user's accessible portfolios
        if db_field.name == "portfolio":
            if request.user.is_superuser:
                kwargs["queryset"] = Portfolio.objects.all()
            else:
                user_profile = UserProfile.objects.filter(user=request.user).first()
                if user_profile:
                    user_portfolios = user_profile.portfolios.all()
                    kwargs["queryset"] = Portfolio.objects.filter(id__in=user_portfolios)
                else:
                    kwargs["queryset"] = Portfolio.objects.none()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    from django.utils import timezone

    def save_model(self, request, obj, form, change):
        # Retrieve the UserProfile for the current user
        user_profile = UserProfile.objects.filter(user=request.user).first()
        if user_profile and not obj.owner:
            obj.owner = user_profile  # Set the owner to the UserProfile instance

        # Set the deadline to today if it's not already set
        if not obj.deadline:
            obj.deadline = timezone.now().date()

        super().save_model(request, obj, form, change)


import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import send_mail

def send_email(subject, body, to_email):
    try:
        send_mail(
            subject,
            body,
            settings.DEFAULT_FROM_EMAIL,  # Using the default from email in settings
            [to_email],
            fail_silently=False,
        )
        print(f"Email sent successfully to {to_email}!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def send_approval_request_email(requester, approver_email, request_details):
    subject = "New Approval Request"
    body = render_to_string('emails/approval_request.html', {'requester': requester, 'request_details': request_details})
    print(f"Triggering approval request email to {approver_email}")
    send_email(subject, body, approver_email)

def send_approval_accepted_email(approver, requester_email, approval_details):
    subject = "Approval Request Accepted"
    body = render_to_string('emails/approval_accepted.html', {'approver': approver, 'approval_details': approval_details})
    print(f"Triggering approval accepted email to {requester_email}")
    send_email(subject, body, requester_email)

def send_approval_rejected_email(approver, requester_email, rejection_details):
    subject = "Approval Request Rejected"
    body = render_to_string('emails/approval_rejected.html', {'approver': approver, 'rejection_details': rejection_details})
    print(f"Triggering approval rejected email to {requester_email}")
    send_email(subject, body, requester_email)

# Example usage in your workflow, ensure these functions are correctly triggered:
def create_approval_request(request, *args, **kwargs):
    print("Function create_approval_request called")
    approval_request = ApprovalRequest.objects.create(...)
    
    # Send the email
    send_approval_request_email(request.user, approval_request.approver.email, approval_request.details)

def approve_request(request, approval_request_id):
    print(f"Function approve_request called with ID: {approval_request_id}")
    approval_request = ApprovalRequest.objects.get(id=approval_request_id)
    approval_request.status = 'accepted'
    approval_request.save()
    
    # Send the email
    send_approval_accepted_email(request.user, approval_request.requester.email, approval_request.details)

def reject_request(request, approval_request_id):
    print(f"Function reject_request called with ID: {approval_request_id}")
    approval_request = ApprovalRequest.objects.get(id=approval_request_id)
    approval_request.status = 'rejected'
    approval_request.save()
    
    # Send the email
    send_approval_rejected_email(request.user, approval_request.requester.email, approval_request.details)


from django.utils.html import format_html
from django.contrib import admin, messages
from django import forms
from django.template.loader import render_to_string
from .models import Risk, RiskAssessment, RiskSnapshot, AssessmentHistory, UserProfile
# from .admin_site import admin_site  # Assuming you have a custom admin site
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import logging
from .models import SMTPSetting

class RiskInlineForm(forms.ModelForm):
    class Meta:
        model = RiskAssessment.risks.through  # Assuming a ManyToMany relationship
        fields = ['risk']  # Include only the risk field (dropdown)

class RiskInline(admin.TabularInline):
    model = RiskAssessment.risks.through
    form = RiskInlineForm
    extra = 0
    fields = ('risk', 'formatted_description')  # Include dropdown and formatted description
    readonly_fields = ('formatted_description',)  # Make description read-only

    def formatted_description(self, obj):
        if obj and obj.risk and obj.risk.description:
            return format_html(obj.risk.description)  # Render HTML as is without sanitization
        return ""

    formatted_description.short_description = 'Risk Description'

class RiskSnapshotInline(admin.TabularInline):
    model = RiskSnapshot
    extra = 0
    readonly_fields = ('title', 'description', 'inherent_score', 'residual_score', 'targeted_score')

class AssessmentHistoryInline(admin.TabularInline):
    model = AssessmentHistory
    extra = 0
    readonly_fields = ('date', 'assessor')
    can_delete = False
    show_change_link = True

@admin.register(RiskAssessment, site=admin_site)

# admin_site.register(RiskAssessment, RiskAssessmentAdmin)

class RiskAssessmentAdmin(admin.ModelAdmin):
    
    def has_change_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        if obj is not None:
            user_profile = UserProfile.objects.get(user=request.user)
            return obj.assessor == user_profile or obj.created_by == user_profile
        return False

    def has_add_permission(self, request, obj=None):
            # Disable for non-superusers
            return request.user.is_superuser

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        else:
            user_profile = UserProfile.objects.get(user=request.user)
            return qs.filter(
                Q(assessor=user_profile) | Q(created_by=user_profile)
            )

    
    def mark_as_completed(self, request, queryset):
        user_profile = UserProfile.objects.get(user=request.user)
        
        for assessment in queryset:
            if assessment.assessor == user_profile:
                assessment.mark_assessed()
                self.message_user(request, f"Assessment '{assessment.title}' marked as completed.", messages.SUCCESS)
                
                # Update last assessed information for the risks
                for risk in assessment.risks.all():
                    risk.update_last_assessed(assessment.assessor)
# Update next_assessment_date
                    if risk.last_assessed_date:
                        risk.next_assessment_date = risk.last_assessed_date + timedelta(days=180)
                    risk.save()
                # Send assessment completion email to the creator
                self.send_assessment_completed_email(request, assessment)
            else:
                self.message_user(request, f"You do not have permission to complete the assessment '{assessment.title}'.", messages.ERROR)
        
    mark_as_completed.short_description = "Mark selected assessments as completed"
    actions = [mark_as_completed]        

    icon = 'fas fa-cogs'
    
    list_display = ('title', 'assessor', 'created_by', 'created_at', 'assessed_at', 'status')
    filter_horizontal = ('risks',)
    search_fields = ('assessor__user__username', 'created_by__user__username', 'status')
    list_filter = ('status', 'created_at', 'assessed_at')
    
    inlines = [RiskInline, AssessmentHistoryInline]  # RiskSnapshotInline is not included if not needed
    
    class Media:
        css = {
            'all': (
                'orm/css/custom_admin.css',  # Load custom CSS first
            ),
        }

    def save_model(self, request, obj, form, change):
        """
        Override the save_model method to apply custom logic when an assessment is saved in the admin.
        This includes updating the assessment, the related risks, and creating an assessment history entry.
        """
        user_profile = UserProfile.objects.get(user=request.user)
        
        # Ensure the user has permission to save/complete the assessment
        if obj.assessor == user_profile:
            # Update last assessed information for the risks
            for risk in obj.risks.all():
                risk.update_last_assessed(obj.assessor)
                
                # Update next_assessment_date
                if risk.last_assessed_date:
                    risk.next_assessment_date = risk.last_assessed_date + timedelta(days=180)
                risk.save()

            # Create an assessment history entry
            AssessmentHistory.objects.create(
                risk_assessment=obj,
                # action='saved',  # Or 'completed' depending on how you track it
                assessor=user_profile,
                date=timezone.now()  # Or timezone.now() if you want the current time
            )

            # Send an email notifying that the assessment has been saved/completed
            self.send_assessment_completed_email(request, obj)

        # else:
            # self.message_user(request, f"You do not have permission to save the assessment '{obj.title}'.", messages.ERROR)

        # Proceed to save the assessment
        super().save_model(request, obj, form, change)

    def send_assessment_completed_email(self, request, assessment):
        """
        Send a completion email to the creator of the assessment.
        """
        subject = f"Assessment '{assessment.title}' Completed"
        message = f"The assessment '{assessment.title}' has been successfully completed."
        recipient = assessment.creator.email if assessment.creator else None

        if recipient:
            send_mail(subject, message, 'riskmanagement@avax.gr', [recipient])
                
    def send_email(self, subject, message, recipient_list):
        
        smtp_settings = SMTPSetting.objects.first()

        
        msg = MIMEMultipart()
        msg['From'] = smtp_settings.sender_email
        msg['To'] = ', '.join(recipient_list)
        msg['Subject'] = subject
        
        # Attach the HTML message
        msg.attach(MIMEText(message, 'html'))

        # SMTP server configuration
        smtp_host = smtp_settings.smtp_server
        smtp_port = smtp_settings.smtp_port
        smtp_user = smtp_settings.smtp_username
        smtp_password = smtp_settings.smtp_password  # Replace with your actual password

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
            logging.info(f"Email sent successfully to {recipient_list}")
        except smtplib.SMTPException as e:
            logging.error(f"Failed to send email: {e}")

    def send_new_assessment_email(self, request, assessment):
        subject = f"New Assessment Assigned for Risk: {assessment.title}"
        
        # Rendering the email content using a template
        message = render_to_string('emails/assessment_email.html', {
            'user': assessment.assessor.user,
            'risk': assessment.title,
            'requesting_user': request.user,
            'assessor': assessment.assessor.user,  # Include assessor separately

        })
        
        # Send the email to the assessor
        try:
            self.send_email(subject, message, [assessment.assessor.user.email])
        except Exception as e:
            logging.error(f"Failed to send email to {assessment.assessor.user.email}: {e}")

    def send_assessment_completed_email(self, request, assessment):
        subject = f"Assessment Completed for Risk: {assessment.title}"
        
        # Rendering the email content using a template
        message = render_to_string('emails/assessment_completed_email.html', {
            'user': assessment.created_by.user,
            'risk': assessment.title,
            'requesting_user': request.user,
        })
        
        # Send the email to the creator
        try:
            self.send_email(subject, message, [assessment.created_by.user.email])
        except Exception as e:
            logging.error(f"Failed to send email to {assessment.created_by.user.email}: {e}")

    def assessment_history_display(self, obj):
        histories = obj.assessment_history.all()
        if not histories:
            return "No history available"
        display_html = ""
        for history in histories:
            display_html += f"<h3>Assessment on {history.date.strftime('%Y-%m-%d')} by {history.assessor.user.username}</h3>"
            for snapshot in history.risk_snapshots.all():
                display_html += f"<p>Risk: {snapshot.title} | Inherent Score: {snapshot.inherent_score} | Residual Score: {snapshot.residual_score} | Targeted Score: {snapshot.targeted_score}</p>"
        return format_html(display_html)

    assessment_history_display.short_description = "Assessment History"
    readonly_fields = ('assessment_history_display',)

# ========================
from .models import ITThreat

@admin.register(ITThreat, site=admin_site)
class ITThreatAdmin(admin.ModelAdmin):
    list_display = ('code', 'category', 'risk_sources', 'description')
    list_filter = ('category', 'risk_sources')
    search_fields = ('code', 'description')

from .models import Vulnerability

@admin.register(Vulnerability, site=admin_site)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('code', 'category', 'description')
    list_filter = ('category',)
    search_fields = ('code', 'description')
    filter_horizontal = ('threats',)  # ✅ Correct: ManyToMany with ITThreat


from .models import ITAsset

@admin.register(ITAsset, site=admin_site)
class ITAssetAdmin(admin.ModelAdmin):
    list_display = ('name', 'asset_type', 'status', 'criticality', 'portfolio')
    list_filter = ('asset_type', 'status', 'portfolio')
    search_fields = ('name', 'description')
    filter_horizontal = ('owners', 'vulnerabilities', 'threats')  # ✅ Correct: All are ManyToManyFields

# ========================


@admin.register(StandardControl, site=admin_site)
class StandardControlAdmin(admin.ModelAdmin):
    list_display = ('standard_name', 'control_id', 'control_name', 'globally_applicable')
    list_filter = ('standard_name', 'globally_applicable')
    search_fields = ('standard_name', 'control_id', 'control_name', 'description')
    ordering = ('standard_name', 'control_id')


@admin.register(PortfolioControlStatus, site=admin_site)
class PortfolioControlStatusAdmin(admin.ModelAdmin):
    list_display = ('portfolio', 'standard_control', 'applicable', 'rationale')
    list_filter = ('applicable', 'portfolio__name', 'standard_control__standard_name')
    search_fields = (
        'portfolio__name',
        'standard_control__control_id',
        'standard_control__control_name',
        'rationale',
    )
    autocomplete_fields = ('portfolio', 'standard_control')  # Efficient for large datasets
    ordering = ('portfolio__name', 'standard_control__control_id')



# -----------------------

from django.contrib import admin
from .models import Counterparty, KYCStandard, KYCQuestion, DueDiligenceAssessment, AssessmentResponse


# Counterparty Admin
@admin.register(Counterparty, site=admin_site)
class CounterpartyAdmin(admin.ModelAdmin):
    list_display = (
        'name', 
        'counterparty_type', 
        'country', 
        'registration_number', 
        'contact_email', 
        'is_sanctioned_display',
        'sanction_source',
        'sanction_created_at',
    )
    search_fields = ('name', 'registration_number', 'country')
    list_filter = ('counterparty_type', 'country', 'is_sanctioned', 'sanction_source')

    def is_sanctioned_display(self, obj):
        """
        Custom display method for is_sanctioned with a badge.
        """
        if obj.is_sanctioned:
            return format_html(
                '<span class="badge bg-danger">Sanctioned</span>'
            )
        return format_html(
            '<span class="badge bg-success">Not Sanctioned</span>'
        )

    is_sanctioned_display.short_description = 'Sanction Status'

from django import forms

from django import forms

from django import forms

from django import forms

class AssessmentResponseForm(forms.ModelForm):
    class Meta:
        model = AssessmentResponse
        fields = ['question', 'response_value']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Safely check if a question exists using `question_id`
        if self.instance and self.instance.question_id:
            self.fields['response_value'] = forms.ChoiceField(
                choices=self.instance.question.get_score_choices(),
                label="Response Value",
                required=True
            )
        else:
            self.fields['response_value'] = forms.ChoiceField(
                choices=[(0, "No question available")],
                label="Response Value",
                required=False
            )
class AssessmentResponseInline(admin.TabularInline):
    model = AssessmentResponse
    form = AssessmentResponseForm
    extra = 0
    fields = ('question', 'response_value')
    readonly_fields = ('question',)

@admin.register(DueDiligenceAssessment, site=admin_site)
class DueDiligenceAssessmentAdmin(admin.ModelAdmin):
    list_display = ('counterparty', 'assessment_date', 'last_saved', 'performed_by', 'overall_score', 'classification', 'status')
    list_filter = ('status', 'assessment_date', 'classification')
    search_fields = ('counterparty__name',)
    inlines = [AssessmentResponseInline]
    readonly_fields = ('overall_score', 'classification', 'last_saved', 'performed_by')

    def save_model(self, request, obj, form, change):
        """
        Automatically set the `performed_by` field to the currently logged-in user and calculate the overall score.
        """
        if not obj.performed_by:  # Only set `performed_by` if it's not already assigned
            try:
                obj.performed_by = UserProfile.objects.get(user=request.user)
            except UserProfile.DoesNotExist:
                raise ValueError("The current user does not have an associated UserProfile.")
        super().save_model(request, obj, form, change)
        obj.calculate_overall_score()


# Inline for KYC Questions in KYC Standard
class KYCQuestionInline(admin.TabularInline):
    model = KYCQuestion
    extra = 1


# KYC Standard Admin
@admin.register(KYCStandard, site=admin_site)
class KYCStandardAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    inlines = [KYCQuestionInline]


from django.contrib import admin
from orm.models import CounterpartySanctionCheck

@admin.register(CounterpartySanctionCheck)
class CounterpartySanctionCheckAdmin(admin.ModelAdmin):
    list_display = ("counterparty", "sanction_list", "status", "check_date")
    list_filter = ("status", "check_date")
    search_fields = ("counterparty__name", "sanction_list__name")




from django.contrib import admin
from .models import LikelihoodImpactDescription

@admin.register(LikelihoodImpactDescription, site=admin_site)
class LikelihoodImpactDescriptionAdmin(admin.ModelAdmin):
    list_display = ('category', 'score', 'description')  # Fields to display in the admin list
    list_filter = ('category',)  # Filter by Likelihood or Impact
    ordering = ('category', 'score')  # Default ordering
    search_fields = ('description',)  # Enable search by description
