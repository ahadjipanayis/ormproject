from pathlib import Path
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'your-secret-key'

DEBUG = True

# ---------------------- Allowed Hosts ----------------------
# Update the ALLOWED_HOSTS to explicitly list your domains for added security
ALLOWED_HOSTS = ['ermapp.avax.gr', '127.0.0.1','localhost','173.19.2.177']

# ---------------------- Site URL ----------------------
# Update the SITE_URL to reflect the correct protocol and domain
SITE_URL = 'https://ermapp.avax.gr'  # For the live environment
# SITE_URL = 'https://ermapp.avax.gr:8443'  # Uncomment this for dev environment if needed

# ---------------------- CSRF Trusted Origins ----------------------
# Make sure CSRF_TRUSTED_ORIGINS uses HTTPS and includes dev environment if applicable
CSRF_TRUSTED_ORIGINS = [
    'https://ermapp.avax.gr',
    'https://localhost:8000',  # If you're running locally for dev
    'http://ermapp.avax.gr:8081'  # For dev with HTTPS on port 8443
]

# ---------------------- X-Frame Options ----------------------
# Make sure only one X_FRAME_OPTIONS is set
X_FRAME_OPTIONS = 'ALLOWALL'  # You can use 'SAMEORIGIN' for stricter policy if needed

# ---------------------- Login URLs ----------------------
LOGIN_URL = '/login/'  # Updated to point to the correct login URL
LOGIN_REDIRECT_URL = '/'  # Redirect to the root of the site after login
LOGOUT_REDIRECT_URL = '/login/'  # Redirect to the login page after logout

# ---------------------- Insecure Settings ----------------------
# Make sure SSL settings are configured properly for your environment
# SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True

# settings.py

INSTALLED_APPS = [
    'tinymce',
    'corsheaders',

    # 'crispy_forms',
    # 'crispy_bootstrap4', 
    # 'slick_reporting',
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'orm',
    'import_export',
  
    'django_select2', 
]


XAI_API_URL = 'https://api.x.ai/v1/chat/completions'




MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',

    'django.middleware.security.SecurityMiddleware',  # Security Middleware
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Static file optimization, directly after SecurityMiddleware
    'django.contrib.sessions.middleware.SessionMiddleware',  # Manages user sessions
    'django.middleware.locale.LocaleMiddleware',  # Add this after SessionMiddleware
    'django.middleware.common.CommonMiddleware',  # Handles common tasks like URL rewriting
    'django.middleware.csrf.CsrfViewMiddleware',  # CSRF protection
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # Handles authentication
    'django.contrib.messages.middleware.MessageMiddleware',  # Message framework middleware
    'django.middleware.clickjacking.XFrameOptionsMiddleware',  # Protects against clickjacking

    # Custom Middleware
    'orm.middleware.Custom403Middleware',  # Custom middleware (ensure it works correctly)
    'orm.middleware.LicenseCheckMiddleware',  # Custom license check middleware
    # 'orm.middleware.UserActivityMiddleware',
    'orm.middleware.UserActivityMiddleware'
]
ROOT_URLCONF = 'ormproject.urls'
import os

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            'libraries': {
                'crispy_forms_tags': 'crispy_forms.templatetags.crispy_forms_tags',
            }
        },
    },
]

WSGI_APPLICATION = 'ormproject.wsgi.application'

CORS_ALLOW_CREDENTIALS = True  # Allow cookies for authentication
CORS_ALLOWED_ORIGINS = [
    "https://ermapp.avax.gr",  # Allow your frontend
    "http://localhost:8081",
    "http://ermapp.avax.gr:8081", # Allow local testing
]

CORS_ALLOW_METHODS = ["GET", "POST", "OPTIONS", "DELETE", "PATCH", "PUT"]
CORS_ALLOW_HEADERS = ["*"]  # Allow all headers

DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB

DATABASE_ROUTERS = ['orm.routers.MetasploitRouter']

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }
# settings.py


# m4 db 

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'postgres',  # Your database name
#         'USER': 'postgres',  # Your PostgreSQL username
#         'PASSWORD': 'a',  # Your PostgreSQL password
#         'HOST': 'localhost',  # Since PostgreSQL is running locally
#         'PORT': '5432',  # Default PostgreSQL port
#   }
# }



# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'd3ce0fhv8pgt07',  # Your database name
#         'USER': 'uemtdingrq3cvk',  # Your PostgreSQL username
#         'PASSWORD': 'p2f54d672016c59bd6015fcc34b82a39aab97d82497a52043af68549b1eae3722',  # Your PostgreSQL password
#         'HOST': 'ccpa7stkruda3o.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com',  # Since PostgreSQL is running locally
#         'PORT': '5432',  # Default PostgreSQL port
#     }
# }


DATABASES = {
   'default': {
         'ENGINE': 'django.db.backends.postgresql_psycopg2',
         'NAME': 'ermapp',
         'USER': 'alexis',
         'PASSWORD': 'Alexis1!',
         'HOST': '173.19.2.177',  # Or the hostname of your database
         'PORT': '5432',        # Default PostgreSQL port
     }
 }


# DATABASES = {
#    'default': {
#          'ENGINE': 'django.db.backends.postgresql_psycopg2',
#          'NAME': 'ermappdev',
#          'USER': 'alexis',
#          'PASSWORD': 'Alexis1!',
#          'HOST': '173.19.2.177',  # Or the hostname of your database
#          'PORT': '5432',        # Default PostgreSQL port
#      }
#  }



AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Europe/Athens'



USE_I18N = True

USE_L10N = True

USE_TZ = True

# Enable internationalization and localization
USE_I18N = True
USE_L10N = True

# Define supported languages
LANGUAGES = [
    ('en', 'English'),
    ('el', 'Greek'),
    ('ru', 'Russian'),
    ('uk', 'Ukrainian'),
    ('ro', 'Romanian'),
    ('de', 'German'),
    ('it', 'Italian'),
]

# Directory for translation files
LOCALE_PATHS = [
    BASE_DIR / 'locale',  # e.g., /path/to/myproject/locale/
]




# Build paths inside the project like this: BASE_DIR / "subdir".
BASE_DIR = Path(__file__).resolve().parent.parent

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/stable/howto/static-files/

# 1. URL to use when referring to static files located in STATIC_ROOT.
STATIC_URL = '/static/'

# 2. Additional directories where Django will search for static files in development
STATICFILES_DIRS = [
    BASE_DIR / "static",  # Include a global static directory
    # or, for Django < 3.1:
    # os.path.join(BASE_DIR, "static"),
]

# 3. Directory where Django will collect static files for deployment
STATIC_ROOT = BASE_DIR / "staticfiles"  # Collect all static files in this directory for production
# or, for Django < 3.1:
# STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [            os.path.join(BASE_DIR, 'templates'),  
            os.path.join(BASE_DIR, 'orm/templates'), ],  # Keep this empty or add custom paths if needed
        'APP_DIRS': True,  # This should be True to allow app-level templates
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


MEDIA_URL = '/media/'
MEDIA_ROOT = '/home/alexis/projects/ormproject/media/'  # Adjust if different

TINYMCE_DEFAULT_CONFIG = {
    'plugins': 'lists fullscreen ',  # Enable spellchecker plugin
    'toolbar': 'fullscreen | bold italic | bullist | outdent indent | spellchecker',  # Add spellchecker button to the toolbar
    'menubar': True,  # Hide the menubar for a simpler interface
    'content_css': 'default',
    'use_tinymce': False,  # Ensure TinyMCE isn't applied to all text fields

    'paste_as_text': True,  # Paste content as plain text
    'paste_auto_cleanup_on_paste': True,  # Clean up on paste to maintain formatting simplicity
    'entity_encoding': 'raw',
    'convert_urls': False,

    'height': 400,
    'width': '100%',
    
    'promotion': False,
    # 'forced_root_block': 'p',  # Wrap content in <p> tags by default, prevents inline text issues

    # Only allow specific elements and attributes
    'valid_elements': 'p,br,b,strong,i,em,ul,li',  # Limited to basic formatting tags
    'extended_valid_elements': 'ul[type|compact],li',  # Ensures unordered lists are handled correctly

    # Additional cleanup for paste functionality
    'paste_word_valid_elements': "b,strong,i,em,ul,li,p",  # Allow only simple tags when pasting
    'paste_merge_formats': True,  # Merges formatting to keep it simple

    'browser_spellcheck': True
}


LOCALE_PATHS = [
    BASE_DIR / 'locale',  # e.g., /path/to/myproject/locale/
]


DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'


STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'

# Extra places for collectstatic to find static files.
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)




JAZZMIN_SETTINGS = {
    # title of the window (Will default to current_admin_site.site_title if absent or None)
    "site_title": "ermapp.avax.gr",
    "login_redirect_url": "/",  # Redirect to the homepage or external tools page

    # Title on the login screen (19 chars max) (defaults to current_admin_site.site_header if absent or None)
    "site_header": "ermapp.avax.gr",

    # Title on the brand (19 chars max) (defaults to current_admin_site.site_header if absent or None)
    "site_brand": "ermapp.avax.gr",

    # Logo to use for your site, must be present in static files, used for brand on top left
    "site_logo": "/images/avax-logo.jpeg",

    # Logo to use for your site, must be present in static files, used for login form logo (defaults to site_logo)
    "login_logo": "/images/avax-logo.jpeg",

    # Logo to use for login form in dark themes (defaults to login_logo)
    "login_logo_dark": "/images/avax-logo.jpeg",

    # CSS classes that are applied to the logo above
    "site_logo_classes": "img-box",

    # Relative path to a favicon for your site, will default to site_logo if absent (ideally 32x32 px)
    "site_icon": '/images/favicon.png',

    # Welcome text on the login screen
    "welcome_sign": "Welcome to the ermapp.avax.gr",

    # Copyright on the footer
    "copyright": "ermapp.avax.gr",

    # List of model admins to search from the search bar, search bar omitted if excluded
    # If you want to use a single search field you dont need to use a list, you can use a simple string 
    # "search_model": "orm.Risk",

    # Field name on user model that contains avatar ImageField/URLField/Charfield or a callable that receives the user

    

    ############
    # Top Menu #
    ############

    "topmenu_links": [
        # {"name": "Home", "url": "admin:index", "permissions": ["auth.view_user"]},

           # Your custom report links
         # external url that opens in a new window (Permissions can be added)
        # {"name": "METABASE", "url": "http://ermapp.avax.gr:3000", "new_window": True},
        {
            "name": "Views", 
            "url": "/",  # Ensure this matches the URL name in urls.py
            "permissions": ["orm.view_risk"],
            "new_window": False
        },
        
#         {
#     "name": "Pivot",
#     "icon": "fas fa-users-cog",
#     "url": "/risk-pivot-table/",  # Use the full path starting with "/"
#     "permissions": ["orm.view_risk"],
#     "new_window": True
# },
        
        
        
        # {
        #     "name": "Risk Detail Report", 
        #     "url": "risk_detail_report",  # Ensure this matches the URL name in urls.py
        #     "permissions": ["orm.view_risk"]
        # },
        
        #   Your models
        {"model": "Risks", "name": "Risks", "url": "admin:orm_risk_changelist", "permissions": ["orm.view_risk"]},
        {"model": "Mitigations", "name": "Mitigations", "url": "admin:orm_mitigation_changelist", "permissions": ["orm.view_mitigation"]},
        {"model": "Opportunitys", "name": "Opportunitys", "url": "admin:orm_opportunity_changelist", "permissions": ["orm.view_opportunity"]},
        {"model": "Threats", "name": "Threats", "url": "admin:orm_threat_changelist", "permissions": ["orm.view_threat"]},

        {"model": "Actions", "name": "Actions", "url": "admin:orm_action_changelist", "permissions": ["orm.view_action"]},
        {"model": "Indicators", "name": "Indicators", "url": "admin:orm_indicator_changelist", "permissions": ["orm.view_indicator"]},
        {"model": "Events", "name": "Events", "url": "admin:orm_event_changelist", "permissions": ["orm.view_event"]},
        {"model": "Procedures", "name": "Procedures", "url": "admin:orm_procedure_changelist", "permissions": ["orm.view_procedure"]},
      
      
        {"model": "ITAsset", "name": "ITAsset", "url": "admin:orm_itasset_changelist", "permissions": ["orm.view_itasse"]},

        {"model": "Approvals", "name": "Approvals", "url": "admin:orm_approvalrequest_changelist", "permissions": ["orm.view_approvalrequest"], "icon": "fa-check-double"},

        {"model": "Assessments", "name": "Assessments", "url": "admin:orm_riskassessment_changelist", "permissions": ["orm.view_riskassessment"]},
       
        # {"app": "orm"},
    ],
    

    #############
    # User Menu #
    #############

    # Additional links to include in the user menu on the top right ("app" url type is not allowed)
    "usermenu_links": [
    # {"name": "Presentation", "url": "http://173.19.2.177/static/images/erm.pdf", "new_window": True,"icon": "fas fa-chart-line"},
    # {"name": "Erd", "url": "http://173.19.2.177/static/images/erd.png", "new_window": True,"icon": "fas fa-project-diagram"},
	 {
            "name": "User manual",  # The name to display
            "url": "/landing-page/",  # The URL to your manual (can be static or an external link)
            "new_window": True,  # Opens in a new tab
            "icon": "fas fa-book",  # Optional, icon from FontAwesome
        },
  
    ],


    #############
    
    # Side Menu #
    #############

    # Whether to display the side menu
    "show_sidebar": True,

    # Whether to aut expand the menu
    "navigation_expanded": True,

    # Hide these apps when generating side menu e.g (auth)
    "hide_apps": [],

    # Hide these models when generating side menu (e.g auth.user)
    # "hide_models": ["orm.Risk","orm.Procedure","orm.Mitigation","orm.Action","orm.Event","orm.Opportunity","orm.Indicator"],
    "order_with_respect_to": [
                             "orm.UserProfile",

                              "orm.Risk",
                              "orm.Mitigation",
                              "orm.Action",
                              "orm.Event",
                              "orm.Opportunity",
                              "orm.Indicator",
                              "orm.Procedure",
                              "auth",
                              "orm.Category", 
                              "orm.Portfolio",
                              "orm.ApprovalRequest",
                              "orm.RiskAssessment",
                              "orm.smtpsetting",
                              "orm.StandardControl",
                              "orm.portfoliocontrolstatus",
                              "orm.itasset",  
                              "orm.counterparty",
                            
                              "orm.kycstandard",
                              "orm.duediligenceassessment",


                              "orm.IndicatorValueHistory", 
                              "orm.RiskScoreHistory" ,

                              "orm.AssessmentHistory"],

    # List of apps (and/or models) to base side menu ordering off of (does not need to contain all apps/models)
    # "hide_models": ["auth","orm.UserProfile","orm.ApprovalRequest","orm.RiskAssessment", "orm.Category", "orm.Portfolio",  "orm.IndicatorValueHistory", "orm.RiskScoreHistory" ,"orm.AssessmentHistory","orm.SMTPSetting"],

    # Custom links to append to app groups, keyed on app name
     "custom_links": {
         
        "orm": [  # Replace with your app's name
            #  {
            #     "name": "HeatMaps", 
            #     "url": "interactive_heatmap",  # URL name must match the one in urls.py
            #     "icon": "fas fa-chart-area",  # Optional: Add an icon
            #     "permissions": ["orm.view_risk"]
            # },
            
            # {"name": "METABASE", "url": "http://173.19.2.177:3000", "icon": "fas fa-database","new_window": True},
            # {"name": "Report", "url": "http://ermapp.avax.gr/generate_annual_report/", "icon": "fas fa-file-word","new_window": True, "permissions": ["orm.can_view_reports"]},
            # {"name": "Report GR", "url": "http://localhost:8000/generate_annual_report_gr/", "icon": "fas fa-file-word","new_window": True, "permissions": ["orm.can_view_reports"]},
            # {"name": "Presentation GR", "url": "http://ermapp.avax.gr/generate-presentation/", "icon": "fas fa-file-powerpoint","new_window": True, "permissions": ["orm.can_view_reports"]},

         
        ],
    },

    
    # Custom icons for side menu apps/models See https://fontawesome.com/icons?d=gallery&m=free&v=5.0.0,5.0.1,5.0.10,5.0.11,5.0.12,5.0.13,5.0.2,5.0.3,5.0.4,5.0.5,5.0.6,5.0.7,5.0.8,5.0.9,5.1.0,5.1.1,5.2.0,5.3.0,5.3.1,5.4.0,5.4.1,5.4.2,5.13.0,5.12.0,5.11.2,5.11.1,5.10.0,5.9.0,5.8.2,5.8.1,5.7.2,5.7.1,5.7.0,5.6.3,5.5.0,5.4.2
    # for the full list of 5.13.0 free icon classes
    "icons": {
        "auth": "fas fa-users-cog",
        "auth.user": "fas fa-user",
        "auth.Group": "fas fa-users",
        "orm.Risk": "fas fa-exclamation-triangle",
        "orm.Action": "fas fa-bolt",
        "orm.RiskAssessment": "fas fa-balance-scale",
        "orm.userprofile": "fas fa-id-card",
        "orm.Procedure": "fas fa-table",
        "orm.Event": "fas fa-bell",
        "orm.Mitigation": "fas fa-shield-alt",
        "orm.approvalrequest": "fas fa-check-double",
        "orm.Indicator": "fas fa-chart-line",
        "orm.category": "fas fa-list",
        "orm.portfolio": "fas fa-briefcase",
        "orm.indicatorvaluehistory":"fas fa-clock",
        "orm.riskscorehistory":"fas fa-clock",
    
        "orm.Opportunity":"fas fa-star",
    
        "orm.SMTPSetting":"fas fa-envelope",

        "orm.AssessmentHistory":"fas fa-clock",
        "orm.itasset":"fas fa-desktop",
        "orm.StandardControl":"fas fa-clipboard",
        "orm.PortfolioControlStatus":"fas fa-thumbs-up",

        "orm.duediligenceassessment":"fas fa-clipboard",
        "orm.kycstandard":"fas fa-list",
        "orm.counterparty":"fas fa-users",
    },
    # Icons that are used when one is not manually specified
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",

    "custom_js": None ,  # Ensure this is the correct path without any brackets or quotes

    
    # "custom_css": "css/custom_admin.css",

    #################
    # Related Modal #
    #################
    # Use modals instead of popups
    "related_modal_active": False,

    #############
    # UI Tweaks #
    #############
    # Relative paths to custom CSS/JS scripts (must be present in static files)
    # "custom_css": "css/custom_admin.css",  # Link to your custom CSS file

    # Whether to link font from fonts.googleapis.com (use custom_css to supply font otherwise)
    "use_google_fonts_cdn": True,
    # Whether to show the UI customizer on the sidebar
    "show_ui_builder": False,

    ###############
    # Change view #
    ###############
    # Render out the change view as a single form, or in tabs, current options are
    # - single
    # - horizontal_tabs (default)
    # - vertical_tabs
    # - collapsible
    # - carousel
    "changeform_format": "horizontal_tabs",
    # override change forms on a per modeladmin basis
    "changeform_format_overrides": {"orm.duediligenceassessment":"single","auth.user": "collapsible", "auth.group": "vertical_tabs"},
    
  

    


}
JAZZMIN_UI_TWEAKS = {
    "navbar_small_text": False,
    "footer_small_text": True,
    "body_small_text": False,
    "brand_small_text": False,
    "brand_colour": "navbar-navy",
    "accent": "accent-primary",
    "navbar": "navbar-primary navbar-dark",
    "no_navbar_border": False,
    "navbar_fixed": True,
    "layout_boxed": False,
    "footer_fixed": False,
    "sidebar_fixed": False,
    "sidebar": "sidebar-dark-navy",
    "sidebar_nav_small_text": False,
    "sidebar_disable_expand": True,
    "sidebar_nav_child_indent": False,
    "sidebar_nav_compact_style": False,
    "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": False,
    "theme": "default",
    "dark_mode_theme": None,
    "button_classes": {
        "primary": "btn-primary",
        "secondary": "btn-secondary",
        "info": "btn-info",
        "warning": "btn-warning",
        "danger": "btn-danger",
        "success": "btn-success"
    },
    "actions_sticky_top": True
}