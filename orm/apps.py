# orm/apps.py
from django.apps import AppConfig

class OrmConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'orm'

    def ready(self):
        # Import signals to ensure they're registered when the app is ready
        import orm.signals

# orm/apps.py
from django.apps import AppConfig

class OrmConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'orm'

    def ready(self):
        import orm.signals  # Import signals when the app is ready