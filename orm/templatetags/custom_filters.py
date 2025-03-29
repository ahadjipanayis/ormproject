# custom_filters.py
from django import template

register = template.Library()
@register.filter
def sum_list_lengths(dict_of_lists):
    return sum(len(lst) for lst in dict_of_lists.values())

@register.filter
def getattr(obj, attr_name):
    """
    Gets an attribute of an object dynamically in templates.
    Usage: {{ object|getattr:"attribute_name" }}
    """
    try:
        return getattr(obj, attr_name)
    except AttributeError:
        return None

@register.filter
def replace(value, args):
    """
    Replaces characters in a string. Syntax: {{ value|replace:"old,new" }}
    """
    old, new = args.split(',')
    return value.replace(old, new)

# In your templatetags folder, create a file `custom_filters.py`

from django import template

register = template.Library()

@register.filter
def get_field_value(obj, field_name):
    try:
        return getattr(obj, field_name)
    except AttributeError:
        return None
from django import template

register = template.Library()

@register.filter
def get_model_fields(obj):
    """
    Returns a dictionary of all fields and their values for a model instance.
    """
    if obj:
        return {field.name: getattr(obj, field.name) for field in obj._meta.get_fields()}
    return {}

from django import template

register = template.Library()


register = template.Library()

@register.filter
def custom_get_item(dictionary, key):
    """Returns the value for the given key from a dictionary."""
    return dictionary.get(key)


import hashlib
from django import template

register = template.Library()

@register.filter
def md5(value):
    """Returns the MD5 hash of a given string."""
    if value:
        return hashlib.md5(value.encode('utf-8')).hexdigest()
    return ''

@register.filter
def get_item(dictionary, key):
    """Retrieve a value from a dictionary by its key."""
    if isinstance(dictionary, dict):
        return dictionary.get(key, 0)
        print("Custom filters loaded successfully.")

    return 0


@register.filter
def add_days(date_value, days):
    """Adds a specified number of days to a given date."""
    return date_value + timedelta(days=int(days))

@register.filter
def countdown_days(target_date):
    """Returns the countdown in days as an integer, including negative values for overdue tasks."""
    if not target_date:
        return None

    today = date.today()
    return (target_date - today).days  # Directly return the day difference
@register.filter
def reverse(value):
    """Reverses a list or range."""
    try:
        return value[::-1]
    except TypeError:
        return value



@register.filter
def abs(value):
    return abs(int(value))





