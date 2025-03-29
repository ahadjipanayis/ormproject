# orm/templatetags/orm_tags.py
from django import template

register = template.Library()

@register.filter
def sum_list_lengths(dict_of_lists):
    return sum(len(lst) for lst in dict_of_lists.values())