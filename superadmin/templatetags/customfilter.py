from django.db import connection
from django import template

register = template.Library()
@register.filter(name="table")
def tables():
    table = []
    tables = connection.introspection.table_names()
    seen_models = connection.introspection.installed_models(tables)
    for i in seen_models:
        table.append(i)
    return table