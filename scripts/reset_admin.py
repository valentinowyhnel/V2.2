"""Reset or create the Django superuser 'admin' with a known password.

Run this via the project manage.py shell like:
    python3 xerror/manage.py shell < scripts/reset_admin.py

It will create a superuser named 'admin' with password 'XerrorAdmin!2025'
or update the existing user's password.
"""
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'xerror.settings')

import django
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()
USERNAME = 'admin'
PASSWORD = 'XerrorAdmin!2025'

try:
    user = User.objects.filter(username=USERNAME).first()
    if user:
        user.set_password(PASSWORD)
        user.is_staff = True
        user.is_superuser = True
        user.save()
        print(f"Updated password for existing superuser: {USERNAME}")
    else:
        User.objects.create_superuser(USERNAME, email='admin@example.local', password=PASSWORD)
        print(f"Created new superuser: {USERNAME}")
except Exception as e:
    print('ERROR:', e)
    sys.exit(2)
