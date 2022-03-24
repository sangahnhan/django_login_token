import re

from django.core.exceptions import ValidationError

from users.models import User

EMAIL_REGEX    = '^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
PASSWORD_REGEX = '^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'

def validate_email(email):
    if not re.match(EMAIL_REGEX,email):
        raise ValidationError('EMAIL_FORMAT_ERROR')
def check_email_duplication(email):
    if User.objects.filter(email = email).exists():
        raise ValidationError('EMAIL_DUPLICATE_ERROR')
def validate_password(password):
    if not re.match(PASSWORD_REGEX,password):
        raise ValidationError('PASSWORD_FORMAT_ERROR')