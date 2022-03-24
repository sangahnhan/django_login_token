from django.db import models

from cores.models import TimeStampModel

class User(TimeStampModel):
    name         = models.CharField(max_length=100)
    email        = models.CharField(max_length=100 , unique=True)
    password     = models.CharField(max_length=200)
    phone_number = models.IntegerField()
    etc_info     = models.CharField(max_length=500 , null=True)

    class Meta:
        db_table = 'users'