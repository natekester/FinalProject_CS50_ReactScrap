from django.db import models
from django.db import models
from django.utils import timezone

#user model: user, password(Hashed -bicrypt)

#permissions model: user(PK), permission level
#
#cache update table for data: time, current iteration
#
# model for scrap data: including time of creation, user created, total cost, units impacted,
# cost per unit (at time of creation of scrap),
#  failure cause (foreign key), product id (foreign key), open/closed
#
# I want a Failure cause table: prod id (FK), Failure cause 
#
#product id: id #, description, cost per unit, date updated, user who updated
#
#



class User(models.Model):
    username = models.CharField(max_length=32)
    password = models.CharField(max_length=64) #this will be hashed with bycrypt


class ProductId(models.Model):
    prod_id = models.CharField(max_length=32)
    description = models.CharField(max_length=128)
    unit_cost = models.DecimalField(max_digits=10, decimal_places=2)
    unit = models.CharField(max_length=32)
    date_updated = models.DateTimeField(default = timezone.now)
    updating_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='updating_user')


class FailureCause(models.Model):
    product = models.ForeignKey(ProductId, on_delete=models.CASCADE, related_name='product')
    failure_mode = models.CharField(max_length=32)

class Scrap(models.Model):
    time = models.DateTimeField(default = timezone.now)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scrap_user')
    total_cost =  models.DecimalField(max_digits=10, decimal_places=2)
    units_scrapped = models.IntegerField()
    prod_id = models.ForeignKey(ProductId, on_delete=models.CASCADE)
    failure = models.ForeignKey(FailureCause, on_delete=models.CASCADE, related_name='failure')
    is_open = models.BooleanField(default=True)
    lot_id = models.CharField(default="p00000", max_length=32)

class CacheToken(models.Model):
    current_rendition = models.CharField(max_length=128)
    
class RefreshToken(models.Model):
    token = models.CharField(max_length=128)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    time_created = models.DateTimeField(default = timezone.now)

# Might be good to have a table tracking closure and comments.

class ClosedScrapComments(models.Model):
    scrap = models.ForeignKey(Scrap, on_delete=models.CASCADE)
    comment = models.CharField(max_length=128)








    




