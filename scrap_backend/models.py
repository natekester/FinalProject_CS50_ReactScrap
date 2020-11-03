from django.db import models


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