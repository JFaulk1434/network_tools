from django.urls import path

from . import views

app_name = 'netscan'
urlpatterns = [
    path('', views.index, name='index'),
]
