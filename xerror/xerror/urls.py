
from django.urls import re_path, include
from django.contrib import admin
from . import settings
from django.views.static import serve

urlpatterns = [
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^', include('parsing.urls')),
    re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),

]



