from django.urls import re_path
from django.views.generic.base import RedirectView

from . import views


app_name = "parsing"

urlpatterns = [
    re_path(r'^$', views.index, name='index'),
    re_path(r'^upload/$', views.upload),

# orignal 



# openvas 

    re_path(r'^openvas_scan_index/$', views.openvas_scan_index, name="openvas_scan_index"),
    # redirect legacy/bookmarked index.html to the canonical openvas_scan_index (301)
    re_path(r'^openvas_scan_index/index.html$', RedirectView.as_view(url='/openvas_scan_index/', permanent=True)),
    re_path(r'^openvas_ip_detailed/(?P<id>\d+)/$', views.openvas_ip_detailed,name="openvas_ip_detailed"),
    re_path(r'^openvas_ajx/$', views.openvas_scan_luncher),
    re_path(r'^openvas_2nmap_ip_ajax/$', views.openvas_nmap2scan_luncher),

    re_path(r'^openvas_report/(?P<host_id>\d+)/$', views.vulnerability_report,name="openvas_report"),

    re_path(r'^nm_scan_index/$', views.nm_scan_index,name="nm_scan_index"),
    re_path(r'^nm_ip_detailed/(?P<id>\d+)/$', views.nm_ip_detailed,name="nm_ip_detailed"),
    # nmap ajax endpoint: point to nm_scan_index (nm_scan_luncher not present in views)
    re_path(r'^nmap_ajx/$', views.nm_scan_index),

#     # url(r'^nm_ip_detail/(?P<id>\d+)/$', views.nm_ip_detail,name="nmdetail"),


# # Metasoloit 

    re_path(r'^msf/(?P<id>\d+)/$', views.msf_exploit,name="msf"),
    re_path(r'^msf_exploit_ajx/$', views.msf_exploit_vulnerability,name="msf_exploit_vulnerability"),
    re_path(r'^msf_exploit_config_ajx/$', views.msf_exploit_config_ajx,name="msf_exploit_config_ajx"),
    re_path(r'^msf_config/(?P<id>\d+)/$', views.exploit_config,name="msf_config"),
    #url(r'^msf/(?P<id>\d+)/$', views.msf_exploit,name="msf"),

    re_path(r'^msf_session/(?P<id>\d+)/$', views.msf_session,name="msf_session"),
    re_path(r'^msf_session_status_check_ajax/$', views.msf_session_status_check_ajax,name="msf_session_status_check_ajax"),

    re_path(r'^msf_session_intract/(?P<session_id>\w+)/(?P<host_id>\w+)/(?P<uuid>\w+)/$', views.msf_session_intract, name='msf_session_intract'),
    re_path(r'^msf_session_intract_ajx/$', views.msf_session_intract_ajx, name='msf_session_intract_ajx'),

# connection 

    re_path(r'^msf_rpc_connect/$', views.msf_rpc_connect, name='msf_rpc_connect'),
    re_path(r'^msf_rpc_connect/$', views.msf_rpc_connect, name='msf_rpc_connect'),

# Report

    re_path(r'^report/$', views.report,name='report_index'),

    re_path(r'^report_view/(?P<id>\d+)/$', views.report_view,name='report_view'),
    re_path(r'^report_download/(?P<id>\d+)/$', views.report_download,name='report_download'),
    re_path(r'^report_overview/(?P<id>\d+)/$', views.report_overview,name='report_overview'),



]

 # 
  



