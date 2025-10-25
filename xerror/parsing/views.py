import json
import os
import time
import urllib.request, urllib.error, urllib.parse

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.core.exceptions import ObjectDoesNotExist
from django.core.files.base import ContentFile
from django.shortcuts import redirect

try:
    from metasploit.msfrpc import MsfRpcClient
except ImportError:
    print("[Error] msfrpc non disponible. Veuillez installer la bibliothèque msfrpc.")
    MsfRpcClient = None

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from xerror.settings import BASE_DIR
from .models import TextFile, Job, Config_exploit, Exploiated_system, MSF_rpc_connection, openvas_connection
from .tasks import process_file, process_ip_vul, process_nmap, process_exploitation, process_session_check, process_session_interact
from .nm_csv_parser import nmcsvpar
from .mapper_cve_exploit import mapper_opn2msf_cve
from .opv_csv_parser import openvas_csv_parse_detail

from django.http import FileResponse, Http404
from PyPDF2 import PdfFileMerger
from django.template.loader import render_to_string
import pdfkit

# Example refactor: Replace Python 2 print statements with Python 3 syntax
# and ensure file handling uses UTF-8 encoding.

def index(request):
    """
    First it checks MSFrpcd connection before redirecting to the dashboard.
    """
    if MsfRpcClient is None:
        print("[Error] MsfRpcClient not available. Ensure pymetasploit3 is installed.")
        return render(request, 'msf_login.html')

    try:
        msf_credentials = MSF_rpc_connection.objects.get(pk=1)
        msf_pass = msf_credentials.rpc_pass
        msf_ip = msf_credentials.rpc_ip

        client = MsfRpcClient(msf_pass, host=msf_ip, port=55553, ssl=False)
        print("[MSF] Rpc server connected.")
    except Exception as e:
        print(f"[Error] MSF connection failed: {e}")
        return render(request, 'msf_login.html')

    job = Job.objects.all()

    total_jobs = job.count()
    total_scans = job.filter(nm_status='Nmap_scan_completed').count()
    total_vul_scans = job.filter(vul_status='OpenVass Vul scan completed ').count()
    total_sessions = Config_exploit.objects.all().count()
    total_exploits = Exploiated_system.objects.all().count()

    print("[Index] Project index loaded.")
    return render(request, 'index.html', {
        "job": job,
        "total": total_jobs,
        "scn": total_scans,
        "vscn": total_vul_scans,
        "exploit": total_exploits,
        "session": total_sessions
    })


def handle_file(file):
    """Get temporary uploaded file and write it into 'project/upload/' dir.

    Returns:
        tuple -- file path, file name
    """
    destination = BASE_DIR + '/upload/' + file.name
    with open(destination, 'wb+') as dest:
        for chunk in file.chunks():
            dest.write(chunk)
    return (destination, file.name)


@csrf_exempt
def upload(request):
    """Upload function.

    Take ajax request, handle file, save it to db,
    send websocket message to client for table change,
    then start 'process_file' celery task.

    Decorators:
        csrf_exempt

    Returns:
        json -- don't need it.
    """

    if request.is_ajax():
        data = {}
        destination, name = handle_file(list(request.FILES.values())[0])
        textfile = TextFile()
        textfile.name = name
        textfile.file = destination
        textfile.save()
        
        # Envoi du message via les Channel Layers
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            'pool',
            {
                "type": "chat.message",
                "action": "uploaded",
                "file_id": list(request.FILES.keys())[0],
                "new_file_id": textfile.id,
            }
        )
        
        try:
            process_file.delay(textfile.id)
        except Exception as e:
            print(f"[task] process_file.delay failed: {e}. Running synchronously.")
            try:
                process_file.run(textfile.id)
            except Exception as e2:
                print(f"[task] process_file.run also failed: {e2}")
        data = {'msg': 'Success'}
    else:
        data = {'msg': 'Failed'}
    return JsonResponse(data)

# ******************** report
# /root/Videos/finlazation/xerror/templates/report/report_view.html

def report(request):
    job = Job.objects.all()
    print(" [ index ] project report \n\n\n\n ")
    return render(request, 'report/report_index.html',{"job":job })


def exploit_mapper_report(ip,id):
    try:
        pass
        opv_csv_file_name = BASE_DIR + '/reports/openvas/opv_'+str(id)+"_"+ip+"/csv/"+ip+".csv"
        ms_cve2exploit_File    = BASE_DIR+'/parsing/msf_module_result/msf_module_cve.txt'
        with open(opv_csv_file_name) as f:
            pass
        obj = mapper_opn2msf_cve(opv_csv_file_name,ms_cve2exploit_File)
        mapping_dict =  obj.mapper()

        temp_dict = {}
        for k,v in list(mapping_dict.items()):
            if k != "ip":
                temp_dict[k] = v
        # return {'CVE-2007-2447': ['CVE-2007-2447', '445', 'tcp', 'Medium', 'exploit/multi/samba/usermap_script'], 'CVE-2004-2687': ['CVE-2004-2687', '3632', 'tcp', 'High', 'exploit/unix/misc/distcc_exec']}
        return temp_dict


    except Exception as e:
        raise e



def report_overview(request,id):
    filename    = BASE_DIR + '/templates/report/overview_report.html' 
    desti       = BASE_DIR + '/templates/report/overview.pdf' 
    temp_page   = BASE_DIR + '/templates/report/temp.html' 
    print("**************")
    try:
        job = Job.objects.get(pk=id)

        # exploit start
        exploit_mapped = exploit_mapper_report(job.name,job.id)
        # exploit section


        # scan start
        ro,host,os,ip_addr= scn_parser_report(job.id,job.name)
        if ro:
            scn_data  = ro 
        else:
            scn_data = "file not found"
        # end scaning


        # vul scanning
        resul_table =  vscn_parser_reort(job.id,job.name)
        vscn_err = False
        if resul_table:
            vscn_err = True

        # end vul scanning


        # pdf report generatoin "date":job.created,
        rendered_page =  render_to_string('report/overview_report.html',{"resul_table":resul_table,"vscn_err":vscn_err,"ro":scn_data,"date":job.created ,"host_name":job.name,"host_id":id,"mapped":exploit_mapped,"d":desti,"base":BASE_DIR})
        f = open(temp_page,'wb')
        f.write(rendered_page.encode("UTF8"))
        f.close()
        print("succcess")

        pdfkit.from_file(temp_page, desti)    
        
    except Exception as e:
        print("[ overview_report ] Requested Object not foud ")
        obj_err = 'Requested Object not foud'
        return render(request, 'report/report_view.html', {'ro':obj_err})

    try:
        pdf_path  = BASE_DIR + '/templates/report/overview.pdf'
        return FileResponse(open( pdf_path, 'rb'), content_type='application/pdf')
    except :
        raise Http404()

    # return render(request, 'report/overview_report.html',{"s":filename,"d":desti})

def vscn_parser_reort(id,ip):
    try:
        opv_csv_file_name = BASE_DIR + '/reports/openvas/opv_'+str(id)+"_"+ip+"/csv/"+ip+".csv"
        with open(opv_csv_file_name) as f:
            pass 
        print(" [ report ] Opv ip address found  ")
        obj = openvas_csv_parse_detail(opv_csv_file_name)
        resul_table,ip   = obj.opv_resul_table() 
        print("*******************88 opv table")
                # print resul_table
        return resul_table
        
    except Exception as e:
        return False

def scn_parser_report(id,ip):

    try:
        csvname = "csv_"+str(id)+"_"+ip+".csv"
        filename = BASE_DIR + '/reports/' + csvname
        with open(filename) as f:
            pass 
        ro,host,os,ip_addr= nmcsvpar(filename)
        return ro,host,os,ip_addr
    except Exception as e:
        return False



def report_view(request, id):
    """Display report summary for a Job (scanning + vuln results + mapped exploits).

    This simplified implementation tries to gather existing scan and vuln
    parsing results using helper functions and renders the report view.
    """
    try:
        job = Job.objects.get(pk=id)
    except Job.DoesNotExist:
        return render(request, 'report/report_view.html', {'ro': 'Requested Object not found'})

    # scanning (nmap csv) parsing
    scn_data = None
    try:
        scn_res = scn_parser_report(job.id, job.name)
        if scn_res:
            scn_data = scn_res
    except Exception:
        scn_data = None

    # vulnerability (openvas) parsing
    resul_table = None
    try:
        resul_table = vscn_parser_reort(job.id, job.name)
    except Exception:
        resul_table = None

    # session extraction
    session_tractor = False
    temp_dict = {}
    try:
        session = Exploiated_system.objects.filter(host_id=id)
        host_ipd, host_idd, cve, temp_dict = session_exptractor(session)
        if cve:
            session_tractor = True
    except Exception:
        session_tractor = False

    # exploit mapping
    exploit_mapped = exploit_mapper_report(job.name, job.id)

    return render(request, 'report/report_view.html', {
        "mapped": exploit_mapped,
        "session_tractor": session_tractor,
        "sessions": temp_dict,
        'resul_table': resul_table,
        'ro': scn_data,
        "host": job.name,
        "os": "",
        "ip_addr": job.name,
        "host_id": str(id),
        "mac": "B0:4E:26:4D:40:28",
    })


def report_download(request, id):
    """Return a merged PDF of the landing page + the OpenVAS PDF result for a job.
    This is a simplified implementation that attempts to merge two PDFs and return
    the resulting file as a FileResponse.
    """
    try:
        job = Job.objects.get(pk=id)
        host_id = job.id
        ip = job.name

        result_dir = BASE_DIR + '/reports/openvas/opv_' + str(host_id) + '_' + ip + '/pdf/' + ip + '.pdf'
        base_page = BASE_DIR + '/templates/report/landing_page.pdf'
        destination = BASE_DIR + '/templates/report/generic_report.pdf'

        merger = PdfFileMerger()
        for pdf in [base_page, result_dir]:
            merger.append(pdf)
        merger.write(destination)
        merger.close()

        return FileResponse(open(destination, 'rb'), content_type='application/pdf')
    except Exception:
        obj_err = "Requested Object Not found"
        return render(request, 'report/report_err.html', {'repo_err': obj_err})




     



# ****************************** msf


@csrf_exempt
def msf_rpc_connect(request):

    if request.method == "POST":
        try:
            msf = MSF_rpc_connection.objects.get(pk=1)
            msf.rpc_uname  = request.POST['rpc_uname']
            msf.rpc_pass = request.POST['rpc_pass']
            msf.rpc_ip= request.POST['rpc_ip']
            msf.save()


        except Exception as e:
            print("[ MSF ] MSF exception ")
            msf = MSF_rpc_connection()
            msf.rpc_uname  = request.POST['rpc_uname']
            msf.rpc_pass = request.POST['rpc_pass']
            msf.rpc_ip= request.POST['rpc_ip']
            msf.save()
            
        job = Job.objects.all()

        total_         =  job.count()
        total_scn      = job.filter(nm_status='Nmap_scan_completed').count()
        total_vscn     = job.filter(vul_status='OpenVass Vul scan completed ').count()
        total_sessions = Config_exploit.objects.all().count()
        total_exploit  = Exploiated_system.objects.all().count()

        # print total_
        # print total_scn
        # print total_vscn
        # print total_sessions
        # print total_exploit

        print(" [ index ] project index \n\n\n\n ")
        return render(request, 'index.html',{"job":job,'total':total_ , 'scn':total_scn , 'vscn':total_vscn,'exploit':total_exploit , 'session':total_sessions  })


  
        print("[ MSF ] MSF credientials saved successfully ")
        # redire = nm_scan_index(request)
        # return redire
        return render(request, 'index.html')
    else:
        return render(request, 'msf_login.html')



@csrf_exempt    
def opv_rpc_connect(request):

    if request.method == "POST":
        try:
            opv = openvas_connection.objects.get(pk=1)
            opv.opv_uname  = request.POST['opv_uname']
            opv.opv_pass = request.POST['opv_pass']
            opv.opv_ip= request.POST['opv_ip']
            opv.save()

        except Exception as e:
            print("[ opv ] opv exception ")
            opv = openvas_connection()
            opv.opv_uname  = request.POST['opv_uname']
            opv.opv_pass = request.POST['opv_pass']
            opv.opv_ip= request.POST['opv_ip']
            opv.save()

        print("[ opv ] openvas credientials saved successfully ")
        # redire = nm_scan_index(request)
        # return redire
        # return render(request, 'nmap/nmap_scan2.html', {'files': files,"job":job })
    else:
        return render(request, 'msf_login.html')





















# ******************************************* msf exploit ********************

# *********************** session
@csrf_exempt
def msf_session_intract_ajx(request):

    if request.is_ajax():
        data = {}

        print("\n\n\n\n ************************* Msf rhost shell command launcher ***************")
        form_data_collector = dict(request.POST)
        lst = form_data_collector["rhost_cmd"] 
        lst_session = form_data_collector["session_id"] 

        cmd = lst[0]
        cmd = cmd.encode("UTF8")

        session_id = lst_session[0]
        session_id = session_id.encode("UTF8")

        print("[ SESSION_INTERACT ] Given Command to Execute : ",cmd)
        print("[ SESSION_INTERACT ] sesionid  ",session_id)
        print(type(cmd))
        print(form_data_collector)
        print((type(form_data_collector["rhost_cmd"])))
        try:
            process_session_interact.delay(session_id,cmd)
        except Exception as e:
            print(f"[task] process_session_interact.delay failed: {e}. Running synchronously.")
            try:
                process_session_interact.run(session_id,cmd)
            except Exception as e2:
                print(f"[task] process_session_interact.run also failed: {e2}")


        # Envoi du message via les Channel Layers
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            'pool',
            {
                "type": "chat.message",
                "action":"session_interact_"+session_id, 
                "session_interact_response": "\n\n Xerror :/~> "+cmd,
                "check_status": "checking host up status so,keep patience ",
            }
        )
        data = {'msg': 'success '}
        return JsonResponse(data)




# def session_interaction_check(session_id,host_id,uuid):
#     print(" [ SESSION ] Backend session check  process STARTED ")
#     try:
#         client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
#         print ("[ SESSION ] Rpc server connected ")
#     except Exception as e:
#             return "Msf rpc connection not succesfull "
#     else:
#         print ("[ SESSION ] Checking session status  ")
#         session_idd = client.sessions.list 
#         lst = session_idd.keys()
#         session_id = int(session_id)
#         if session_id in lst:
#             return "alive"
#         else:
#             return "dead"



# interact base page
def msf_session_intract(request,session_id,host_id,uuid):

    try:
        print("[ SESSION ]  shell interctation Starts ")
        print(session_id)
        print(host_id)
        print(uuid)
        session_detail = Exploiated_system.objects.get(session_id=session_id,host_id=host_id,exploit_uuid=uuid)
        host_name = session_detail.host_name
        session_type = session_detail.session_type
        shell_tunnel = session_detail.tunnel_peer
        rport = session_detail.exploit_rport
        
        

        print("[ SESSION ] Interact: sesion object found  ")

        resul_dict = {"rhost":host_name,"session_id":session_id ,"rport":rport,"session_type":session_type,"tunnel":shell_tunnel}
        return render(request, 'metasploit/sessions_handler.html', resul_dict)
    except Exception as e:
        print("[ SESSION ] Interact: sesion object not found 404 ")
        ro = "object not found"
        return render(request, 'metasploit/sessions_handler.html', {"objerr":ro}  )


# def msf_session(request,id):
#     """Index page view.
#     id =rhost id
#     Move all textfiles to context.
#     """
#     resul_dict = {}
#     temp_dict = {}
#     name  = ""
#     hid = ""
#     session = Exploiated_system.objects.filter(host_id=id)
#     print "************************* sessoins"
#     for sesion_obj in session:
#         temp_detail_dict ={}
#         temp_detail_dict['host_id']          =  sesion_obj.host_id.encode("UTF8")
#         temp_detail_dict['host_name']        =  sesion_obj.host_name.encode("UTF8")
#         temp_detail_dict['rport']           =  sesion_obj.exploit_rport.encode("UTF8")
#         temp_detail_dict['cve']             =  sesion_obj.cve_number.encode("UTF8")
#         temp_detail_dict['exploit_name']     =  sesion_obj.exploit_name.encode("UTF8")
#         temp_detail_dict['payload_name']     =  sesion_obj.payload_name.encode("UTF8")
#         temp_detail_dict['exploited']       =  sesion_obj.exploited.encode("UTF8")
#         temp_detail_dict['session_id']      =  sesion_obj.session_id.encode("UTF8")

#         if sesion_obj.exploit_uuid:
#             temp_detail_dict['exploit_uuid']     =   sesion_obj.exploit_uuid.encode("UTF8") 
#             temp_detail_dict['session_type']     =  sesion_obj.session_type.encode("UTF8")
#             temp_detail_dict['tunnel_peer']     =  sesion_obj.tunnel_peer.encode("UTF8")
#             temp_dict[sesion_obj.session_id.encode("UTF8")]  = temp_detail_dict
#         else:
#             temp_detail_dict['exploit_uuid']     =  "no uuid" 
#             temp_detail_dict['session_type']     =  "no sesstion type"
#             temp_detail_dict['tunnel_peer']     =  "no tunnel"
#             temp_dict[sesion_obj.session_id.encode("UTF8")]  = "no session"

#             name = sesion_obj.host_name.encode("UTF8")
#             hid  =  sesion_obj.host_id.encode("UTF8"),



#     print temp_dict
#     # resul_dict = {"ip_addr":sesion_obj.host_name.encode("UTF8"),"host_id": sesion_obj.host_id.encode("UTF8"), "sessions":  temp_dict}
#     resul_dict = {"ip_addr":name ,"host_id": hid, "sessions":  temp_dict}
#     return render(request, 'metasploit/sessions.html', resul_dict)


def session_exptractor(session_obj):

    try:
        session = session_obj
        temp_dict = {}

        host_ipd = ''
        host_idd ='' 
        cve  = ""
        print("[ SESSION ] SESSION REQ  RENDERING  ")
        for sesion_obj in session:
            temp_detail_dict ={}
            temp_detail_dict['host_id']          =  sesion_obj.host_id.encode("UTF8")
            temp_detail_dict['host_name']        =  sesion_obj.host_name.encode("UTF8")
            temp_detail_dict['rport']           =  sesion_obj.exploit_rport.encode("UTF8")
            temp_detail_dict['cve']             =  sesion_obj.cve_number.encode("UTF8")
            temp_detail_dict['exploit_name']     =  sesion_obj.exploit_name.encode("UTF8")
            temp_detail_dict['payload_name']     =  sesion_obj.payload_name.encode("UTF8")
            temp_detail_dict['exploited']       =  sesion_obj.exploited.encode("UTF8")
            temp_detail_dict['session_id']      =  sesion_obj.session_id.encode("UTF8")
            temp_detail_dict['exploit_uuid']     =  sesion_obj.exploit_uuid.encode("UTF8")
            temp_detail_dict['session_type']     =  sesion_obj.session_type.encode("UTF8")
            temp_detail_dict['tunnel_peer']     =  sesion_obj.tunnel_peer.encode("UTF8")
            temp_dict[sesion_obj.session_id.encode("UTF8")]  = temp_detail_dict
            
            host_ipd = sesion_obj.host_name.encode("UTF8")
            host_idd = sesion_obj.host_id.encode("UTF8")
            cve  =  sesion_obj.cve_number.encode("UTF8")

        return host_ipd,host_idd,cve,temp_dict
    except Exception as e:
        raise e




def msf_session(request,id):
    """Index page view.
    id =rhost id
    Move all textfiles to context.
    """

    try:
        session = Exploiated_system.objects.filter(host_id=id)


        resul_dict = {}
        host_ipd = ''
        host_idd ='' 
        cve  = ""
        host_ipd,host_idd,cve,temp_dict = session_exptractor(session)



        temp_ = "none"
        if cve != '':
            temp_ = 'exist'


        resul_dict = {"ip_addr":host_ipd,"host_id": host_idd, "flag":temp_, "sessions":  temp_dict}
        return render(request, 'metasploit/sessions2.html', resul_dict)

    except Exception as e:
        ro = "object not sound"
        return render(request, 'metasploit/sessions2.html', {"objerr": ro})









@csrf_exempt
def msf_session_status_check_ajax(request):

    '''
        Ths funcion checks the exploited RHOST sessions
    '''
    if request.is_ajax():
        print(" [ SESSION ] SESSION STATUS CHEECK ")

        session_data_collector = dict(request.POST)
        print(type(session_data_collector))
        key= list(session_data_collector.keys())
        key= key[0].encode("UTF8")
        # This key dont have any value 
        id_lst = key.split("?")
        print(id_lst)

        session_id = id_lst[0]
        host_id    = id_lst[1]
        expl_uuid    = id_lst[2]

        print(" [ SESSION ] sending SESSION STATUS CHEECK req to background process ")
        try:
            process_session_check.delay(session_id,host_id,expl_uuid)
        except Exception as e:
            print(f"[task] process_session_check.delay failed: {e}. Running synchronously.")
            try:
                process_session_check.run(session_id,host_id,expl_uuid)
            except Exception as e2:
                print(f"[task] process_session_check.run also failed: {e2}")
        print(session_id)
        print(host_id)
        print(expl_uuid)
        # Envoi du message via les Channel Layers
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            'pool',
            {
                "type": "chat.message",
                "action": "session_status_checking",
                "session_current_status":  "Xerror@W11 #:~> Checking sessoin",
                "session_status":  "Checking",
                "session_id": session_id,
                
                   }
               )

        data = {'msg': "Checking session  " }
        return JsonResponse(data)
    else:
        data = {'msg': 'Failed'}
        return JsonResponse(data)







def msf_exploit(request,id):

    '''
        This module map exploits based on cve scanned in phase 2
        Vulnerability scan shoud be completed and csv file should be present   
        It uses msf exploit list for mapping and file is present in project with the name msf_module_cve.txt

    '''

    print("\n\n\n\n [ Exploit ] MSF IP Exploit Result req recived ")
    try:
        job = Job.objects.get(pk=id)
        print(" [ Exploit ] MSF IP objec found  ")


        try:
            opv_csv_file_name = BASE_DIR + '/reports/openvas/opv_'+id+"_"+job.name+"/csv/"+job.name+".csv"
            ms_cve2exploit_File    = BASE_DIR+'/parsing/msf_module_result/msf_module_cve.txt'
            with open(opv_csv_file_name) as f:
                pass 
            # with open(ms_cve2exploit_File) as d:
            #     pass 

            print(" [ Exploit ] Starting Maping process")

            '''
                mapper_cve_exploit.py file contains the mapper script and it req vulnerability scan 
                csv file and msf exploit txt file 

                mapper_opn2msf_cve is a class and it returns their obj and mapper is its fun 

                msf exploit file is generate using following cmd in py or direct terminal
                python script :
                            test = subprocess.Popen(["ruby","/usr/share/metasploit-framework/tools/modules/module_reference.rb","-t","CVE", "-o", "/root/Desktop/celery_setup.txt/dj_file_upload/hicarser/msf_module_result/msf_module_cve.txt"], stdout=subprocess.PIPE)
                            output = test.communicate()[0]
                terminal cmd :
                         ruby /usr/share/metasploit-framework/tools/modules/module_reference.rb -t CVE -o  <<project dir>>/msf_module_cve.txt

            '''
            obj = mapper_opn2msf_cve(opv_csv_file_name,ms_cve2exploit_File)
            mapping_dict = obj.mapper()
            print("*"*65)
            mapper_key_lst  =  list(mapping_dict.keys())

            resul_dict = {}
            host_ip    = ''
                                    
            for k in mapper_key_lst:
                if k == 'ip':
                    host_ip = mapping_dict[k]
                    print("ip address :" , k) 
                else:
                    resul_dict[k] = mapping_dict[k]
                    print(mapping_dict[k])
            print(" [ Exploit ] Maping process completed  ")

            print("*"*65)



            mapped = { 'ip': host_ip, "cve_detail":resul_dict }
            resul = {'ip': host_ip,"id":id, 'mapped': resul_dict }

            print(" [ Exploit ] Rendering and sending result   ")
            # return render(request, 'metasploit/msf_exploit.html', resul)
            return render(request, 'metasploit/msf_exploit2.html', resul)

        except IOError as ObjectDoesNotExist :
            ro = 'file not found'
            print(" [ Exploit ] MSF IP Exploit Result file not Found 404  \n\n\n\n ")
            return render(request, 'metasploit/msf_exploit2.html', {'objerr':ro})
            # return render(request, 'metasploit/msf_exploit.html', {'ro':ro})
    except Exception as e:
        print(" [ Exploit ] Requested Object not Found 404  \n\n\n\n ")
        ro = 'Requested Object not found'
        return render(request, 'metasploit/msf_exploit2.html', {'objerr':ro})


# **************** sample 
    # a= mapper_opn2msf_cve(opv,ms)
    # mapping_dict =  a.mapper()
    # print "*"*65
    # mapper_key_lst  =  mapping_dict.keys()

    # resul_dict = {}
    # host_ip    = ''

    # for k in mapper_key_lst:
    #     if k == 'ip':
    #         host_ip = mapping_dict[k]
    #         print "ip address :" , k 
    #     else:
    #         resul_dict[k] = mapping_dict[k]
    #         print mapping_dict[k]

    # print "*"*65
    # files = TextFile.objects.all()
    # job = Job.objects.all()

    # mapped = { 'ip': host_ip, "cve_detail":resul_dict }
    # resul = {'ip': host_ip, 'mapped': resul_dict }

    # return render(request, 'metasploit/msf_exploit.html', resul)

'''
 {{ ip }}<br>
{% for key, value in mapped.items %}
    ******************************************<br>
    <!-- <dt>{{ key }}</dt> -->
    <!-- <dd>{{ value }}</dd> -->
    <!-- <br> cve <br> -->
    {% if key == ip %}
         <!-- {{key }} -->
    {%else%}
                {% for j in value %}
             {{ j }}
            <!-- <br> -->
        {% endfor %}

    {% endif %}
    <br>
{% endfor %}

'''



# __________________________ exploit  section 


def exploit_config(request,id):

    return render(request, 'metasploit/msf_exploit_config.html', {'ro':"sadfsad"})

def exploit_update(request):
    pass

def exploit_detail_extractor(exploit_name):

    try:
        print('[ MSFRPC ] ********************Exploit informaitn ')
        exploit_name = exploit_name.replace(" ","")
        client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
        # time.sleep(1)
        # exploit = client.modules.use('exploit', 'exploit/multi/samba/usermap_script')
        exploit = client.modules.use('exploit',exploit_name)
        # time.sleep(1)
        temp_dict ={} 
        temp_dict['archi']   = exploit.arch[0]
        temp_dict['authors'] =exploit.authors[0]
        temp_dict['desc']    =exploit.description
        temp_dict['isue_date']    =exploit.disclosuredate
        temp_dict['license']    =exploit.license
        temp_dict['payloads']    =exploit.payloads
        temp_dict['rank']    =exploit.rank
        temp_dict['type']    =exploit.type
        temp_dict['obj']    =exploit
        return  temp_dict
    except Exception as e:
        print("Msf rpc error ")
        return "conneciton_sucks"



def exploit_form_data_extractor(form_data_collector):

        try:

            print('[ extract ] ********************Form Data Recived')
            temp_exploit_dict = {} 
            exploit_data= ''

            for k,v in  list(form_data_collector.items()):
                # keys from request.POST are already strings in Django/Python3
                exploit_data  = str(k)

            exploit_data = exploit_data.replace('[',"")
            exploit_data = exploit_data.replace(']',"")
            exploit_data = exploit_data.replace("'","")
            exploit_data_lst = exploit_data.split(",")
            #extract host db id and cve nimber  
            host_id = exploit_data_lst[0]
            host_id_extrat = host_id.split("?")
            host_id =host_id_extrat[0]
            cve_number = host_id_extrat[1]
            # print host_id
            # print cve_number
            # port      =exploit_data_lst[1]
            # proto     =exploit_data_lst[2]
            # severity  =exploit_data_lst[3]
            # exp_name  =exploit_data_lst[4]
            temp_exploit_dict['cve_number']  =cve_number
            temp_exploit_dict['host_id']  =host_id
            temp_exploit_dict['port']  =exploit_data_lst[1]
            temp_exploit_dict['port']  =exploit_data_lst[1]
            temp_exploit_dict['proto']  =exploit_data_lst[2]
            temp_exploit_dict['severity']  =exploit_data_lst[3]
            temp_exploit_dict['exp_name']  =exploit_data_lst[4]
            print(temp_exploit_dict)
            print('[ extract ] ********************Form Data Sended')

            return temp_exploit_dict

        except Exception as e:
            return "exploit_form_data_parser_sucks"





@csrf_exempt
def msf_exploit_config_ajx(request):

    '''
        This module is used to config exploit, Any AI model is gonna implement hope so i do in future
        This module called through ajax req and it sends data in the form of Form and it uses deux fonction 
        1. exploit_form_data_extractor  to parse comming data from front 
        2.exploit_detail_extractor      will get data related to exploit uisng msfrpc server 

    '''
    if request.is_ajax():
        print("[ exploit_config ] Exploit config req recived")

        form_data_collector = dict(request.POST)
        # data = exploit_form_data_extractor(form_data_collector)
        exploit_form_data  = exploit_form_data_extractor(form_data_collector)
        expl_name = exploit_form_data['exp_name']
        rport = exploit_form_data['port']
        
        

        exploit_detail_dict = exploit_detail_extractor(exploit_form_data['exp_name'])
        exploit_cve_number  = exploit_form_data['cve_number']
        exploit_name        = exploit_form_data['exp_name']

        if exploit_detail_dict  != "conneciton_sucks":

            job          = Job.objects.get(pk=exploit_form_data["host_id"])
            rhost_ip      = job.name
            # ensure we keep a native str type for RHOST
            rhost_ip       = str(rhost_ip)

            archi       =exploit_detail_dict['archi']   
            authors     =exploit_detail_dict['authors']  
            desc        =exploit_detail_dict['desc']    
            isue_date   =exploit_detail_dict['isue_date']    
            license     =exploit_detail_dict['license']    
            payloads    =exploit_detail_dict['payloads']    
            rank        =exploit_detail_dict['rank']    
            type_       =exploit_detail_dict['type']  

            exploit_obj =exploit_detail_dict['obj']  
            exploit_obj['RHOSTS'] = rhost_ip #"172.16.217.128"
            rhosts = exploit_obj['RHOSTS']

            #  save the exoloit configurations to config table
            '''
            job.exploit_config
                job exploit config will track each exploit 
                is configured or not ,, it saves cve to each exploit
                which is confiugred ... wit comma seperated string 

                first split exploit config based on comma and then checks if 
                requeseted string alreadted configured or not 
            '''
            expl_confi_lst = job.exploit_config
            expl_confi_lst = expl_confi_lst.split(",")

            if exploit_cve_number not in expl_confi_lst:
                config                       = Config_exploit()
                config.config_host_name      = rhost_ip
                config.config_host_id        = str(job.id)
                config.config_cve_number     = exploit_cve_number
                config.config_exploit_name   = exploit_name
                config.config_payload_name   = payloads[0]
                config.config_rhost          = rhosts
                config.config_rport          = rport  
                config.save()
                job.exploit_config = job.exploit_config + ","+exploit_cve_number
                job.save()


            # Envoi du message via les Channel Layers
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'pool',
                {
                    "type": "chat.message",
                    "action": "exploiting_config_exploit",
                    "msf_exploit_config_current_status":  "Config working",
                    "name":expl_name,
                    "archi":archi,
                    "authors":authors,
                    "desc":desc,
                    "rport":rport,
                    "license":license,
                    "rank":rank,
                    "type_":type_,
                    "rhosts": rhosts,
                       }
                   )

            for payl in payloads:
                print("payloads sending ")
                async_to_sync(get_channel_layer().group_send)("pool", {
                        "text": json.dumps({
                            "action": "exploiting_config_exploit_payloads",
                            "payloads":payl,

                               })
                           })
            data = {'msg': job.exploit_config+"config Data Sended " }
            return JsonResponse(data)
        else:
            data = {'msg': "Msf Rpc connection not successfull  " }
            return JsonResponse(data)
    else:
        data = {'msg': 'Failed'}
        return JsonResponse(data)

# exploit.missing_required

@csrf_exempt
def msf_exploit_vulnerability(request):
    if request.is_ajax():
        data = {}
        print("[ Exploit ] Exploiation Index Recived request to exploit ***************")
        form_data_collector = dict(request.POST)

        exploit_form_data = exploit_form_data_extractor(form_data_collector)
        exploit_cve_number  = exploit_form_data['cve_number']
        exploit_name        = exploit_form_data['exp_name']

        '''
            it gets the requested ip obj and acquire lock to exploit a single CVE at a time 
            after exploitation it release the lock 
        '''
        job            = Job.objects.get(pk=exploit_form_data["host_id"])
        exploit_lock   = job.exploit_lock
        host_id        = job.id
        expl_confi_lst = job.exploit_config

        expl_confi_lst = expl_confi_lst.split(",")
        print("[ Exploit ] Checking exploit Lock ")
        if exploit_lock == 'no': 
            print("[ Exploit ] Checking if exploit configured or not ")
            print(exploit_lock)

            if exploit_cve_number in expl_confi_lst:
                if exploit_form_data == "exploit_form_data_parser_sucks":
                    async_to_sync(get_channel_layer().group_send)("pool", {
                        "text": json.dumps({
                            "action": "exploiting_remort_host",
                            "msf_exploit_current_status":  "Exploit form data parsing Error ",
                            "job_status": "not running",
                               })
                           })
                    data = {'msg': "not Exploiteed exploit form data error  " }
                    return JsonResponse(data)
                else:
                    # here comes  the exploit baground process 
                    # it get the configuration from config exploit table which is configured previously 
                    config_setting = Config_exploit.objects.get(config_exploit_name=exploit_name,  config_host_id=exploit_form_data["host_id"])
                    config_setting_id = str(config_setting.id)

                    print("[ Exploit ] All set handovering Exploitation process to background procss ")
                    # process_exploitation fun is backgroud celery server function to handle exploit process, it take time to exploit RHOST
                    try:
                        process_exploitation.delay(config_setting_id,host_id)
                    except Exception as e:
                        print(f"[task] process_exploitation.delay failed: {e}. Running synchronously.")
                        try:
                            process_exploitation.run(config_setting_id,host_id)
                        except Exception as e2:
                            print(f"[task] process_exploitation.run also failed: {e2}")
                    job.exploit_lock = "acquired"
                    job.save()

                    async_to_sync(get_channel_layer().group_send)("pool", {
                        "text": json.dumps({
                            "action": "exploiting_remort_host",
                            "msf_exploit_current_status":  "Exploiation Process Started",
                            "job_status": "running",
                            "job_id": exploit_cve_number,
                               })
                           })
                    data = {'msg': str(config_setting.id)+"Yes config check and Exploiteed " }
                    return JsonResponse(data)
            else: 
                    data = {'msg': "Please config the Exploit first1 23   " }
                    return JsonResponse(data)
        else: 
                print("[ Exploit ] Exploit Lock  Acquried ")
                async_to_sync(get_channel_layer().group_send)("pool", {
                        "text": json.dumps({
                            "action": "exploiting_remort_host",
                            "msf_exploit_current_status":  "Already Exploiation Process Running Please till would ened",
                            "job_status": "running",
                            "job_id": exploit_cve_number,
                               })
                           })
                data = {'msg': "Exploit Lock  Acquried for requeseted CVE " }
                return JsonResponse(data)
    else:
        data = {'msg': 'Failed'}
        return JsonResponse(data)















# *************************************** Vulnerability scan ************************************

def openvas_scan_index(request):

    '''
        This Function Loads all Vulnerability scan result to Page
        Pending / completed scans are seperated during randering using jinja2 on front page 

    '''
    print("\n\n\n\n [ v_scn ] Opv index Sending default Result req recived ")

    job = Job.objects.all()
    # return render(request, 'openvas/openvas_scan.html', {"job":job })
    return render(request, 'openvas/openvas_scan2.html', {"job":job })


# show raw report 
def vulnerability_report(request,host_id):
    try:
        '''
            job is a base table in db which holds status and track record to ip 
        '''
        job  = Job.objects.get(pk=host_id)
        host_id = job.id
        ip= job.name

        result_dir =BASE_DIR + '/reports/openvas/' +"opv_"+str(host_id)+"_"+ip+"/html/"+ip+".html"
        desti  = BASE_DIR + '/templates/openvas/reports/generic_report.html'
        print(result_dir)


        with open(desti,"w", encoding='utf-8') as repo:
            repo.write('<div style="margin: 150px;"> <button ><h1><a href="{% url "parsing:openvas_scan_index"  %}"> <- back to Vul scaning </a></h1> </button>')
            with open(result_dir,"r", encoding='utf-8') as f:
                for line in f:
                    repo.write(line)
                    # do whatever you want to
            repo.write('</div>')

        return render(request, 'openvas/reports/generic_report.html')

    except Exception as e:
        raise Http404("Response : Requested object does not exist")


def openvas_ip_detailed(request,id):
    '''
        This fun parse vulnerability scan report and send back parsed report result 
        it req only id  
    '''
    
    try:
        print("\n\n\n\n [ v_scn ] Opv IP Detail Result req recived ")
        job = Job.objects.get(pk=id)
        opv_csv_file_name = BASE_DIR + '/reports/openvas/opv_'+id+"_"+job.name+"/csv/"+job.name+".csv"
        print(" [ v_scn ] Opv ip address found  ")
        try:
            with open(opv_csv_file_name) as f:
                pass 

            '''
                opv_csv_parser.py parse the csv file below openvas_csv_parse_detail is its class instance and it req
                csv file path.
                it returns their object and functin called opv_result_table usedto get result in table form

            '''            
            obj = openvas_csv_parse_detail(opv_csv_file_name)
            print(" [ v_scn ] Opv IP Detail parsig \n\n\n\n ")
            resul_table,ip   = obj.opv_resul_table() 
            # return render(request, 'openvas/openvas_ip_detail.html', {'ro':resul_table,"ip_addr":ip, 'host_id': id.encode("UTF8")})
            return render(request, 'openvas/openvas_ip_detail2.html', {'ro':resul_table,"ip_addr":ip, 'host_id': id.encode("UTF8")})
        except IOError:
            ro = 'file not found'
            print(" [ v_scn ] Opv IP Detail Result file not Found 404  \n\n\n\n ")
            return render(request, 'openvas/openvas_ip_detail2.html', {'ro':ro})
    except Exception as e:
        ro = 'Requested Object not Found'
        print(" [ v_scn ] Requested IP Address dont have object, not Found 404  \n\n\n\n ")
        return render(request, 'openvas/openvas_ip_detail2.html', {'ro':ro})



     



@csrf_exempt
def openvas_nmap2scan_luncher(request):
    # This endpoint intentionally kept for backward compatibility.
    # The real logic for starting an OpenVAS scan from a previous Nmap run
    # is handled elsewhere; keep a thin wrapper that delegates or returns
    # a helpful JSON message.
    data = {'msg': 'Use the Vulnerability Scan page to launch an OpenVAS scan.'}
    return JsonResponse(data)

def opv_serverCon_chacker():

    try:
        urllib.request.urlopen('https://127.0.0.1:9392', timeout=1)
        return True
    except urllib.error.URLError:
        return False



@csrf_exempt
def openvas_scan_luncher(request):

    if request.is_ajax():
        # If OpenVAS server is NOT reachable, abort early with a helpful message
        if not opv_serverCon_chacker():
            async_to_sync(get_channel_layer().group_send)("pool", {
                "type": "chat.message",
                "action": "openvas_host_up_check",
                "check_status": "openvas Server is down, Start the server ",
            })
            data = {'msg': 'Err: openvas Server connection error'}
            return JsonResponse(data)


        data = {}
        print("\n\n\n\n ************************* Vulnerability  Scan launcher ***************")
        form_data_collector = dict(request.POST)
        lst = form_data_collector["host_ip"] 

        ip_address_to_scan = lst[0]
        print(type(ip_address_to_scan))
        if ip_address_to_scan:
            pass
        else:
            ip_address_to_scan = form_data_collector["host_ip"][1]
        # keep ip as string (do not encode to bytes)
        if isinstance(ip_address_to_scan, bytes):
            try:
                ip_address_to_scan = ip_address_to_scan.decode('utf-8')
            except Exception:
                ip_address_to_scan = str(ip_address_to_scan)
        ip_address_to_scan = str(ip_address_to_scan).strip()
        # print "[+] **************Given IP Address : ",ip_address_to_scan
        print("[ v_scn ] **************Given IP Address : ",form_data_collector["host_ip"])
        print() 
        # print "[+] **************Given IP Address : ",form_data_collector["host_ip"][1]
        print(type(ip_address_to_scan))
        print(form_data_collector)
        print((type(form_data_collector["host_ip"])))


        async_to_sync(get_channel_layer().group_send)("pool", {
                "type": "chat.message",
                "action": "openvas_host_up_check",
                "check_status": "openvas checking host up status so,keep patience ",
            })

        # Use subprocess for reliability instead of os.system
        import subprocess
        try:
            ping = subprocess.run(["ping", "-c", "1", ip_address_to_scan], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            host_up = (ping.returncode == 0)
        except Exception:
            host_up = False

        if host_up:
  

            # print len(form_data_collector)
            # for i in form_data_collector:
                # print i
                # b = i.encode('UTF8')
                # print "view"
                # print type(b)
                # print b
                # print

            job = Job(
                name=ip_address_to_scan,
                status="started",
                vul_status="added"
            )
            job.save()

            try:
                process_ip_vul.delay(job.id, ip_address_to_scan)
            except Exception as e:
                print(f"[task] process_ip_vul.delay failed: {e}. Running synchronously.")
                try:
                    process_ip_vul.run(job.id, ip_address_to_scan)
                except Exception as e2:
                    print(f"[task] process_ip_vul.run also failed: {e2}")


            async_to_sync(get_channel_layer().group_send)("pool", {
            "type": "chat.message",
            "action": "openvas_taken_ip",
            "job_id": job.id,
            "job_name":  job.name,
            "job_status": job.status,
               })


            print("[ v_scn] ************************* Openvas Scan launcher Ender Hand over to background process ***************\n\n\n\n")


            data = {'msg': "ip address received :: " + ip_address_to_scan}
        else:

            data = {'msg': "host is down "}
        # data = {'msg': }
    else:
        data = {'msg': 'Failed'}
    return JsonResponse(data)

@csrf_exempt
def nm_scan_index(request):
    """Nmap scanning page and AJAX launcher.

    - GET: render the `nmap/nmap_scan2.html` page with available Job rows.
    - AJAX POST: accept either a `host_ip` field (from the scan form) or a
      job id sent as the single POST key (legacy behavior). Create a Job if
      needed and hand off to `process_nmap` Celery task. Notify channel
      layer so the UI can update.
    """
    if request.is_ajax():
        data = {'msg': 'ajax Failed'}
        form = dict(request.POST)

        # Prefer explicit host_ip form field
        if 'host_ip' in form:
            try:
                lst = form['host_ip']
                ip_address_to_scan = lst[0] if isinstance(lst, (list, tuple)) else lst
                if isinstance(ip_address_to_scan, bytes):
                    ip_address_to_scan = ip_address_to_scan.decode('utf-8', errors='ignore')
                ip_address_to_scan = str(ip_address_to_scan).strip()

                job = Job(name=ip_address_to_scan, status='started', nm_status='added')
                job.save()

                try:
                    process_nmap.delay(job.id, ip_address_to_scan)
                except Exception as e:
                    print(f"[task] process_nmap.delay failed: {e}. Running synchronously.")
                    try:
                        process_nmap.run(job.id, ip_address_to_scan)
                    except Exception as e2:
                        print(f"[task] process_nmap.run also failed: {e2}")

                async_to_sync(get_channel_layer().group_send)('pool', {
                    'type': 'chat.message',
                    'action': 'nmap_taken_ip',
                    'job_id': job.id,
                    'job_name': job.name,
                    'job_status': job.status,
                })

                data = {'msg': f'ip address received :: {ip_address_to_scan}'}
            except Exception as e:
                data = {'msg': f'error: {e}'}
            return JsonResponse(data)

        # Legacy: POST contains a single key that is the job id
        try:
            key = next(iter(form))
            job_id = int(key)
        except Exception:
            return JsonResponse({'msg': 'Invalid request'})

        try:
            ip_detail = Job.objects.get(pk=job_id)
        except Job.DoesNotExist:
            return JsonResponse({'msg': 'Job not found'})

        ip_detail.status = 'started'
        ip_detail.nm_status = 'added'
        ip_detail.save()

        import subprocess
        try:
            ping = subprocess.run(['ping', '-c', '1', ip_detail.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            host_up = (ping.returncode == 0)
        except Exception:
            host_up = False

        if host_up:
            try:
                process_nmap.delay(ip_detail.id, ip_detail.name)
            except Exception as e:
                print(f"[task] process_nmap.delay failed: {e}. Running synchronously.")
                try:
                    process_nmap.run(ip_detail.id, ip_detail.name)
                except Exception as e2:
                    print(f"[task] process_nmap.run also failed: {e2}")
            async_to_sync(get_channel_layer().group_send)('pool', {
                'type': 'chat.message',
                'action': 'nmap_taken_ip',
                'job_id': ip_detail.id,
                'job_name': ip_detail.name,
                'job_status': ip_detail.status,
            })
            return JsonResponse({'msg': 'host ip received'})
        else:
            return JsonResponse({'msg': 'host is down'})

    # non-ajax -> render page
    job = Job.objects.all()
    return render(request, 'nmap/nmap_scan2.html', {'job': job})

def nm_ip_detailed(request, id):
    """
    Placeholder function for nm_ip_detailed.
    This function currently does nothing and serves as a placeholder.
    """
    return JsonResponse({"message": f"nm_ip_detailed is not implemented yet for id {id}."})





























