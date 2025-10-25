import datetime
import json
import os,sys
import time
import subprocess

from subprocess import Popen, PIPE
from shlex import split

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from xerror.celery import app
from .models import TextFile,Config_exploit,Exploiated_system


from xerror.settings import BASE_DIR
from .models import TextFile,Job


from .openvas_scanner_script import opv_scan_hacker 
from .nm_xml_parser import nmxmlparser
from .msf_rpc_handler import MSF_rpc_Hhandler
from .msf_rpc_client import CustomMsfRpcClient





@app.task
def process_file(file_id):


    file = TextFile.objects.get(pk=file_id)
    with open(file.file) as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            result = 0
            send_message_to_group('pool', {
                "action": "processing",
                "file_id": file_id,
                "progress": 100,
            })
        else:
            step = size // 100
            result = 0
            for line in f:
                for char in line:
                    result += 1
                    if result % step == 0:
                        send_message_to_group('pool', {
                            "action": "processing",
                            "file_id": file_id,
                            "progress": result // step,
                    })

    file.amount = result
    file.completed = datetime.datetime.now()
    file.save()
    for i in range(1,10):
        time.sleep(2)
        send_message_to_group('pool', {
                            "action": "processing",
                            "file_id": file_id,
                            "progress": str(i),
                        })

    send_message_to_group('pool', {
        "action": "completed",
        "file_id": file_id,
        "file_amount": result,
    })
















# *********************************************************  Vuonerability Scanning ************************************

@app.task
def process_ip_vul(job_id,ip_addr):

    job = Job.objects.get(pk=job_id)
    print("[ openvas ] Start Background Process ")
    opv_scan_hacker(job_id,ip_addr)
 
    # else:    
    if True:
        job.status ="completed"
        job.vul_status = "OpenVass Vul scan completed "
        job.save()

        send_message_to_group('pool', {
                "action": "completed_ip",
                "job_id": job_id,
                "job_name": job.name,
                "job_status": job.status,
            })   


    print("[ openvas ] Ending opv Background Process ")











# *********************************************************  Generabl Scanning ************************************




@app.task
def process_nmap(job_id,ip_addr):

    job = Job.objects.get(pk=job_id)

    def run(command):
        process = Popen(command, stdout=PIPE, shell=True)
        while True:
            line = process.stdout.readline().rstrip()
            if not line:
                break
            yield line


    name_xml = "nm_"+str(job_id)+"_"+str(job.name)+".xml"
    scnRepo = BASE_DIR + '/reports/' + name_xml
    print("[ NMAP  ] ************************* Nmap Background Process running **************")
    print(scnRepo)

    # Revert to a more thorough nmap profile for full scans. This profile
    # performs a SYN scan with service/version detection and OS detection,
    # and scans all TCP ports. Note: SYN scans (-sS) and OS detection (-O)
    # generally require root privileges or granting cap_net_raw/cap_net_admin
    # to the nmap binary (e.g. `sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap`).
    #
    # Flags used:
    # -T4      : aggressive timing for faster but still reliable results
    # -sS      : TCP SYN scan (stealthy, requires privileges)
    # -sV      : service/version detection
    # -O       : OS detection
    # -A       : enable OS detection, version detection, script scanning and traceroute
    # -p-      : scan all 65535 TCP ports (thorough but slower)
    # -Pn      : skip host discovery (treat host as up)
    # --stats-every 1s : print progress statistics every 1 second
    #
    # If you prefer to avoid privilege requirements, replace -sS with -sT
    # and drop -O (or run nmap with the appropriate capabilities).
    nmap_cmd = f"nmap -T4 -sS -sV -O -A -p- -Pn --stats-every 1s {ip_addr} -oX {scnRepo}"
    for path in run(nmap_cmd):
            # `run()` yields raw bytes from the subprocess stdout; decode to str
            if isinstance(path, bytes):
                try:
                    path = path.decode('utf-8', errors='ignore')
                except Exception:
                    path = str(path)

            send_message_to_group('pool', {
                "action": "not_completed",
                "job_id": job_id,
                "job_name": job.name,
                "job_nmap_status": str(path),
                "job_current_status": "Running",
                # "job_status": "Running",
            })
            print("[ NMAP ] "+path)


    print("[NMAP ]  converting csv file  ")
    name_csv = "csv_"+str(job_id)+"_"+str(job.name)+".csv"
    # nmxmlparser expects paths relative to BASE_DIR. The XML is written
    # into the `reports/` subdirectory (scnRepo). Pass the 'reports/'
    # prefix so the parser can find the file. Also write the CSV into
    # the reports directory for consistency.
    xml_rel = 'reports/' + name_xml
    csv_rel = 'reports/' + name_csv
    print("[ NMAP ]  "+nmxmlparser(xml_rel,csv_rel))
    print("[ NMAP ]  finshed Nmpa scanning ")

    # for i in range(1,10):
    #     print(i)
    #     time.sleep(2)

    job.status ="completed"
    job.nm_status="Nmap_scan_completed"

    job.save()

    send_message_to_group('pool', {
            "action": "completed_ip",
            "job_id": job_id,
            "job_name": job.name,
            "job_status": job.status,
        })    
    print("[ NMAP  ]  ************************* Nmap Background Process Ended  **************")







# *********************************************************  Metasploit exploit and post exploits( totally depend on external scripts ) ************************************

@app.task
def process_exploitation(config_id,job_id):
    print("[ Exploit ] ************************ [ Exploit] Starting Background Process ******************************")
    # Job.objects.get(pk=exploit_form_data["host_id"])
    obj = MSF_rpc_Hhandler()
    obj.try_exploit(config_id,job_id)

    print("[ Exploit ] ************************ [ Exploit] Background Process Ended  ******************************")





@app.task
def process_session_check(session_id,host_id,uuid):
    print(" [ SESSION ] Backend session check  process STARTED ")
    try:
        client = CustomMsfRpcClient("msf", "password", host="127.0.0.1", port=55553)
        print ("[ SESSION ] Rpc server connected ")
    except Exception as e:
            send_message_to_group('pool', {
                    "action": "session_status_checking",
                    "session_current_status":   "\n xerror@w11:~> Metasploit Connection Not succesfuull \n",
                    "session_status":  "Msf conect/error",
                    "session_id": session_id,
                    
                       })
    else:
        print ("[ SESSION ] Checking session status  ")
        session_idd = client.sessions.list 
        lst = list(session_idd.keys())
        session_id = int(session_id)
        if session_id in lst:
            print ("[ SESSION ] Session Active for following uuid ")
            print (uuid)

            send_message_to_group('pool', {
                    "action": "session_status_checking",
                    "session_current_status":   "\n xerror@w11:~> Metasploit Sssion to Remote host is active \n",
                    "session_status":  "active",
                    "session_id": session_id,
                    
                       })
        else:
            print ("[ SESSION ] Session is not active for following uuid ")
            print (uuid)
            send_message_to_group('pool', {
                    "action": "session_status_checking",
                    "session_current_status":   "\n xerror@w11:~> Metasploit Session to Remote host is not active \n",
                    "session_status":  "no",
                    "session_id": session_id,
                    
                       })




@app.task
def process_session_interact(session_id,cmd, uuid):

    print("*****************************backend session check  process")
    try:
        client = CustomMsfRpcClient("msf", "password", host="127.0.0.1", port=55553)
        print ("********************** rpc connected ")
    except Exception as e:
            send_message_to_group('pool', {
                "action": "session_interact",
                "session_current_status":   "\n xerror@w11:~> Metasploit Connection Not succesfuull \n",
                "session_status":  "Msf conect/error",
                "session_id": session_id,
                
                   })
    else:
        print ("[ SESSION ] Interacting with session  ")
        session_idd = client.sessions.list 
        lst = list(session_idd.keys())
        session_id = int(session_id)
        if session_id in lst:
            print ("[ SESSION ] Interacting with active session ")
            print (uuid)
            output = client.sessions.session_info(session_id)
            print (output)
            client.sessions.session_interact(session_id,cmd)
            send_message_to_group('pool', {
                    "action": "session_interact",
                    "session_current_status":   "\n xerror@w11:~> Metasploit Interact with Remote host is successful \n",
                    "session_status":  "active",
                    "session_id": session_id,
                    "data": output,
                       })
        else:
            print ("[ SESSION ] Session is not active for following uuid ")
            print (uuid)
            send_message_to_group('pool', {
                    "action": "session_interact",
                    "session_current_status":   "\n xerror@w11:~> Metasploit Session to Remote host is not active \n",
                    "session_status":  "no",
                    "session_id": session_id,
                    
                       })




# Ajout de la définition de la fonction manquante

def send_message_to_group(group_name, message):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": "chat.message",
            "message": message,
        }
    )



