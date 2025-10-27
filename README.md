# Xerror


Xerror is an automated penetration tool , which will help security professionals and non professionals to automate their pentesting tasks. Xerror will perform all tests and, at the end generate two reports for executives and analysts.

Xerror provides GUI easy to use menu driven options.Iinternally it supports openVas for vulnerability scanning, Metasploit for exploitation and gives GUI based options after successful exploitation e.g Meterpreter sessoins.
Building in python as major. 

Xerror build on python2 as a primary language and Django2 as web framework along with, websockets(django channel) on celery server and Redis srver to achieve asynchronization. On front side it supports Djanog default template enging language which is jinga2 and jquery.   



 You are goog to go </br>
 
 This is xerror Beta version, soon complete version will be uploaded with complete explanation and detail of each step ...   </br>
 
 ![alt text](https://i.imgur.com/oJQH6ax.png)
 
 
![alt text](https://i.imgur.com/RTyPiiZ.png)

![alt text](https://i.imgur.com/yLMMNC2.png)


![alt text](https://i.imgur.com/K7k2uRu.png)

![alt text](https://i.imgur.com/dnDWm0O.png)

![alt text](https://i.imgur.com/pn0evVH.png)




![alt text](https://i.imgur.com/tMo0B5S.png)

![alt text](https://i.imgur.com/65JUi9y.png)
 
 ![alt text](https://i.imgur.com/BIqlXr9.png)
 
 
 ![alt text](https://i.imgur.com/dV3NuRv.png)
 
 ![alt text](https://i.imgur.com/W9bBejm.png)
 
 
 
 
 
 
 
 
</br>

<b>Contact :</b> exploitmee@protonmail.com

# Guide d'installation et de configuration
Ce fichier fournit une procédure reproducible pour installer et configurer Xerror en environnement de développement, ainsi que des notes pour la mise en production.

### 1. Prérequis système

- Système Linux (développé/testé sur Ubuntu/Debian)
- Python 3.10+ (un `venv` dans le dépôt est utilisé ici)
- pip
- Redis (broker pour Celery)
- nmap (outil en ligne de commande)
- setcap (fourni par libcap) pour accorder des capacités réseau à nmap si vous voulez des scans SYN/OS sans exécuter en root
- (optionnel) Metasploit + msfrpcd si vous comptez utiliser les modules d'exploitation

Installez les paquets système recommandés :

```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential redis-server nmap libcap2-bin libxml2-dev libxslt1-dev pkg-config
```

Note : `libcap2-bin` fournit `setcap`.

### 2. Préparer l'environnement Python

```bash
cd /chemin/vers/V2.2
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### 3. (Optionnel mais recommandé) Accorder des capacités à nmap

Pour exécuter des scans SYN (-sS) et la détection d'OS (-O) sans lancer les services en root, donnez les capacités à l'exécutable `nmap` :

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
getcap /usr/bin/nmap  # vérifie que les capacités sont présentes
```

Si pour une raison quelconque vous préférez ne pas toucher aux capacités, la configuration de Xerror utilise par défaut des scans non privilégiés (`-sT`) ou bascule en mode degradé.

### 4. Démarrer Redis

Redis est utilisé comme broker Celery. Pour un environnement de développement local :

```bash
sudo systemctl enable --now redis-server
sudo systemctl status redis-server
```

### 5. Configurer les variables d'environnement

Créez un `.env` (ou exportez) selon vos besoins. Exemple minimal :

```env
DJANGO_SETTINGS_MODULE=xerror.settings
```

Le projet lit `xerror/settings.py`. Pour d'autres secrets (DB, MSF credentials), utilisez votre méthode standard (dotenv, vault, etc.).

### 6. Appliquer les migrations

```bash
cd xerror
../env/bin/python manage.py migrate
```

### 7. Lancer l'application et worker (développement)

Lancer le serveur Django (accessible sur http://localhost:8000) :

```bash
# depuis le répertoire racine du dépôt
env/bin/python xerror/manage.py runserver 0.0.0.0:8000 > /tmp/xerror_runserver.log 2>&1 & echo $! > /tmp/xerror_runserver.pid
```

Lancer Celery (depuis le répertoire `xerror` afin que `xerror.celery` soit importable) :

```bash
cd xerror
../env/bin/celery -A xerror.celery worker --loglevel=info --concurrency=1 -n worker1@%h > /tmp/celery_worker.log 2>&1 & echo $! > /tmp/celery_worker.pid
```

Vérifiez les logs :

```bash
tail -f /tmp/xerror_runserver.log
tail -f /tmp/celery_worker.log
```

### 8. Lancer msfrpcd (optionnel, pour Metasploit RPC)

Si vous utilisez les fonctionnalités d'exploitation, démarrez un service Metasploit RPC sécurisé :

```bash
# installer Metasploit via votre méthode (distribution/installer officiel)
# puis lancer (exemple) :
sudo msfrpcd -P <mot_de_passe_rpc> -S -U msf -a 127.0.0.1 -p 55553
```

Ensuite configurez les mêmes identifiants dans l'UI xerror ou via les modèles `MSF_rpc_connection`.

### 9. Emplacement des rapports et logs

- Rapports XML/CSV : `xerror/reports/` (nmap écrit `nm_<id>_<host>.xml` et le parser crée `csv_<id>_<host>.csv`)
- Logs : `/tmp/xerror_runserver.log` et `/tmp/celery_worker.log`

Si vous lancez des tâches en root (par ex. pour des scans complets), les fichiers créés peuvent avoir `root:root` pour propriétaire — changez la propriété si nécessaire :

```bash
sudo chown $(whoami):$(whoami) xerror/reports/*
```

### 10. Profils Nmap recommandés

Le code supporte plusieurs profils ; modifiez `parsing/tasks.py` pour changer le profil par défaut ou ajouter une option UI :

- `dev/fast` : `-T4 -sT -sV -Pn --max-retries 1 --host-timeout 30s` (rapide, sans privilèges)
- `full` : `-T4 -sS -sV -O -A -p- -Pn` (complet, nécessite capacités ou privilèges root)

### 11. Automatisation / production

Pour un déploiement durable, créez des unités systemd :

Example systemd unit for Celery (save as `/etc/systemd/system/xerror-celery.service`):

```ini
[Unit]
Description=Xerror Celery Worker
After=network.target redis-server.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/path/to/V2.2/xerror
Environment=PATH=/path/to/V2.2/env/bin
ExecStart=/path/to/V2.2/env/bin/celery -A xerror.celery worker --loglevel=info --concurrency=4 -n worker1@%h
Restart=always

[Install]
WantedBy=multi-user.target
```

Example systemd unit for a privileged scan helper (optional):

```ini
[Unit]
Description=Xerror privileged scan helper
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/V2.2/xerror
ExecStart=/usr/bin/python3 /path/to/V2.2/xerror/scan_helper.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### 12. Dépannage rapide

- Si Celery ne se connecte pas à Redis : vérifiez `redis-server` et l'URL `REDIS_URL` (par défaut `redis://localhost:6379/0`).
- Si `nmap` se plaint de privilèges : appliquez `setcap` ou lancez le scan via un service contrôlé.
- Si `msfrpc` est introuvable : installez la bibliothèque Python attendue (ex : `pymetasploit3`) et/ou démarrez `msfrpcd`.

### 13. Récapitulatif rapide des commandes

```bash
# créer venv et installer
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt

# donner capabilities à nmap (optionnel)
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# migrations
cd xerror && ../env/bin/python manage.py migrate

# runserver (background)
../env/bin/python manage.py runserver 0.0.0.0:8000 > /tmp/xerror_runserver.log 2>&1 & echo $! > /tmp/xerror_runserver.pid

# celery (from xerror/)
../env/bin/celery -A xerror.celery worker --loglevel=info --concurrency=1 -n worker1@%h > /tmp/celery_worker.log 2>&1 & echo $! > /tmp/celery_worker.pid

# démarrer msfrpcd (optionnel)
sudo msfrpcd -P <password> -S -U msf -a 127.0.0.1 -p 55553
```


-----

Contact: exploitmee@protonmail.com

