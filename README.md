# Xerror


Xerror is an automated penetration tool , which will help security professionals and non professionals to automate their pentesting tasks. Xerror will perform all tests and, at the end generate two reports for executives and analysts.

Xerror provides GUI easy to use menu driven options.Iinternally it supports openVas for vulnerability scanning, Metasploit for exploitation and gives GUI based options after successful exploitation e.g Meterpreter sessoins.
Building in python as major. 

Xerror build on python2 as a primary language and Django2 as web framework along with, websockets(django channel) on celery server and Redis srver to achieve asynchronization. On front side it supports Djanog default template enging language which is jinga2 and jquery.   


How to use this porject: </br>
 1.Activate virtual enviroment by using following command( make sure you have pre-installed py virtual env) </br>
      souce env/bin/activate</br>
 2. Start redis server</br>
      service redis-server start</br>
 3. start python srver </br>
      1. cd xerror </br>
      2. python manage.py runserver </br>
 4. start celery server( run this in new terminal) </br>
      1. cd xerror </br>
      2. celery -A xerror worker -l info </br>
 5. start msfrpc server for metasploit </br>
      msfrpcd -P 123 -S -a 127.0.0.1</br>
 6. start openvas server and set OMP server credientials to admin@admin 127.0.0.1 9392 </br>
 
 
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

Ce document décrit les étapes nécessaires pour installer et configurer le projet.

## Prérequis

- **Python 3.12** ou une version ultérieure
- **Virtualenv** pour gérer les environnements virtuels
- **Django** (inclus dans les dépendances du projet)
- **pip** pour installer les dépendances
- Accès à un serveur Metasploit (si nécessaire pour certaines fonctionnalités)

## Étapes d'installation

### 1. Cloner le dépôt
```bash
git clone https://github.com/valentinowyhnel/V2.2.git
cd V2.2
```

### 2. Créer un environnement virtuel
```bash
python3 -m venv env
source env/bin/activate
```

### 3. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 4. Configurer les variables d'environnement
Créer un fichier `.env` à la racine du projet et ajouter les variables suivantes :
```env
DJANGO_SETTINGS_MODULE=xerror.settings
```

### 5. Appliquer les migrations
```bash
python manage.py migrate
```

### 6. Lancer le serveur de développement
```bash
python manage.py runserver
```

Le projet sera accessible à l'adresse [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Dépendances principales

- **Django** : Framework web principal
- **python-decouple** : Gestion des variables d'environnement
- **PyPDF2** : Génération de fichiers PDF
- **nmap** : Analyse réseau
- **celery** : Gestion des tâches asynchrones

## Notes supplémentaires

- Assurez-vous que le serveur Metasploit est configuré si vous utilisez des fonctionnalités liées à Metasploit.
- Pour les environnements de production, configurez un serveur WSGI tel que Gunicorn et un serveur web comme Nginx.
- Utilisez une base de données comme PostgreSQL pour la production (au lieu de SQLite).

## Dépannage

### Erreur : `ModuleNotFoundError: No module named 'decouple'`
Assurez-vous que le module `python-decouple` est installé dans votre environnement virtuel :
```bash
pip install python-decouple
```

### Erreur : `AttributeError` ou `ImportError`
Vérifiez que toutes les dépendances sont correctement installées et que les migrations ont été appliquées.

### Erreur : `msfrpc non disponible`
Installez le client Metasploit ou configurez un serveur Metasploit accessible.

Pour toute autre question, consultez la documentation ou ouvrez une issue sur le dépôt GitHub.
