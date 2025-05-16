from scapy.all  import *
import os, subprocess, re, shutil


chemin_disque = input("Entrez le chemin du disque dur à explorer :") #demande le path à l'utilisateur


chemin_stockage_jpg = input("Entrez le chemin pour stocker les jpg :")

regex_jpg = re.compile(r".+\.jpg")                                                          #cration regex pour rechercher les fichier .jpg
regex_txt = re.compile(r".+\.txt")                                                          #cration regex pour rechercher les fichier .txt

ls_jpg = []                                                                                 #creation d'une liste dans laquelle le nom des fichiers jpg seront stocker
ls_txt = []                                                                                 #creation d'une liste dans laquelle le nom des fichiers txt seront stocker
ls_path_jpg = []                                                                            #creation d'une liste dans laquelle le PATH des fichiers jpg seront stocker
ls_path_txt = []                                                                            #creation d'une liste dans laquelle le PATH des fichiers txt seront stocker
ls_ip = []                                                                                  #creation d'une liste dans laquelle seront stocker les ip trouvées

for chemins, dossiers, fichiers in os.walk(chemin_disque) :                                 #permet de parcourir mes dossiers à partir du path donné par l'utilisateur pour aller chercher tous les fichier avec l'extension donnée dans le regex
    for fichier in fichiers :
        if regex_jpg.findall(str(fichier)) :
            ls_jpg.append(fichier)
            ls_path_jpg.append(chemins.replace("\\", "/")+"/"+str(fichier))

# print(ls_jpg)                                                                             #j'affiche tous mes fichiers .jpg

for chemins, dossiers, fichiers in os.walk(chemin_disque) :
    for fichier in fichiers :
        if regex_txt.findall(str(fichier)) :                                                #permet de parcourir mes dossiers à partir du path donné par l'utilisateur pour aller chercher tous les fichier avec l'extension donnée dans le regex
            ls_txt.append(fichier)
            ls_path_txt.append(chemins.replace("\\", "/")+"/"+str(fichier))                 #transforme le path qui possède deux antislash en path avec uniquement des slash




# print(ls_txt)                                                                             #j'affiche tous mes fichiers .txt
# print(ls_path_jpg)                                                                        #j'affiche les PATH des jpg trouvé en parcourant les dossiers
# print(ls_path_txt)                                                                        #j'affiche les PATH des txt trouvé en parcourant les dossiers

for file in  ls_path_jpg :
    shutil.copy(file,chemin_stockage_jpg)                                                 #je déplace les jpg dans mon dossier cible

ls_path_txt_ip = []

for file in ls_path_txt :                                                                   #ici une boucle for qui parcours tous les fichiers à l'intérieur de ma liste de path_txt qui recherche à l'intérieur de chaque fichiers pour trouver des adresses ip et les mettres dans une liste
    
    a = open(file, "r")
    data = a.read()
    a.close()
    
    regex_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")              #ici le regex trouvant les textes ressemblant à des ip

    ls_ip.extend(regex_ip.findall(data))
    if regex_ip.findall(data) != [] :
        ls_path_txt_ip.append(file)

os_type = os.name


if os_type == 'nt' :
    mon_ip_cmd = subprocess.run("""netsh interface ipv4 show addresses ""Wi-fi"" | findstr "IP adress" """, shell=True, capture_output=True, text=True, check=True)     #ici je lance une commande cmd pour récupérer mon adresse IP
else :
    interface = input("Entrez le nom de votre interface reseau :")
    mon_ip_cmd = subprocess.run(f"""ip addr show {interface} | grep -w 'inet' | grep -v 'inet6' | awk '{{print $2}}' | cut -d'/' -f1""", shell=True, capture_output=True, text=True, check=True)

mon_ip_cmd = regex_ip.findall(mon_ip_cmd.stdout)                                            #je récupére avec un regex uniquement l'adresse ip
mon_ip_cmd = "".join(mon_ip_cmd)                                                            #je transforme la liste en string

# print(mon_ip_cmd)                                                                         #affiche mon adresse ip

def meme_lan(ip1, ip2):                                                                     #definition fonction pour vérifier si les 3 premiers octects d'une adresse ip sont les même que ceux de mon adresse ip
    return ip1.split('.')[:3] == ip2.split('.')[:3]

adresses_meme_lan = []                                                                      #creation d'une liste contenant toutes les adresses du meme lan

for ip in ls_ip:
    if meme_lan(mon_ip_cmd, ip):
        adresses_meme_lan.append(ip)                                                        #boucle dans la liste de toutes les ip pour ajouter les ip étant dans le meme lan que la notre dans une liste "adresses_meme_lan"



print("Voici la liste des adresses IP étant dans le même réseaux que mon ip :")
for i in adresses_meme_lan :
    print (i)                                                                               #affiche les addresse faisant partis du meme lan
print(ls_ip)
print("========================================================================")

for file_name in ls_jpg:
    name_without_extension = file_name[:-4]                                                 # Supprime les 4 derniers caractères (extension .jpg) du nom de fichier et print les fichier jpg
    print(name_without_extension)


print("========================================================================")

for file in ls_path_txt_ip :                                                                 #Affiche les chemins de fichiers contenant des adresses IP
    print(file)

print("========================================================================")

port_min = 1024
port_max = 1030


# Fonction qui scan:
def myScan(liste_addresses):
  for addresse in liste_addresses:
    for port in range(port_min, port_max) :
        packet = IP(dst = addresse)/TCP(dport = port, flags='S')
        response = sr1(packet, timeout = 0.1, verbose = 0)

        if response == None:
            print('port est filtré par un firewall')
        elif response.haslayer(TCP) and response[TCP].flags == "SA":
            print('port ouvert')
        elif response.haslayer(TCP) and response[TCP].flags == "RA":
            print('port fermé')

myScan(adresses_meme_lan)
