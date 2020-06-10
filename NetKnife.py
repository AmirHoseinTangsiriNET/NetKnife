import os
from colorama import Fore

print Fore.RED + ("""

'|.   '|'           .   '||'  |'            ||    .'|.            
 |'|   |    ....  .||.   || .'    .. ...   ...  .||.     ....     
 | '|. |  .|...||  ||    ||'|.     ||  ||   ||   ||    .|...||  
 |   |||  ||       ||    ||  ||    ||  ||   ||   ||    ||       
.|.   '|   '|...'  '|.' .||.  ||. .||. ||. .||. .||.    '|...' 

""")
print Fore.GREEN + ("Hello Welcome To The NetKnife. Please Chose The Tools Number ")
print ("[+]Chode Tools Number ")
print ("[1]:Arp Cache Poisiner Tools")
print ("[2]:Fake Access Point Creator Tools")
print ("[3]:SSID Hidden Locator Tools")
print ("[4]:Hash Creator Tools")
print ("[5]:SYN Flooder Tools")
TN = input ("[+]Please Enter the Toools Number: ")
if TN == 1:
	os.system("cd Arp-Cache-Poisiner ; python Arp.py")
if TN == 2:
	os.system("cd Fake-AP ; python FKAP.py")
if TN == 3:
	os.system("cd SSID-Hidden ; python SSID.py")
if TN == 4:
	os.system("cd Hash-Generator ; python Hash.py")
if TN == 5:
	os.system("cd Syn-Flooder ; python Syn.py")
	
