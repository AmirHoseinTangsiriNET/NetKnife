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
print ("[1]:Arp Cache Poisoner Tools")
print ("[2]:Fake Access Point Generator Tools")
print ("[3]:SSID Hidden Locator Tools")
print ("[4]:Hash Generator Tools")
print ("[5]:SYN Flooder Tools")
TN = input ("[+]Please Enter the Toools Number: ")
if TN == 1:
	os.system("python Arp.py")
if TN == 2:
	os.system("python FKAP.py")
if TN == 3:
	os.system("python SSID.py")
if TN == 4:
	os.system("python Hash.py")
if TN == 5:
	os.system("python Syn.py")
	
