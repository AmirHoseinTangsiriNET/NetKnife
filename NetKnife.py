import os
from colorama import Fore
import sys
import time
os.system("clear")
print Fore.RED + ("""

'|.   '|'           .   '||'  |'            ||    .'|.            
 |'|   |    ....  .||.   || .'    .. ...   ...  .||.     ....     
 | '|. |  .|...||  ||    ||'|.     ||  ||   ||   ||    .|...||  
 |   |||  ||       ||    ||  ||    ||  ||   ||   ||    ||       
.|.   '|   '|...'  '|.' .||.  ||. .||. ||. .||. .||.    '|...' 

""")
def printer(Print):
    for c in Print + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(5. / 100)

printer ("\033[91m[+]Welcome To NetKnife Framework")
printer ("[+]Please Wait")

printer("Developer: AmirHosein Tangsiri Nezhad")
time.sleep(3)
printer ("[+]Chose Tools Number ")
printer ("[1]:Arp Cache Poisiner Tools(Coming Soon)")
printer ("[2]:Fake Access Point Creator Tools")
printer ("[3]:SSID Hidden Locator Tools(Coming Soon)")
printer ("[4]:Hash Creator Tools")
printer ("[5]:SYN Flooder Tools")
printer ("[6]:Network Packet Capture Tools")
printer ("[7]:AP And WIFI Device Detection Tools")
printer ("[8]:Public IP Changer In 3 Per Second(Linux System-D Only)")
printer ("[99]: Exit The NetKnife")

TN = input ("[+]Please Enter the Toools Number: ")
if TN == 1:
	print "Coming Soon"
	#os.system("python Arp.py")
if TN == 2:
	os.system("python FKAP.py")
if TN == 3:
	print "Coming Soon"
	#os.system("python SSID.py")
if TN == 4:
	os.system("python Hash.py")
if TN == 5:
	os.system("python Syn.py")
if TN == 6:
	os.system("python NetSniffer.py")
if TN == 7:
	ps.system("python APD.py")
if TN == 8:
	os.system("python IP-Changer.py")
if TN == 99:
	printer ("Exited The NetKnife")
	sys.exit()
else:
	print ("[!]Not Found Tools Number")
	
