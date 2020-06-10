import os
from colorama import Fore

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
	
