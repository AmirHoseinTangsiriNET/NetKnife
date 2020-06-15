import os,sys,time,hashlib,nmap,socket
from colorama import Fore
from scapy.all import *
from playsound import playsound
from modules.__init__ import *

#Check Root User
if os.getuid() != 0:
        sys.exit("Please Ran As Root User")

#slowprint function
def printer(Print):
    for c in Print + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(4. / 100)

#clean function
def clean():
    print(chr(27)+'[2j')
    print('\033c')
    print('\x1bc')

clean()

print Fore.BLUE + "Started NetKnife Voice"
playsound("core/Voice/NetVoice.mp3")
clean()

time.sleep(1)
#banner
print Fore.GREEN + ("""
'|.   '|'           .   '||'  |'            ||    .'|.            
 |'|   |    ....  .||.   || .'    .. ...   ...  .||.     ....     
 | '|. |  .|...||  ||    ||'|.     ||  ||   ||   ||    .|...||  
 |   |||  ||       ||    ||  ||    ||  ||   ||   ||    ||       
.|.   '|   '|...'  '|.' .||.  ||. .||. ||. .||. .||.    '|...' 
""")



printer ("Welcome To NetKnife Framework")
printer ("Developer: AmirHosein Tangsiri Nezhad")
printer ("GitHub: https://github.com/AmirHoseinTnagsiriNET/NetKnife")
printer ("Please Select The Tools Number")
printer ("--------------------------------------------------------------")
	
	
#printer ("\033[91m[+]Welcome To NetKnife Framework")
#printer ("[+]Please Wait")

#printer ("Developer: AmirHosein Tangsiri Nezhad")
#printer ("GitHub: https://github.com/AmirHoseinTnagsiriNET/NetKnife")

time.sleep(2)
#menu
printer ("\033[91m[1]:Arp Cache Poisiner Tools(Coming Soon)")
printer ("\033[91m[2]:Fake Access Point Creator Tools")
printer ("\033[91m[3]:SSID Hidden Locator Tools")
printer ("\033[91m[4]:Hash Creator Tools")
printer ("\033[91m[5]:SYN Flooder Tools")
printer ("\033[91m[6]:Network Packet Capture Tools")
printer ("\033[91m[7]:AP And WIFI Device Detection Tools")
printer ("\033[91m[8]:Public IP Changer In 3 Per Second(Linux System-D Only)")
printer ("\033[91m[9]:Wi-Fi Deauthentication Attacker Tools")
printer ("\033[91m[10]:Tcp Port Scanner Tools")
printer ("\033[91m[11]:Live IP And Device scanner")
printer ("\033[91m[12]:Mac Flooder Tools")

printer ("\033[91m[99]:Exit The NetKnife")
print Fore.GREEN + ("--------------------------------------------------------------")


if __name__ == '__main__':
    while True:
        try:
            TN = int(raw_input ("[+]Please Enter the Tools Number: "))
            if TN == 1:
                Arp()
            if TN == 2:
                FakeAP()
            if TN == 3:
                SSIDHeddin()
            if TN == 4:
                HashGen()
            if TN == 5:
                Syn()
            if TN == 6:
                NetSniffer()
            if TN == 7:
                APD()		
            if TN == 8:
                IP_Changer()
            if TN == 9:
                Deauthentication()
            if TN == 10:
                TCPPortScanner()
            if TN == 11:
                NetScanner()
            if TN == 12:
                MacFlooder()
            if TN == 99:
                sys.exit("Exited The NetKnife")
            else:
                print "[!]Wrong!!!"
        except KeyboardInterrupt:
            sys.exit("Bye Byte :D")
        except :
            pass
