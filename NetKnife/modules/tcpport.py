from colorama import Fore
from scapy.all import *
import nmap
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


	