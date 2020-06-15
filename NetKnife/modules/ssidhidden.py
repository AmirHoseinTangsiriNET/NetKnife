from scapy import *
from colorama import Fore
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
