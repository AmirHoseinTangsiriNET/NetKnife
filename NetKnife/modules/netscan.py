#Live IP And Device scanner Tools:
#This tool is used to scan IP addresses and Mac addresses of active devices within the network
from colorama import Fore
from scapy.all import *
def NetScanner():
	print """
	#     #               #####                                            
	##    # ###### ##### #     #  ####    ##   #    # #    # ###### #####  
	# #   # #        #   #       #    #  #  #  ##   # ##   # #      #    # 
	#  #  # #####    #    #####  #      #    # # #  # # #  # #####  #    # 
	#   # # #        #         # #      ###### #  # # #  # # #      #####  
	#    ## #        #   #     # #    # #    # #   ## #   ## #      #   #  
	#     # ######   #    #####   ####  #    # #    # #    # ###### #    # 

	"""
	NetRange = raw_input("Plese Enter The Network Range IP Address: ")

	ArpPakcet = ARP(pdst=NetRange)

	NetMac = Ether(dst="ff:ff:ff:ff:ff:ff")
	#Brotcast Mac Address

	packet = NetMac/ArpPakcet
	output = srp(packet, timeout=4, verbose=0)[0]


	NetAva = []
	for received, sent, in output:
	    NetAva.append({'IP Address': received.psrc, 'Mac Address': received.hwsrc})
	print "---------------------------------"
	print "Live Addresses Were Discovered"

	print "IP Address" + " "*12 + "Mac Address"
	for client in NetAva:
 	   print "{:16}      {}".format(client['IP Address'], client['Mac Address'])
	   print "---------------------------------"
	

	