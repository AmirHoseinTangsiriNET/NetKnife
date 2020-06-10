from scapy.all import *
from colorama import Fore

iface = raw_input("Plese Enter The(For Example:wlan0mon): ")
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
