from scapy.all import *
from colorama import Fore
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

