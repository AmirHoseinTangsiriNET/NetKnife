from scapy.all import *

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