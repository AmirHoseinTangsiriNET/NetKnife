from colorama import Fore
import os,time
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

