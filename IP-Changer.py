import os
import time
from colorama import Fore
print """
### ######   #####                                            
 #  #     # #     # #    #   ##   #    #  ####  ###### #####  
 #  #     # #       #    #  #  #  ##   # #    # #      #    # 
 #  ######  #       ###### #    # # #  # #      #####  #    # 
 #  #       #       #    # ###### #  # # #  ### #      #####  
 #  #       #     # #    # #    # #   ## #    # #      #   #  
### #        #####  #    # #    # #    #  ####  ###### #    # 
"""
print Fore.BLUE + "[+]Started Tools"
while True:
	time.sleep(3)
	print Fore.GREEN + "Changed IP"
	os.system("sudo systemctl reload tor")
