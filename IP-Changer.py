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
while True:
	time.sleep(3)
	os.system("sudo systemctl reload tor")
print (Fore.GREEN + "Changed IP")
