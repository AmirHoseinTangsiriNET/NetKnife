#[4]:Hash Creator Tools
#This tool is used to convert Plain-Text texts to Cipher-Text texts using Hash algorithms.
from hashlib import *
from colorama import Fore
def HashGen():

    print """
    '||'  '||'                '||       ..|'''.|                                     .     .                   
     ||    ||   ....    ....   || ..   .|'     '    ....  .. ...   ... ..    ....  .||.  .||.    ...   ... ..  
     ||''''||  '' .||  ||. '   ||' ||  ||    .... .|...||  ||  ||   ||' '' .|...||  ||    ||   .|  '|.  ||' '' 
     ||    ||  .|' ||  . '|..  ||  ||  '|.    ||  ||       ||  ||   ||     ||       ||    ||   ||   ||  ||     
    .||.  .||. '|..'|' |'..|' .||. ||.  ''|...'|   '|...' .||. ||. .||.     '|...'  '|.'  '|.'  '|..|' .||. 
    """

    print Fore.GREEN + """
    [+] Hash Genrettor Tools [+]
    	*** Hash Algorithm Support List ***
    		md5:      [+]-1
    		sha1:     [+]-2
    		sha224:   [+]-3 
    		sha256:   [+]-4 
    		sha512:   [+]-5
    """
    text = raw_input("[*]Please Enter The Your Text: ")
    hashmodel = raw_input("[*]Please Ente The Hash Algorithm Number: ")
    if hashmodel == "1":
    	md5 = hashlib.md5()
    	md5.update(inputer)
    	print "[*] md5 hash genereted: ",md5.hexdigest()
    if hashmodel == "2":
    	sha1 = hashlib.sha1()
    	sha1.update(text)
    	print Fore.WHITE + "[*] sha1 hash genereted: ",sha1.hexdigest()
    if hashmodel == "3":
    	sha224 = hashlib.sha224()
    	sha224.update(text)
    	print Fore.YELLOW + "sha224 hash genereted: ",sha224.hexdigest()
    if hashmodel =="4":
    	sha256 = hashlib.sha256()
    	sha256.update(text)
    	print Fore.RED + "[*] sha256 hash genereted: ",sha256.hexdigest()
    if hashmodel =="5":
        sha512 = hashlib.sha512()
    	sha512.update(text)
        print Fore.WHITE + "[*] sha512 hash genereted: ",sha512.hexdigest() 
