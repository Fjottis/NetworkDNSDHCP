Instruction for DNS/DHCP trace Project
================

## Installation

Basic installation : 
1. Install the libraries required with : `pip install
-r requirements.txt` in your file

2. Verify that you have the database in the file
   
Optional : 
1. If you want the icon of the notification to be printed change the path for the path of the repository in your computer
2. If you want the function email to work ,add your email address in the function mail as sender and the password of your address in password.  
example : sender = 'myemail@gmail.com' password = 'mypassword'


## Run the program

Run the following command in the repository location : `python3 main.py`

Option :
* You can choose your interface with the **-i** (or **–iface**) followed
by your port name

* The verbose mode causes main.py to print the DNS and DHCP frames while
storing them in the database. If you want to see the Verbose mode,run
the command with the **-v** (or **–verbose**) flag

Examples :
* `python3 main.py -i en1`  
* `python3 main.py -i en1 -v`

You can also filter more MAC address by adding them directly in the table
UnauthorizedDNS

DISCLAIMER:

EN I am not responsible for the misuse of this script, it isn't in any case a tool to be used for malicious purposes. 

FR Je ne suis pas responsable d'abus d'utilisation de ce script par autrui, il ne devrait en aucun cas être utilisé à des fins malveillantes. 
