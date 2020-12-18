Instruction for DNS/DHCP trace Project
================

## Installation

1 - Install the librairies required with : `pip install
-requirements.txt` in your file

2 - Verify that you have the database in the file

3 - Depending the OS your using ,you should open the file
notification.py and in the funstion notification replace ostype:‘Mac’ to
your OS . Write Mac,Linux,Windows

Optional - If you want the icon of the notification to be printed change th path

## Run the program

Run the following command in the repository location : `python3 main.py`

Option :

You can choose your interface with the **-i** (or **–iface**) followed
by your port name

The verbose mode causes main.py to print the DNS and DHCP frames while
storing them in the database. If you want to see the Verbose mode,run
the command with the **-v** (or **–verbose**) flag

example :

`python3 main.py -i en1`

`python3 main.py -i en1 -v`

You can filter more MAC adress by adding them directly in the table
UnauthorizedDNS
