# swagmac
Network activity monitor

Collects various information available form the local area network.

Input is obtained from opsi, the dhcp server, local area network scanning (nmap), the managed switches, and the UniFi WiFi control server. In addition, the oui.txt file vailable from https://gitlab.com/wireshark/wireshark/-/raw/master/manuf is used.

The program assembles a list of all MACs seen on the local network and incorporates the results into a xml format master file maintained by the program. The data saved includes MAC, hostname (if available), vendor, last known ip address.

The master xml file format is based on the xml format used by nmap. A short example follows:

<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.111" addrtype="ipv4"/>
    <address addr="0c:9a:42:18:3f:6c" addrtype="mac" vendor="Fn-Link Technology Limited"/>
    <hostnames>
      <hostname name="andrew.swag.local" type="PTR"/>
    </hostnames>
  </host>
  <host>
    <address addr="10.0.0.151" addrtype="ipv4"/>
    <address addr="88:12:4e:0f:3d:3c" addrtype="mac" vendor="Qualcomm Inc."/>
    <hostnames>
      <hostname name="bethlehem.swag.local" type="PTR"/>
    </hostnames>
  </host>
  <host>
    <address addr="10.0.0.40" addrtype="ipv4"/>
    <address addr="f8:bc:12:a8:27:3c" addrtype="mac" vendor="Dell"/>
    <hostnames>
      <hostname name="bookkeeper-pc.SWAG.local" type="PTR"/>
    </hostnames>
  </host>
</nmaprun>

The input file is expected to be on MACdata.xml. When the program terminates, an updated copy of the file will be saved as MACdataOut.xml and a copy of the old mac data is saved in oldmaclist.txt. If you are happy with the run, you should move MACdataOut.xml to MACdata.xml. Doing so will permanently save any new MAC data that the program found.

The program takes three run time optional arguments:
The first argument is the location of the "config" file. This file contains a list of all of the input files to be processed as well as their respective output (listing) files. The format of the config file is listed below.
The second argument is primarily used for program debug/checkout. It controls which section of the code (which input file) is to be run. If set to "all", then all of the input files will be read. It can be used to mask the processing options specified in the config file.
The third argument specifies the name of the file containing switch information. This argument is ignored if a switch file is specified in the config file. By successively running the program against each switch on the network and examining the portlist.txt output file, it's possible to guess the relative configuration of the network.

The "config" file looks similar to this:

1,opsiMACs.csv,maclist.txt,0
2,scan2X.txt,maclistscan.txt,0
3,unifimac.txt,maclist3.txt,0
4,leases.txt,maclist4.txt,0
5,oui.txt,ouilist.txt,0
7,MyUserName,MyPassword,0
8,10.0.0.2,T2600G-28TS-SEP24.txt,1
6,T2600G-28TS-SEP24.txt,portlist-T2600G-28TS-SEP24.txt,0

Each line specifies a file to be processed or an option to run. The first field on the line is the option type. the types are as follows:
1 -> process opsi data file
2 -> process local network scan file
3 -> process UniFi WiFi data file
4 -> process dhcp lease data file
5 -> process OUI database file
6 -> process switch data file
7 -> specify username/password data
8 -> connect to switch via telnet and create switch data file
For type 1-6, the second field is the name of the input file. For type 7 it is the username. For type 8 it is the host name or ip address. The third field is the name to use for the output file (except for type 7 where it is the password). The fourth field is not used with all formats. However, it must be present. It is intended to be used to specify additional format information.
Note that the lines in the config file are processed in the order that they are read. I.e., if you intend to process switch data using your latest updates to the MAC database, you should include all type 6 lines after the lines performing your MAC updates.


The portlist output file is produced when processing type 6 input. The default file name is portlist.txt. The output file looks something like this:

 line found : "T2600G-28TS(config)#show mac address-table vlan 1"
 line found : ""
 line found : "                    MAC Address Table                    "
 error : mac address bad on line 3
 line found : "------------------------------------------------------------  "
 line found : "MAC                VLAN    Port     Type            Aging    "
 error : mac address bad on line 5
 line found : "---                ----    ----     ----            -----    "
 error : mac address bad on line 6
 line found : "00:15:17:68:90:55  1       Gi1/0/23 dynamic         aging    "
 line found : "00:15:17:ea:56:10  1       Gi1/0/16 dynamic         aging    "
 line found : "00:17:f2:02:ca:1e  1       Gi1/0/16 dynamic         aging    "
 warning : MAC address connected to port 16 at line 9 not in database. It's vendor is Apple, Inc.
 line found : "00:1a:a0:8f:47:aa  1       Gi1/0/16 dynamic         aging    "
 line found : "00:1d:72:bb:fa:f4  1       Gi1/0/21 dynamic         aging    "
 line found : "00:1e:67:19:4d:60  1       Gi1/0/16 dynamic         aging    "
 line found : "00:20:6b:0b:8f:f3  1       Gi1/0/16 dynamic         aging    "
 line found : "00:20:6b:ea:9f:e7  1       Gi1/0/16 dynamic         aging    "
 line found : "00:25:64:04:51:fc  1       Gi1/0/16 dynamic         aging    "
 line found : "00:25:b3:0a:07:e8  1       Gi1/0/16 dynamic         aging    "
.
. (etc)
.
 line found : "f8:bc:12:a8:27:3c  1       Gi1/0/20 dynamic         aging    "
 line found : ""
 line found : ""
-----------------------
"iPhone.SWAG.local"
"Apple"
b8:b2:f8:72:2b:bd
10.0.0.79
Port 5
-----------------------
"C-2.SWAG.local"
"Ubiquiti Networks Inc."
74:83:c2:96:df:f1
10.0.0.101
Port 5
-----------------------
"iPad-Pro-11.SWAG.local"
"bogus"
22:27:ab:4e:42:db
10.0.0.170
Port 5


The initial section is an echo of the (switch) input file with some diagnostic messages. The bottom section is a sorted list (by switch port number) of all of the machines that the switch has recently seen. The input file includes the switch's MAC cache.

The type 1 input is opsi data. The default opsi input file name is opsiMACs.csv. It is created using opsi-configed: First, show all clients and make sure that "Show OPSI MAC address" is selected in the clients pane. Select all of the data in the clients pane and copy it to your clipboard (use <ctrl>Ins). Next open your speadsheet program and paste the clipboard data into a blank worksheet. Finally, save the data in .csv format. If the data is coming form Windows, you'll likely need to convert it to 8 bit ascii. (use dos2uni). The final file should look something like the following:

"andrew.swag.local","student tablet (RCA)",,"2020-03-17 14:45:47","10.0.0.111","0c:9a:42:18:3f:6c"
"bethlehem.swag.local","student tablet",,"2020-09-02 11:03:52","10.0.0.151","88:12:4e:0f:3d:3c"
"bookkeeper-pc.swag.local",,,"2020-09-09 17:35:05","10.0.0.40","f8:bc:12:a8:27:3c"
"caesarea.swag.local","student tablet (missing)",,"2018-09-10 12:55:44",,
"cana.swag.local","student tablet",,"2019-12-09 17:22:24","10.0.0.38","88:12:4e:0f:37:00"
.
.
.


The default input file name for type 2 input (local network scan data) is scan2X.txt. It should be in standard nmap xml output format. For example, it can be generated as so: sudo nmap -sn -oX scan2X.txt 10.0.0.0/23


The default input file name for type 3 input (UniFi WiFi mac data) is unifimac.txt. It is generated using the UniFi controller web app. Open the controller and select the "Insights" tab. Use your mouse to select all of the data displayed in the main pane and copy to your clipboard. Paste the data into a text editor. The file will look something like this:


	Name	Manufacturer	Mac	Fixed IP	User/Guest	Down	Up	First Seen	Last Seen	
1-100 of 101 records
Rows per page
	06:b5:12:37:bb:71		06:b5:12:37:bb:71	-	Guest	28 MB	4.52 MB	09/23/2020 6:49 pm	09/23/2020 8:37 pm	
	42:21:c4:9f:42:1c		42:21:c4:9f:42:1c	-	Guest	1.89 MB	810 KB	09/22/2020 8:29 am	09/24/2020 12:12 pm	
	48:f1:7f:d3:17:97	IntelCor	48:f1:7f:d3:17:97	-	Guest	235 MB	33.9 MB	09/16/2020 5:59 pm	09/23/2020 7:08 pm	
	4a:ec:7f:96:8b:9f		4a:ec:7f:96:8b:9f	-	Guest	2.15 MB	1.23 MB	09/23/2020 8:41 am	09/24/2020 12:12 pm	
	72:55:3d:35:60:37		72:55:3d:35:60:37	-	Guest	17.7 MB	4.55 MB	09/21/2020 3:08 pm	09/24/2020 8:44 am	
	AV-Galaxy	SamsungE	a4:6c:f1:45:d8:b6	-	Guest	3.08 MB	1.02 MB	12/18/2019 3:17 pm	09/24/2020 12:12 pm	
	b4:69:21:04:77:7f	IntelCor	b4:69:21:04:77:7f	-	Guest	2.08 GB	190 MB	09/08/2020 9:35 am	09/24/2020 10:35 am	
.
.
.


The default input file name for type 4 input (dhcp lease input file) is leases.txt. If your dhcp server is a Windows server, it can be generated using your dhcp server snap in. Select your server - IPv4 - Scope - Address Leases in the left hand pane. Select all of the data in the center pane and then click the "Export List" button on the toolbar. Select the csv output format. Note that this file will need to be converted to 8 bit ascii when you move it to your linux machine...   A sample output follows:


Client IP Address,Name,Lease Expiration,Type,Unique ID,Description,Network Access Protection,Probation Expiration,Filter Profile,Policy
10.0.0.11,DESKTOP-SDRAR14.SWAG.local,10/1/2020 8:38:44 AM,DHCP,d017c28ba606,,Full Access,N/A,None,
10.0.0.12,iPad-4.SWAG.local,9/28/2020 9:51:52 AM,DHCP,103025b1711f,,Full Access,N/A,None,
10.0.0.13,iPad-Pro-129.SWAG.local,9/28/2020 8:36:59 AM,DHCP,70480fbc799c,,Full Access,N/A,None,
10.0.0.15,AT&T MicroCell,Reservation (active),DHCP,702e6163636573732d33472d41502d3734353437442d30303236393139393330,The AT&T MicroCell device in Dareld's office,Full Access,N/A,None,
10.0.0.16,ICA-72.campus.islandchristianacademy.com,10/2/2020 9:22:30 AM,DHCP,f0761c88d6d3,,Full Access,N/A,None,
10.0.0.21,front-office.SWAG.local,10/2/2020 9:55:41 AM,DHCP,001cc0fe56ae,,Full Access,N/A,None,
10.0.0.22,android-217583c42a90d142.SWAG.local,9/27/2020 1:37:26 PM,DHCP,a470d6b04b8d,,Full Access,N/A,None,
10.0.0.23,,10/1/2020 8:19:59 AM,DHCP,3eab9cf226a5,,Full Access,N/A,None,
.
.
.

The default input file name for type 5 input (a current copy of the OUI database file) is oui.txt. See the comment near the top of this file for where to download this guy...
The main body of the file will look something like this:

00:00:00	00:00:00	Officially Xerox, but 0:0:0:0:0:0 is more common
00:00:01	Xerox	Xerox Corporation
00:00:02	Xerox	Xerox Corporation
00:00:03	Xerox	Xerox Corporation
00:00:04	Xerox	Xerox Corporation
00:00:05	Xerox	Xerox Corporation
00:00:06	Xerox	Xerox Corporation
00:00:07	Xerox	Xerox Corporation
00:00:08	Xerox	Xerox Corporation
00:00:09	Powerpip	powerpipes?
00:00:0A	OmronTat	Omron Tateisi Electronics Co.
00:00:0B	Matrix	Matrix Corporation
00:00:0C	Cisco	Cisco Systems, Inc
00:00:0D	Fibronic	Fibronics Ltd.
00:00:0E	Fujitsu	Fujitsu Limited
.
.
.


The default input file name for type 6 input (switch data) is 24portMACs.txt. However, this file name can also be specified as a run time argument to the program. The format of this file is based on the output produced by T-Link managed switches (which varies somewhat between models). A sample follows:


00-12-3F-B3-66-DC	1	20	Dynamic	Aging
00-15-17-68-90-55	1	7	Dynamic	Aging
00-15-17-EA-56-10	1	6	Dynamic	Aging
00-17-F2-02-CA-1E	1	4	Dynamic	Aging
00-1A-A0-8F-47-AA	1	20	Dynamic	Aging
00-1C-C0-FE-56-AE	1	4	Dynamic	Aging
.
.
.


The type 7 input option is used to set the username and password data sent when connecting to a switch via telnet (type 8). The "input file" field is used for the username and the "output file" field is used to specify the password. The default username and password are blank. If you are connecting to multiple switches with different passwords, each type 8 option should be proceeded with a new type 7. If all of your switches share the same username/password, then this option only needs to be specified once (before the first type 8 config line).


The type 8 input option is used to connect to switches via telnet to download switch information. The "input file" field specifies the ip address or hostname of the switch to be contacted. The "output file" field specifies where the switch data is to be saved. The format of the output file will be compatible with the input file used for type 6 switch processing. Thus, to process up-to-date switch information, you would first download fresh switch information to a local file using the type 8 option and follow it with a type 6 option that processes the file created by the type 8 option. Presently, the only switches supported by this option are the T-Link managed switches. It has been tested with TL-SG2424, TL-SG2216, and T2600G-28TS switches. It recognizes two flavors of T-Link commands and the format option field is used to specify which format is expected. The format option should be set to 0 for TL-SG2424 and TL-SG2216 switches and set to 1 for T2600G-28TS switches. The sequence of commands used by format 0 are : {"username","password","\r","enable","configure","show mac address-table address all","exit","exit","exit"}. While the sequence of commands used by format 1 are : {"username","password","enable","configure","show mac address-table vlan 1","exit","exit","exit"}


General processing of the program:
The program starts by looking for old MAC data on the MACdata.xml file. It then reads each line of the config file and processes options mentioned above. Options 1-4 look for MACs that are not yet in its database. Option 5 loads the oui database used to identify vendors. Option 6 reads switch data and matches each of the MACs in the switch's cache with the data in the database and outputs all known data for each computer seen by the switch (sorted by switch port number). Before exiting, the program copies all data in its MAC database to MACdataOut.xml. A typical order of options in the config file would be 7,8,1,2,3,4,5,6.




