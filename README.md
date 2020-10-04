# swagmac
Network activity monitor

Collects various information available form the local area network.

Input is obtained from the dhcp server, local area network scanning (nmap), the namaged switches, and the UniFi WiFi control server. In addition, the oui.txt file vailable from https://gitlab.com/wireshark/wireshark/-/raw/master/manuf is used.

The program assembles a list of all MACs seen on the local network and incorporates the results into a xml format master file maintanined by the program. The data saved includes MAC, hostname (if available), vendor, last known ip address.
