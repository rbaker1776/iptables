#!/bin/bash

# flush existing tables
sudo iptables -F
# delete user-defined chains
sudo iptables -X

# reject packets from f1.com
sudo iptables -A INPUT -s f1.com -j REJECT

# enable MASQUERADE for outgoing packets
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# protect port scanning
sudo iptables -N PORTSCAN
sudo iptables -A PORTSCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j RETURN
sudo iptables -A PORTSCAN -j DROP
sudo iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK -j PORTSCAN

# block SYN flooding
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 500 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP

# loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# forward from 8888 to 25565
sudo iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination :25565

# only allow ssh to engineering.purdue.edu
sudo iptables -A OUTPUT -p tcp --dport 22 -d engineering.purdue.edu -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --sport 22 -s engineering.purdue.edu -m state --state ESTABLISHED -j ACCEPT

# drop all others
sudo iptables -A INPUT -j DROP
sudo iptables -A FORWARD -j DROP
sudo iptables -A OUTPUT -j DROP
