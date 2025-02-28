#!bin/sh
#Flush and delete all previous defined rules and chains
iptables -t filter -F           #Flush all previous filter rules
iptables -t filter -X           #Delete previously defined filter rules
iptables -t mangle -F           #Flush all previous mangle rules
iptables -t mangle -X           #Delete previously defined mangle rules
iptables -t nat -F              #Flush all previous nat rules
iptables -t nat -X              #Delete previously defined nat rules
iptables -t raw -F              #Flush all previous raw rules
iptables -t raw -X              #Delete previously defined raw rules

#Write a rule that only accepts packets that originate from F1.com
iptables -A INPUT -s F1.com -j ACCEPT

#For all outgoing packets, change their source IP address to your own machine's IP Address
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

#Write a rule to protect yourself against indiscriminate and nonstop scanning of ports on your machine
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m limit --limit 1/s -j ACCEPT

#Write a rule to protect yourself from a SYN-flood Attack by limiting the number of incoming 'new connection' requests to 1 per second once your machine has reached 500 requests
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m limit --limit 1/s --limit-burst 500 -j ACCEPT

#Write a rule to allow full loopback access on your machine i.e. access using localhost
iptables -A INPUT -i lo -j ACCEPT       #Accept loopback access for input packets
iptables -A OUTPUT -o lo -j ACCEPT      #Accept loopback access for output packets

#Write a port forwarding rule that routes all traffic arriving on port 8888 to port 25565. Make sure you specify the correct table and chain. Subsequently, the target for the rule should be DNAT
iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 127.0.0.1:25565

#Write a rule that only allows outgoing ssh connections to engineering.purdue.edu. You will need two rules, one for the INPUT chain and one for the OUTPUT chain and one for the FILTER table. Make sure to specify the correct options for the --state suboption for both rules
iptables -A INPUT -p tcp --dport 22 -s 128.46.104.20 -m state --state ESTABLISHED -j ACCEPT             #Input chain rule
iptables -A OUTPUT -p tcp --dport 22 -d 128.46.104.20 -m state --state NEW,ESTABLISHED -j ACCEPT        #Output chain rule
 
#Drop any other packets if they are not caught by the rules above
iptables -A INPUT -j DROP       #Drop input packets int filter table
iptables -A OUTPUT -j DROP      #Drop output packets in filter table
iptables -A FORWARD -j DROP     #Drop forward packets in filter table