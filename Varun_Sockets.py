# -*- coding: utf-8 -*-
"""
Created on Tue Mar 31 21:51:43 2015

@author: Isaiah


This program is a simple packet sniffer. It will sniff packets and display
important packet information.
"""

"""
NOTES:
    1.Ask the user which protocols they would like to see: ALL, TCP, UDP, OTHER
    2.Display the next batch(10,20,50?) and ask the user if they wany to see more
    3.If the user says no then exit the program.
    4.Keep timer and cumulative size or number of packets
    5.Measure throughput, display in graph
    
    to get the throughput we can have a server running which our program will bind to and
    send a file, we measure the time for it and that will give us the RTT. Also we can store the data
    so that we can then filter through it according to the user
    
    
"""

import socket
import sys
from struct import *
import re
import sys, time
#from socket import *
import plotly.plotly as py
from plotly.graph_objs import *




MY_PORT = 50000 + 42

BUFSIZE1 = 1024

def main() :
    read_data()
    
def read_data() :

    
    HOST = socket.gethostbyname(socket.gethostname())    
    
    try :        
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        print 'Successfully Created Raw Socket!'
    
        s.bind((HOST, 0))
     
        #Include IP headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        #receive all packages
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        count = 0
        print "{TCP, UDP, ICMP}"
        option = raw_input("Pick an Option: \n")
        option = option.upper()
        while True:
            packet = s.recvfrom(65565)
            #print 'hi'
            #print "\nOriginal IP: "+str(packet[1])
            packet = packet[0]
            """
            #parse ethernet header
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = unpack('!6s6sH' , eth_header)
            eth_protocol = socket.ntohs(eth[2])
            print "Protocol: "+ str(eth_protocol)
            """
            
            ipHeader = packet[0:20]
            #unpack the data found in the ip datagram, there are 10 items
            ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
            version_IPHeaderLength = ipDatagram[0]
            ipVer = version_IPHeaderLength >> 4
            #0xF is 15 and the '&' operand copies a bit to the result if it exists
            #in both operands            
            ipHeaderLength = version_IPHeaderLength & 0xF
            #
            iphl = ipHeaderLength * 4
            TOS = ipDatagram[1]            
            totalLength = ipDatagram[2]
            ID = ipDatagram[3]
            flags = ipDatagram[4]
            fragments = ipDatagram[4] & 0x1FFF
            #time to live
            ttl = ipDatagram[5]
            #transport protocol
            protocol = ipDatagram[6]
            checksum = ipDatagram[7]
            #source and destination ip addresses
            sourceIP = socket.inet_ntoa(ipDatagram[8])
            destinationIP = socket.inet_ntoa(ipDatagram[9])
            if(ipVer == 6):
                print "version 6"
            """    
            print "\n\nVersion: \t\t" + str(ipVer)
            print "Header Length: \t\t" + str(iphl) + " bytes"
            #print "Type of Service: \t" + TypeOfService(TOS)
            #print "Length:\t\t\t" + str(totalLength)
            #print "ID:\t\t\t" + str(hex(ID)) + '(' +str(ID) + ')'
            print "Flags:\t\t\t" + getFlags(flags)
            #print "Fragment Offset:\t" + str(fragments)
            #print "TTL:\t\t\t" + str(ttl)
            print "Protocol:\t\t" + getProtocol(protocol)
            #print "Checksum:\t\t" + str(checksum)
            print "SourceIP:\t\t" + sourceIP
            print "DestinationIP:\t\t" + destinationIP
            """
            if(protocol == 6 and option == 'TCP'):
                
                tcp_header = packet[iphl:iphl+20]
                #unpack the tcp header information                
                tcph = unpack('!HHLLBBHHH', tcp_header)
                source_port = tcph[0]
                destination_port = tcph[1]
                sequence = tcph[2]
                acknowledgment = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                
                #extract all the flags from the tcp header
                getTCPFlags(tcph[4], tcph[5])                
                
                print 'Source Port {}, Destination Port {}, sequence {}'.format(source_port, destination_port, sequence)
                print 'Acknowledgement {}, TCP Length {}'.format(acknowledgment, tcph_length)
                
                header_size = iphl + tcph_length * 4
                data_size = len(packet) - header_size
                data = packet[header_size:]                
              
            elif(protocol == 17 and option == 'UDP'):
                udpl = 8
                udp_header = packet[iphl:iphl+8]
                #unpack the udp header which is much smaller than TCP
                udph = unpack('!HHHH', udp_header)
                
                source_port = udph[0]
                destination_port = udph[1]
                length = udph[2]
                checksum = udph[3]
                
                print 'Source Port: {}, Destination Port: {}'.format(source_port, destination_port)
                print 'length: {}, checksum: {}'.format(length, checksum)                
                
                header_size = iphl + udpl
                data = packet[header_size:]
                
            elif(protocol == 1 and option == 'ICMP'):
                icmpl = 8
                icmp_header = packet[iphl:iphl+icmpl]
                #unpack the ICMP header which is only 4bytes
                icmp = unpack('!BBHHH',icmp_header)
                icmp_type = icmp[0]
                icmp_code = icmp[1]
                icmp_identifier = icmp[3]
                icmp_sequence = icmp[4]
                icmp_checksum = icmp[2]
                
                print "Type: {}, Code: {}, Checksum: {}".format(icmp_type, icmp_code, icmp_checksum)
                print "Identifier: {}, Sequence: {}".format(icmp_identifier, icmp_sequence)
            else:
                print "\n\nOther Protocol\n\n"                
            count = count + 1
            if(count == 10):
                answer = raw_input('Would you like to continue: Y|N \n')
                answer = answer.lower()                
                if(answer == 'y'):
                    count = 0;
                else:
                    ram, rams = server()               
            
                                  
    except socket.error, msg:
        print 'Socket could not be created. Error code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    except KeyboardInterrupt :
        print "Interrupted by User!"
    
    
    
    # disable promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()
    
#get time of service - 8bits    
def TypeOfService(data):
    #set up the dictionaries that will contain the possible options
    precedence = {0:"Routine", 1:"Priority", 2:"Immediate", 3:"Flash", 4:"Flash Override", 5:"CRITIC/ECP", 6:"Internetwork Contril", 7:"Network Control"}
    delay = {0:"Normal delay", 1:"Low delay"}
    throughput = {0:"Normal Throughput", 1:"High Throughput"}
    reliability = {0:"Normal reliability", 1:"High reliability"}
    cost = {0:"Normal monetary cost", 1:"Minimize monetary cost"}
    
    #D->delay, T->throughput, R->reliability, M->monetary cost
    #the shift done by '>>=' is a bit operator that takes two binary strings and copies any that match
    #while the rest are all set to 0s.
    #0x10 -> 16, 0x8 -> 8, 0x4 ->4, 0x2 -> 2
    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1
    #string to format the output with a new line and three tabs
    tabs = '\n\t\t\t'
    TimeOfService = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TimeOfService

#returns the flag options for the IP header in a string format for easy printing    
def getFlags(data):
    #dictionaries with available options initialized
    flagR = {0:"0-Reserved Bit"}
    flagDF = {0:"0-Fragment if Necessary", 1:"1-Do Not Fragment"}
    flagMF = {0:"0-Last Fragment", 1:"1-More Fragments"}
    
    #bit wise operator used to shift decimals
    #0x8000 is 10000000 00000000
    #0x4000 is 01000000 00000000
    #0x2000 is 00100000 00000000
    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13
    #string to format the output
    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags
#function that returns the protocol used at the transport layer
def getProtocol(data):
    #open file containing all possible protocols
    protocolFile = open('Protocols.txt', 'r')
    #reads the data in opened file
    protocolData = protocolFile.read()
    #returns all strings that match the patter described, \n + data + ending character
    protocol = re.findall(r'\n' + str(data) + ' (?:.)+\n', protocolData)
    #finds matching protocol on file and returns if one is found
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(data), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return "No Such Protocol Found"
        
def getTCPFlags(reserved, flags) :
    
    #reserved flags
    NS_flag = reserved & 0x1
    
    #congestion Window Reduced
    CWR_flag = flags >> 7
    #ECN-Echo, if SYN = 1 TCP peer is ECN capable, if SYN = 0 packet with congestion received
    ECE_flag = flags >> 6 & 0x1
    #indicates that the Urgent pointer field is significant
    URG_flag = flags >> 5 & 0x1
    #acknowledgement field is significant
    ACK_flag = flags >> 4 & 0x1
    #push function, asks to push the buffered data to the received
    PSH_flag = flags >> 3 & 0x1
    #reset the connection
    RST_flag = flags >> 2 & 0x1
    #synchronize sequence numbers
    SYN_flag = flags >> 1 & 0x1
    #no more data coming
    FIN_flag = flags & 0x1
    
    print "NS: {}\nCWR: {}\nECE: {}\nURG: {}\nACK: {}".format(NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag)
    print "\nPSH: {}\nRST: {}\nSYN: {}\nFIN: {}\n".format(PSH_flag, RST_flag, SYN_flag, FIN_flag)

def server():
    print "varun"
    count = 100
    host = 'localhost'
    port = MY_PORT
    BUFSIZE1 = 1024
    rams = []
    for x in range(0, 19):
        #global throughput
        testdata = 'x' * (BUFSIZE1-1) + '\n'
        t1 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t2 = time.time()
        s.connect((host, port))
        t3 = time.time()
        i = 0
        while i < count:
            i = i+1
            s.send(testdata)
        s.shutdown(1) # Send EOF
        t4 = time.time()
        data = s.recv(BUFSIZE1)
        t5 = time.time()
        print data
        print 'Raw timers:', t1, t2, t3, t4, t5
        print 'Intervals:', t2-t1, t3-t2, t4-t3, t5-t4
        print 'Total:', t5-t1
        #print 'Throughput:', round((BUFSIZE1*count*0.001) / (t5-t1), 3),
        ram = round((BUFSIZE1*count*0.001) / (t5-t1), 3)
        rams.append(ram)
        BUFSIZE1 = BUFSIZE1 + 10240
        #print BUFSIZE1
        print ram
        print 'K/sec.'
   
    trace1 = Scatter(
        x=[rams],
        y=[1, 10, 100]
    )
    data = Data([trace1])

    unique_url = py.plot(data, filename = 'basic-line')

    
    exit()
    
if __name__ == '__main__':
    main()

