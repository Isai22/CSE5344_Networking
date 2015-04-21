# -*- coding: utf-8 -*-
"""
Created on Sun Feb 22 22:23:13 2015

@author: Daniel Aguilera
NetID: 1000659280
Class: CSE5344
Assignment: Lab 2

This program is to create a client host that will utilze UDP to send data
segments to a server host and then print the time it was sent and the 
Rount Trip Time that the packet took. If the segment take longer than 
1 second then it should return that it Timed Out and therefore that 
packet was lost.
"""

"""
import the needed classes and libraries needed
"""
from socket import  *
from datetime import *

def main() :

    #create the port number 12000 and the serverName set to 'localhost'
    serverPort = 12000
    serverName = 'localhost'
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    
    #start the counter to track the number of pings sent
    pings = 0;
    #variables used to track the min, max, and average RTT
    #had to encapsulate the integers as timedelta objects
    minimumRTT = timedelta(1000);
    maximumRTT = timedelta(-1);
    averageRTT = timedelta(0);
    numTimeOuts = 0;
    #while loop that runs a certain number of times; dependent on number of packets/segments
    while(pings<10) :
        #increment number of segments sent by one each loop        
        pings += 1;
        #take the current time for when the segment is sent to the server
        a = datetime.now()
        #message sent to the server in the sendto() function 
        message = 'ping' +  ' number ' + str(pings) + ' hit at ' + str(a)       
        clientSocket.sendto(message, (serverName, serverPort))
        #set the timeout time to just 1 second
        clientSocket.settimeout(1)    
        
        """
        This section attemps to read a returned message, if it fails it will then
        print that the segment timedout meaning that the segment was lost        
        """        
        try:
            #modified message returned by the server and the address
            modifiedMessage, serverAddress = clientSocket.recvfrom(1048)
            #take the current time when the message is returned by the server
            b = datetime.now()
            #find the difference from time sent to time received and store in 'c'
            c = b-a
            #sum all the RTT to be able to get the average
            averageRTT = c + averageRTT
            #find the biggest RTT
            if(c>maximumRTT) :
                maximumRTT = c
            #find the smallest RTT
            if(c<minimumRTT) :
                minimumRTT = c
            """
            print the returned message and the amount of time that it took for the RTT
            in seconds
            """
            print modifiedMessage
            print 'elapsed RTT in seconds is: ', str(c.total_seconds()), '\n'            
        except timeout:
                #track number of packets lost to use in calculating the average RTT
                numTimeOuts += 1
                print 'Request Timed Out!\n'
    
    #section that signals the end of transmission and gives the min, max, and average RTTs
    print "\nTransmission closed!\n"
    print "Minimum RTT: ", minimumRTT.total_seconds()
    print "Maximum RTT: ", maximumRTT.total_seconds()
    print "Average RTT: ", (averageRTT/(10-numTimeOuts)).total_seconds()
      
    #close the socket once all is done
    clientSocket.close()


if __name__ == '__main__': 
    main()