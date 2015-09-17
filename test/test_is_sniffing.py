#!/usr/bin/python
#coding:utf-8


from scapy.all import *
from threading import Thread

class ScapySniff(Thread):
    def __init__(self):
        Thread.__init__(self)


    def run(self):
        sniff(timeout=30)

ss = ScapySniff()
ss.start()
for i in range(0,13):
    print 'sniffing:',is_sniffing()
    time.sleep(2)
    
print 'stop sniff'
stop_sniff()
for i in range(0,13):
    print 'sniffing:',is_sniffing()
    time.sleep(2)

