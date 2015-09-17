#! /usr/bin/env python


#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
#
# See RFC2236, Section 2. Introduction for definitions of proper IGMPv2 message format
#   http://www.faqs.org/rfcs/rfc2236.html
#
from scapy.utils import checksum
from scapy.layers.l2 import *
from scapy.config import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import *

igmptypes = { 0x11 : "Group Membership Query",
             0x12 : "Version 1 - Membership Report",
             0x16 : "Version 2 - Membership Report",
             0x17 : "Leave Group"}

class IGMP(Packet):
    '''IGMP Message Class for v1,v2 and v3.
    
    This class is derived from class Packet. You may need to "sanitize" the IP
    and Ethernet headers before a full packet is sent.
    '''
    name = "IGMP"
    fields_desc = [ ByteEnumField("type", 0x11, igmptypes),
                   ByteField("mrtime",0),
                   XShortField("chksum", None),
                   IPField("gaddr", "0.0.0.0")]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # print 'igmp dispatch hook'
        if _pkt:
            if ord(_pkt[0]) == 0x11: #Query
                if len(_pkt)  == 8: # IGMPv2
                    return IGMPv2
                elif len(_pkt) >= 12:
                    return IGMPv3
            elif ord(_pkt[0]) == 0x22: #IGMPv3 Membership Report RFC3376
                return IGMPv3
            elif ord(_pkt[0]) in [0x16,0x17]: #IGMPv2 Membership Report and Leave Group RFC2236
                return IGMPv2

        return cls
        
    def post_build(self, p, pay):
        '''Called implicitly before a packet is sent to compute and place IGMP checksum.
        
        Parameters:
            self    The instantiation of an IGMP class
            p       The IGMP message in hex in network byte order
            pay     Additional payload for the IGMP message
        '''
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
            return p
        
    def mysummary(self):
        '''Display a summary of the IGMP object.'''
        
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("IGMP: %IP.src% > %IP.dst% %IGMP.type% %IGMP.gaddr%")
        else:
            return self.sprintf("IGMP %IGMP.type% %IGMP.gaddr%")
        
    def sanitize (self, ip=None, ether=None):
        '''Called to explicitely fixup associated IP and Ethernet headers
        
        Parameters:
            self    The instantiation of an IGMP class.
            ip      The instantiation of the associated IP class.
            ether   The instantiation of the associated Ethernet.
            
        Returns:
            True    The tuple ether/ip/self passed all check and represents a proper IGMP packet.
            False   One of more validation checks failed and no fields were adjusted.
            
        The function will examine the IGMP message to assure proper format.
        Corrections will be attempted if possible. The IP header is then properly
        adjusted to ensure correct formatting and assignment. The Ethernet header
        is then adjusted to the proper IGMP packet format.
        '''
        
# The rules are:
#   1.  the Max Response time is meaningful only in Membership Queries and should be zero
#       otherwise (RFC 2236, section 2.2)
        if (self.type != 0x11):         #rule 1
            self.mrtime = 0
        if (self.adjust_ip(ip) == True):
            if (self.adjust_ether(ip, ether) == True):
                return True
        return False

    def adjust_ether (self, ip=None, ether=None):
        '''Called to explicitely fixup an associated Ethernet header
        
        Parameters:
            self    The instantiation of an IGMP class.
            ip      The instantiation of the associated IP class.
            ether   The instantiation of the associated Ethernet.
            
        Returns:
            True    The tuple ether/ip/self passed all check and represents a proper IGMP packet.
            False   One of more validation checks failed and no fields were adjusted.
            
            The function adjusts the ethernet header destination MAC address based on the destination IP address.
            '''
# The rules are:
#   1. send the packet to the group mac address address corresponding to the IP
        if ip != None and ip.haslayer(IP) and ether != None and ether.haslayer(Ether):
            ipaddr = socket.ntohl(atol(ip.dst)) & 0x007FFFFF
            macstr = "01:5e:00:%02x:%02x:%02x" %((ipaddr>>16)&0xFF, (ipaddr>>8)&0xFF, (ipaddr>>0)&0xFF)
            ether.dst=macstr
            return True
        else:
            return False

    def adjust_ip (self, ip=None):
        '''Called to explicitely fixup an associated IP header
        
        Parameters:
            self    The instantiation of an IGMP class.
            ip      The instantiation of the associated IP class.
            
        Returns:
            True    The tuple ip/self passed all checks and represents a proper IGMP packet.
            False   One of more validation checks failed and no fields were adjusted.
            
            The function adjusts the IP header based on conformance rules and the group address
             encoded in the IGMP message.
        '''
# The rules are:
#   1. send the packet to the group address registering/reporting for
#     a. for General Group Query, send packet to 224.0.0.1 (all systems)
#   2. send the packet with the router alert IP option (RFC 2236, section 2)
#   3. ttl = 1 (RFC 2236, section 2)
        if ip != None and ip.haslayer(IP):
            if (self.type == 0x11):
                if (self.gaddr == "0.0.0.0"):
                    ip.dst = "224.0.0.1"
                    retCode = True
                elif (atol(self.gaddr)&0xff >= 224) and (atol(self.gaddr)&0xff <= 239):
                    ip.dst = self.gaddr
                    retCode = True
                else:
                    retCode = False
            elif ((self.type == 0x12) or (self.type == 0x16) or (self.type == 0x17)) and (atol(self.gaddr)&0xff >= 224) and (atol(self.gaddr)&0xff <= 239):
                ip.dst = self.gaddr
                retCode = True
            elif (self.type == 0x22):
                ip.dst = "224.0.0.22"
                retCode = True
            elif (self.type == 0x30) or (self.type == 0x32):
                ip.dst = "224.0.0.106"
                retCode = True
            elif (self.type == 0x31):
                ip.dst = "224.0.0.2"
                retCode = True
            else:
                retCode = False
        else:
            retCode = False
        if retCode == True:
            ip.options="\x94\x04\x00\x00"   # set IP Router Alert option
        return retCode



class IGMPv2(IGMP):
    name    =   'IGMPv2'
    fields_desc =   [ ByteEnumField('type',0x11,{0x11:'Membership Query',
                                                  0x16:'Version 2 Membership Report',
                                                  0x17:'Leave Group',
                                                  0x12:'Version 1 Membership Report'}),
                      ByteField('max_resp_time',100),
                      XShortField('chksum',None),
                      IPField('group_addr','0.0.0.0'),
                      
                    ]
                    
    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            c = checksum(p)
            p = p[:2]+chr((c>>8)&0xff)+chr(c&0xff)+p[4:]
        return p

igmpv3grtypes = { 1 : "IS_IN",   #"Mode Is Include",
                 2 : "IS_EX",    #"Mode Is Exclude",
                 3 : "TO_IN",    #"Change To Include Mode",
                 4 : "TO_EX",    #"Change To Exclude Mode",
                 5 : "ALLOW",    #"Allow New Sources",
                 6 : "BLOCK",    #"Block Old Sources"
                 }

class IGMPv3gr(Packet):
    '''IGMP Group Record for IGMPv3 Membership Report
    
    This class is derived from class Packet and should be concatenated to an
    instantiation of class IGMPv3. Within the IGMPv3 instantiation, the numgrp
    element will need to be manipulated to indicate the proper number of
    group records.
    '''
    
    name = "IGMPv3gr"
    fields_desc = [ ByteEnumField("rtype", 1, igmpv3grtypes),
                   ByteField("auxdlen",0),
                   ShortField("numsrc", 0),#FieldLenField("numsrc", 0, count_of = "srcaddrs"),
                   IPField("maddr", "0.0.0.0"),
                   FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"), count_from = lambda x:x.numsrc), ]
    show_indent=0
    
    def post_build(self, p, pay):
        '''Called implicitly before a packet is sent.'''
        print("p=%s and pay = %s" %(p,pay))
        p += pay
        if self.auxdlen != 0:
            print "NOTICE: A properly formatted and complaint V3 Group Record should have an Auxiliary Data length of zero (0)."
            print "        Subsequent Group Records are lost!"
        return p
        
    def mysummary(self):
        '''Display a summary of the IGMPv3 group record.'''
        return self.sprintf("IGMPv3 Group Record %IGMPv3gr.type% %IGMPv3gr.maddr%")

    def extract_padding(self, p):
        return "",p

igmpv3types = { 0x11 : "Membership Query",
               0x22 : "Version 3 Membership Report",
               0x30 : "Multicast Router Advertisement",
               0x31 : "Multicast Router Solicitation",
               0x32 : "Multicast Router Termination"}

class IGMPv3(IGMP):
    '''IGMP Message Class for v3.
    
    This class is derived from class IGMP.
    The fields defined below are a direct interpretation of the v3 Membership Query Message.
    'chksum' is automagically calculated before the packet is sent.
    'mrcode' is also the Advertisement Interval field
    '''
    
    name = "IGMPv3"
    fields_desc = [
                    ByteEnumField("type", 0x11, igmpv3types),
                   
                    #for igmpv3query
                    ConditionalField(ByteField("mrcode",0), lambda x:x.type==0x11),
                    ConditionalField(XShortField("chksum", None),lambda x:x.type==0x11),
                    ConditionalField(IPField("group_addr", "0.0.0.0"),lambda x:x.type==0x11),
                    ConditionalField(BitField("resv",0,4),lambda x:x.type==0x11),
                    ConditionalField(BitField("s",0,1),lambda x:x.type==0x11),
                    ConditionalField(BitField("qrv",0,3),lambda x:x.type==0x11),
                    ConditionalField(ByteField("qqic",0),lambda x:x.type==0x11),
                    ConditionalField(FieldLenField("numsrc", 0, count_of ="srcaddrs"),lambda x:x.type==0x11),
                    ConditionalField(FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"), count_from = lambda x:x.numsrc),lambda x:x.type==0x11 and x.numsrc>0),
                    
                    #for igmpv3report
                    ConditionalField(ByteField("rsvd1", 0),lambda x:x.type==0x22),
                    ConditionalField(XShortField("chksum", None),lambda x:x.type==0x22),
                    ConditionalField(ShortField("rsvd2", 0),lambda x:x.type==0x22),
                    ConditionalField(ShortField("numgrp", 0),lambda x:x.type==0x22),
                    ConditionalField(PacketListField("grouprecords", None, IGMPv3gr, count_from= lambda x:x.numgrp),lambda x:x.type==0x22 and x.numgrp>0),
                    ]

    def float_encode(self, value):
        '''Convert the integer value to its IGMPv3 encoded time value if needed.
        
        If value < 128, return the value specified. If >= 128, encode as a floating
        point value. Value can be 0 - 31744.
        '''
        if value < 128:
            code = value
        elif value > 31743:
            code = 255
        else:
            exp=0
            value>>=3
            while(value>31):
                exp+=1
                value>>=1
            exp<<=4
            code = 0x80 | exp | (value & 0x0F)
        return code
    
    def post_build(self, p, pay):
        '''Called implicitly before a packet is sent to compute and place IGMPv3 checksum.
        
        Parameters:
            self    The instantiation of an IGMPv3 class
            p       The IGMPv3 message in hex in network byte order
            pay     Additional payload for the IGMPv3 message
        '''
        p += pay
        if self.type in [0, 0x31, 0x32, 0x22]:   # for these, field is reserved (0)
            p = p[:1]+chr(0)+p[2:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p
    
    def mysummary(self):
        """Display a summary of the IGMPv3 object."""
        
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("IGMPv3: %IP.src% > %IP.dst% %IGMPv3.type% %IGMPv3.gaddr%")
        else:
            return self.sprintf("IGMPv3 %IGMPv3.type% %IGMPv3.gaddr%")


bind_layers( IP,           IGMP,          proto=0x02)
    
