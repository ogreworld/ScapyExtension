## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import struct

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP
from scapy.layers.ppp import PPP


from scapy.layers.l2 import *
#from win32com.decimal_23 import adjust
#from scapy.layers.dhcp6 import fields_desc
_L2TP_ctrlmsg_type={
      1:'SCCRQ',#    Start-Control-Connection-Request
      2:'SCCRP',#    Start-Control-Connection-Reply
      3:'SCCCN',#    Start-Control-Connection-Connected
      4:'StopCCN',#  Stop-Control-Connection-Notification
      5:'reserved',
      6:'HELLO',#   Hello
      7:'OCRQ',#     Outgoing-Call-Request
      8:'OCRP',#     Outgoing-Call-Reply
      9:'OCCN',#     Outgoing-Call-Connected
      10:'ICRQ',#     Incoming-Call-Request
      11:'ICRP',#     Incoming-Call-Reply
      12:'ICCN', #    Incoming-Call-Connected
      13:'reserved',
      14:'CDN',#      Call-Disconnect-Notify
      15:'WEN',#      WAN-Error-Notify
      16:'SLI',#      Set-Link-Info
      }
_L2TP_type={
            0:'Control message',
            1:'Result code',
            2:'Protocol version',
            3:'Framing capabilities',
            4:'Bearer capabilities',
            5:'Tie breaker',
            6:'Firmware revision',
            7:'Host name',
            8:'Vendor name',
            9:'Assigned tunnel id',
            10:'Receive window size',
            11:'Chanllege',
            12:'Cause code',
            13:'Challenge response',#to do
            14:'Assigned session ID',
            15:'Call serial number',
            16:'Minimum BPS',
            17:'Maximum BPS',
            18:'Bearer type',
            19:'Framing type',
            21:'Called number',
            22:'Calling number',
            23:'Sub-Address',
            24:'Tx Connect speed BPS',
            25:'Physical channel ID',
            26:'Initial received LCP CONFREQ',
            27:'Last send LCP CONFREQ',
            28:'Last received LCP CONFREQ',
            29:'Proxy authen type',
            30:'Proxy authen name',
            31:'Proxy authen challenge',
            32:'Proxy authen ID',
            33:'Proxy authen response',
            34:'Call errors',
            35:'ACCM',
            36:'Random vector',
            37:'Private group ID',
            38:'Rx Connect speed BPS',
            39:'Sequencing required',
            
            
            
            
            }
class _L2TP_Header(Packet):
    fields_desc=[
                 BitEnumField("mandatory",0,1,{0:False,1:True}),
                 BitEnumField("hidden",0,1,{0:False,1:True}),
                 BitField("rsvd",0,4),                
                 ]
class L2TP_AVP(Packet):
    name="L2TP AVP"
    fields_desc=[_L2TP_Header,
                 BitFieldLenField("len",6,10,length_of="attr_value",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",None,_L2TP_type)
                 ]
    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.attr_type.default] = cls
        
        
        
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        
        if _pkt:
            o = ord(_pkt[5])
            return cls.registered_options.get(o, cls)
        return cls

class L2TP_CTRLMSG_AVP(L2TP_AVP):
    name="L2TP Control Message AVP"
    fields_desc=[
                 _L2TP_Header,
                 #BitFieldLenField("len",8,10,length_of="attr_value",adjust=lambda ptk,x:x+6),
                 BitField("len",None,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",0,_L2TP_type),
                 ShortEnumField("ctrlmsg_type",0,_L2TP_ctrlmsg_type)
                 ]
    
_L2TP_stopCCN_resultcode={
                 0:'Reserved',
                 1:'General request to clear control connection',
                 2:'General error--Error Code indicates the problem',
                 3:'Control channel already exists',
                 4:'Requester is not authorized to establish a control channel',
                 5:'The protocol version of the requester is not supported',
                      #Error Code indicates highest version supported
                 6:'Requester is being shut down',
                 7:'Finite State Machine error'                  
                  }
_L2TP_CDN_resultcode={
                      0:'Reserved',
                      1:'Call disconnected due to loss of carrier',
                      2:'Call disconnected for the reason indicated in error code',
                      3:'Call disconnected for administrative reasons',
                      4:'Call failed due to lack of appropriate facilities being available (temporary condition)',
                      5:'Call failed due to lack of appropriate facilities being available (permanent condition)',
                      6:'Invalid destination',
                      7:'Call failed due to no carrier detected',
                      8:'Call failed due to detection of a busy signal',
                      9:'Call failed due to lack of a dial tone',
                      10:'Call was not established within time allotted by LAC',
                      11:'Call was connected but no appropriate framing was detected'           
                      }
#Type 1
class L2TP_RSLTCODE_AVP(L2TP_AVP):
    name="L2TP Result and Error Codes"
    mandatory=1
    fields_desc=[
                 _L2TP_Header,
                 #BitFieldLenField("len",8,10,length_of="error_msg",adjust=lambda ptk,x:x+10),
                 BitField("len",None,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",1,_L2TP_type),
                ShortEnumField("result_code",1,_L2TP_stopCCN_resultcode),
                 ConditionalField(ShortField("error_code",0), lambda p:p.len!=8),
                 #ShortField("error_code",0),
                 ConditionalField(StrLenField("error_msg","", length_from=lambda pkt:pkt.len-10), lambda p:p.len!=8 and p.len!=10),            
                ]
    
    def post_build(self, p, pay):
        if self.len is None:
            l1 = ( len(pay)+len(p) ) & 0x03ff
            l2 = ord(p[:1]) & 0xfc 
            l3 = ( l2 << 8 ) + l1            
            p0 = struct.pack("!H",l3) 
            p = p0 + p[2:]
        return p+pay
    
        
class L2TP_PROTOVER_AVP(L2TP_AVP):
    name="L2TP Protocol Version AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",8,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",2,_L2TP_type),
                 ByteField("ver",1),
                 ByteField("rev",0)                 
                 ]


    
class L2TP_FRAMINGCAP_AVP(L2TP_AVP):
    name="L2TP Framing Capabilities AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",3,_L2TP_type),
                 BitField("frmng_rsvd",0,30),
                 BitField("frmng_asyn",0,1),#to be converted to Enum
                 BitField("frmng_syn",1,1)                 
                 ]
    
class L2TP_BEARERCAP_AVP(L2TP_AVP):
    name="L2TP Framing Capabilities AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",4,_L2TP_type),
                 BitField("bearer_rsvd",0,30),
                 BitField("bearer_analog",0,1),#to be converted to Enum
                 BitField("bearer_digital",1,1)                 
                 ]
#class L2TP_TIEBREAK_AVP to be added here


class L2TP_FIRMWAREREV_AVP(L2TP_AVP):
    name="L2TP Firmware Revision AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",8,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",6,_L2TP_type),
                 ShortField("fm_revison",0)                 
                 ]
class L2TP_HOSTNAME_AVP(L2TP_AVP):
    name="L2TP Host Name AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="hostname",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",7,_L2TP_type),
                 StrLenField("hostname","",length_from=lambda p:p.len-6)                 
                 ]
    
class L2TP_VENDORNAME_AVP(L2TP_AVP):
    name="L2TP Vendor Name AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="vendorname",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",8,_L2TP_type),
                 StrLenField("vendorname","",length_from=lambda p:p.len-6)                 
                 ]    
#,L2TP_TUNNELID_AVP,L2TP_RECVWINSZ_AVP....to be added

class L2TP_ASSGNTUNLID_AVP(L2TP_AVP):
    name="L2TP Assigned Tunnel ID AVP"
    fields_desc=[
                 _L2TP_Header,
                 #BitFieldLenField("len",8,10,length_of="attr_value",adjust=lambda ptk,x:x+6),
                 BitField("len",8,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",9,_L2TP_type),
                 ShortField("assgntunl_id",0)                 
                 ]    
class L2TP_WINSIZE_AVP(L2TP_AVP):
    name="L2TP Window Size AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",8,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",10,_L2TP_type),
                 ShortField("winsize",0)
                 ]

class L2TP_CHALLENGE_AVP(L2TP_AVP):
    name="L2TP Chanllenge AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="challenge",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",11,_L2TP_type),
                 StrLenField("challenge","",length_from=lambda p:p.len-6)                 
                 ]    

class L2TP_CAUSECODE_AVP(L2TP_AVP):
    name="L2TP Cause Code AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="adv_msg",adjust=lambda ptk,x:x+9),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",12,_L2TP_type),
                 ShortField("cause_code",0),
                 ByteField("cause_msg",0),
                 StrLenField("adv_msg","",length_from=lambda p:p.len-9)                 
                 ]      
    
class L2TP_ASSGNSESNID_AVP(L2TP_AVP):
    name="L2TP Assigned Session ID AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",8,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",14,_L2TP_type),
                 ShortField("assgnsesn_id",0)
                 ]
                 
class L2TP_CALLSERLNUM_AVP(L2TP_AVP):
    name="L2TP Call Serial Number AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",15,_L2TP_type),
                 IntField("callserl_num",0)
                 ]                 
                 
class L2TP_MINBPS_AVP(L2TP_AVP):
    name="L2TP Minimum BPS AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",16,_L2TP_type),
                 IntField("minbps",0)
                 ]         
                 
class L2TP_MAXBPS_AVP(L2TP_AVP):
    name="L2TP Maximum BPS AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",17,_L2TP_type),
                 IntField("maxbps",0)
                 ]                 

class L2TP_BEARERTYPE_AVP(L2TP_AVP):
    name="L2TP Bearer Type AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",18,_L2TP_type),
                 BitField("bearer_rsvd",0,30),
                 BitField("bearer_analog",0,1),#to be converted to Enum
                 BitField("bearer_digital",1,1)                 
                 ]
    
class L2TP_FRAMINGTYPE_AVP(L2TP_AVP):
    name="L2TP Framing Type AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",19,_L2TP_type),
                 BitField("framing_rsvd",0,30),
                 BitField("asyn-framing",0,1),#to be converted to Enum
                 BitField("syn-framing",1,1)                 
                 ]
class L2TP_CALLEDNUM_AVP(L2TP_AVP):
    name="L2TP  Called Number AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="called_num",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",21,_L2TP_type),
                 StrLenField("called_num","",length_from=lambda p:p.len-6)                 
                 ]     
class L2TP_CALLINGNUM_AVP(L2TP_AVP):
    name="L2TP Calling Number AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="calling_num",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",22,_L2TP_type),
                 StrLenField("calling_num","",length_from=lambda p:p.len-6)                 
                 ]
class L2TP_SUBADDR_AVP(L2TP_AVP):
    name="L2TP Sub-Address Number AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="sub_addr",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",23,_L2TP_type),
                 StrLenField("sub_addr","",length_from=lambda p:p.len-6)                 
                 ]

class L2TP_TXCNSPD_AVP(L2TP_AVP):
    name="L2TP (Tx) Connect Speed AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",24,_L2TP_type),
                 IntField("bps",0)
                 ]                  
class L2TP_PHYCHNLID_AVP(L2TP_AVP):
    name="L2TP Physical Channel ID AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",25,_L2TP_type),
                 IntField("phychnl_id",0)
                 ]                
class L2TP_IRLC_AVP(L2TP_AVP):
    name="L2TP Initial Received LCP CONFREQ (ICCN)"
    mandatory=0
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="lcp_confreq",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",26,_L2TP_type),
                 StrLenField("lcp_confreq","",length_from=lambda p:p.len-6)                 
                 ]
class L2TP_LSLC_AVP(L2TP_AVP):
    name="L2TP Last Sent LCP CONFREQ (ICCN)"
    mandatory=0
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="lcp_confreq",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",27,_L2TP_type),
                 StrLenField("lcp_confreq","",length_from=lambda p:p.len-6)                 
                 ]
class L2TP_LRLC_AVP(L2TP_AVP):
    name="L2TP Last Received LCP CONFREQ (ICCN)"
    mandatory=0
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="lcp_confreq",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",28,_L2TP_type),
                 StrLenField("lcp_confreq","",length_from=lambda p:p.len-6)                 
                 ]
class L2TP_PROXYAUTYPE_AVP(L2TP_AVP):
    name="L2TP Proxy Authen Type AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",8,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",29,_L2TP_type),
                 ShortEnumField("authen_type",0,{0:'Reserved',
                                                1:'Textual username/password exchange',
                                                2:'PPP CHAP',
                                                3:'PPP PAP',
                                                4:'No Authentication',
                                                5:'Microsoft CHAP Version 1 (MSCHAPv1)'})
                 ]
class L2TP_PROXYAUNAME_AVP(L2TP_AVP):
    name="L2TP Proxy Authen Name"
    mandatory=0
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="auth_name",adjust=lambda ptk,x:x+6),
                 #BitField("len",6,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",30,_L2TP_type),
                 StrLenField("auth_name","",length_from=lambda p:p.len-6)                 
                 ]    
class L2TP_PROXAUCHLG_AVP(L2TP_AVP):
    name="L2TP Proxy Authen Challenge"
    mandatory=0
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="auth_chlg",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",31,_L2TP_type),
                 StrLenField("auth_chlg","",length_from=lambda p:p.len-6)                 
                 ]   
class L2TP_PROXAURES_AVP(L2TP_AVP):
    name="L2TP Proxy Authen Response"
    mandatory=0
    fields_desc=[
                 _L2TP_Header,
                 BitFieldLenField("len",None,10,length_of="auth_res",adjust=lambda ptk,x:x+6),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",33,_L2TP_type),
                 StrLenField("auth_res","",length_from=lambda p:p.len-6)                 
                 ]   
    
class L2TP_PROXYAUID_AVP(L2TP_AVP):
    name="L2TP Proxy Authen ID AVP"
    mandatory=0
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",8,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",32,_L2TP_type),
                 ByteField("reserved",0),
                 ByteField("id",None)
                 ] 
             
class L2TP_RXCNSPD_AVP(L2TP_AVP):
    name="L2TP Rx Connect Speed AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",10,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",38,_L2TP_type),
                 ShortField("bps_h",0),
                 ShortField("bps_l",0)
                 ]
                 
 
    
class L2TP_SQNCRQR_AVP(L2TP_AVP):
    name="L2TP Sequencing Required ID AVP"
    fields_desc=[
                 _L2TP_Header,
                 BitField("len",6,10),
                 ShortField("vendor_id",0),
                 ShortEnumField("attr_type",39,_L2TP_type)
                 ]                  

 
class L2TP(Packet):
    name="L2TP"
    fields_desc = [
                   BitEnumField("type",0,1,{0:'Data message',1:'Control message'}),
                   BitEnumField("len_present",0,1,{0:'Not present',1:'Present'}),
                   BitField("reserved0",0,2),
                   BitEnumField("seq_present",0,1,{0:'Not present',1:'Present'}),
                   BitField("reserved1",0,1),
                   BitEnumField("offset_present",0,1,{0:'Not present',1:'Present'}),
                   BitEnumField("priorty_present",0,1,{0:'Not present',1:'Present'}),
                   BitField("reserved2",0,4),
                   BitField("vers",2,4),
                   ConditionalField(ShortField("len",None),lambda pkt:pkt.len_present==1),
                   ShortField("tunnel_id",None),
                   ShortField("session_id",None),
                   ConditionalField(ShortField("Ns",None),lambda pkt:pkt.seq_present==1),
                   ConditionalField(ShortField("Nr",None),lambda pkt:pkt.seq_present==1),
                   ConditionalField(ShortField("offset_size",None),lambda pkt:pkt.offset_present==1),
                   ConditionalField(ShortField("offset_pad",None),lambda pkt:pkt.offset_present==1),
                   ConditionalField( PacketListField("AVPs", [],  L2TP_AVP, length_from=lambda p:p.len),lambda pkt:pkt.type==1)
                   ]
    
    def do_build(self):      

        avpval = self.getfieldval( (self.fields_desc[-1]).name) # if AVPs exists
            
        if avpval is not None and len(avpval):
            self.overloaded_fields["type"]=1
            self.overloaded_fields["seq_present"]=1 
            self.overloaded_fields["len_present"]=1
        #other function can be added here to extend the intelligence 
        return Packet.do_build(self)
    
    def post_build(self, p, pay):
   
        if (ord(p[0]) & 0b01000000) and self.len is None:            
            l = len(pay)+len(p)
            p = p[:2]+struct.pack("!H",l)+ p[4:]            
        return p+pay
    """
    
    fields_desc = [ ShortEnumField("pkt_type",2,{2:"data"}),
                    ShortField("len", None),
                    ShortField("tunnel_id", 0),
                    ShortField("session_id", 0),
                    ShortField("ns", 0),
                    ShortField("nr", 0),
                    ShortField("offset", 0) ]
    
    def post_build(self, pkt, pay):
        if self.len is None:
            l = len(pkt)+len(pay)
            pkt = pkt[:2]+struct.pack("!H", l)+pkt[4:]
        return pkt+pay
    """

bind_layers( UDP,           L2TP,          sport=1701)
bind_layers( UDP,           L2TP,          dport=1701)
bind_layers( L2TP,          PPP,           )



