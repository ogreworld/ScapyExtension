## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license
import struct
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP,IP
from scapy.layers.l2 import Ether
from scapy.base_classes import Net
from scapy.volatile import RandField
from scapy.packet import Padding,Raw
from scapy.automaton import *
from scapy.error import log_scapy

dhcpmagic="c\x82Sc"

class BOOTP(Packet):
    name = "BOOTP"
    fields_desc = [ ByteEnumField("op",1, {1:"BOOTREQUEST", 2:"BOOTREPLY"}),
                    ByteField("htype",1),
                    ByteField("hlen",6),
                    ByteField("hops",0),
                    XIntField("xid",0),
                    ShortField("secs",0),
                    BitEnumField("flags", 0, 1, {0:"Unicast",1:"Broadcast"}),
                    #ShortEnumField("flags", 32768, {0:"Unicast",32768:"Broadcast"}),
                    BitField('flagspad',None,15),
                    IPField("ciaddr","0.0.0.0"),
                    IPField("yiaddr","0.0.0.0"),
                    IPField("siaddr","0.0.0.0"),
                    IPField("giaddr","0.0.0.0"),
                    MACField("chaddr","00:00:00:00:00:00"),
                    Field("chpad","", "10s"),
                    Field("sname","","64s"),
                    Field("file","","128s"),
                    #StrFixedLenField("chpad","",10),
                    #StrFixedLenField("sname","",64),
                    #StrFixedLenField("file","",128),
                    StrField("options","")
                                            ]
    def guess_payload_class(self, payload):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            return DHCP
        else:
            return Packet.guess_payload_class(self, payload)
    def extract_padding(self,s):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            # set BOOTP options to DHCP magic cookie and make rest a payload of DHCP options
            payload = self.options[len(dhcpmagic):]
            self.options = self.options[:len(dhcpmagic)]
            return payload, None
        else:
            return "", None
    def hashret(self):
        return struct.pack("L", self.xid)
    def answers(self, other):
        if not isinstance(other, BOOTP):
            return 0
        return self.xid == other.xid


DHCPTypes = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
    9: "force_renew",
    10:"lease_query",
    11:"lease_unassigned",
    12:"lease_unknown",
    13:"lease_active",
                }
_DHCP_options_code = {
    0: "pad",
    1: "subnet_mask",
    2: "time_zone",
    3: "router",
    4: "time_server",
    5: "IEN_name_server",
    6: "name_server",
    7: "log_server",
    8: "cookie_server",
    9: "lpr_server",
    12: "hostname",
    14: "dump_path",
    15: "domain",
    17: "root_disk_path",
    22: "max_dgram_reass_size",
    23: "default_ttl",
    24: "pmtu_timeout",
    28: "broadcast_address",
    33: "static_route",
    35: "arp_cache_timeout",
    36: "ether_or_dot3",
    37: "tcp_ttl",
    38: "tcp_keepalive_interval",
    39: "tcp_keepalive_garbage",
    40: "NIS_domain",
    41: "NIS_server",
    42: "NTP_server",
    43: "vendor_specific",
    44: "NetBIOS_server",
    45: "NetBIOS_dist_server",
    50: "requested_addr",
    51: "lease_time",
    54: "server_id",
    55: "param_req_list",
    57: "max_dhcp_size", 
    58: "renewal_time", 
    59: "rebinding_time",
    60: "vendor_class_id",
    61: "client_id",
    64: "NISplus_domain",
    65: "NISplus_server",
    69: "SMTP_server",
    70: "POP3_server",
    71: "NNTP_server",
    72: "WWW_server",
    73: "Finger_server",
    74: "IRC_server",
    75: "StreetTalk_server",
    76: "StreetTalk_Dir_Assistance",
    82: "relay_agent_Information",
    53: "message_type",
    #             55: DHCPRequestListField("request-list"),
    116:"DHCP_auto_config",
    121:"classless_static_route",
    255: "end",
    241: "Private"
    }
DHCPOptions = {
    #0: "pad",
    1: IPField("subnet_mask", "0.0.0.0"),
    2: "time_zone",
    3: IPField("router","0.0.0.0"),
    4: IPField("time_server","0.0.0.0"),
    5: IPField("IEN_name_server","0.0.0.0"),
    6: IPField("name_server","0.0.0.0"),
    7: IPField("log_server","0.0.0.0"),
    8: IPField("cookie_server","0.0.0.0"),
    9: IPField("lpr_server","0.0.0.0"),
    12: "hostname",
    14: "dump_path",
    15: "domain",
    17: "root_disk_path",
    22: "max_dgram_reass_size",
    23: "default_ttl",
    24: "pmtu_timeout",
    28: IPField("broadcast_address","0.0.0.0"),
    35: "arp_cache_timeout",
    36: "ether_or_dot3",
    37: "tcp_ttl",
    38: "tcp_keepalive_interval",
    39: "tcp_keepalive_garbage",
    40: "NIS_domain",
    41: IPField("NIS_server","0.0.0.0"),
    42: IPField("NTP_server","0.0.0.0"),
    43: "vendor_specific",
    44: IPField("NetBIOS_server","0.0.0.0"),
    45: IPField("NetBIOS_dist_server","0.0.0.0"),
    50: IPField("requested_addr","0.0.0.0"),
    51: IntField("lease_time", 43200),
    54: IPField("server_id","0.0.0.0"),
    55: "param_req_list",
    57: ShortField("max_dhcp_size", 1500),
    58: IntField("renewal_time", 21600),
    59: IntField("rebinding_time", 37800),
    60: "vendor_class_id",
    61: "client_id",
    64: "NISplus_domain",
    65: IPField("NISplus_server","0.0.0.0"),
    69: IPField("SMTP_server","0.0.0.0"),
    70: IPField("POP3_server","0.0.0.0"),
    71: IPField("NNTP_server","0.0.0.0"),
    72: IPField("WWW_server","0.0.0.0"),
    73: IPField("Finger_server","0.0.0.0"),
    74: IPField("IRC_server","0.0.0.0"),
    75: IPField("StreetTalk_server","0.0.0.0"),
    76: "StreetTalk_Dir_Assistance",
    82: "relay_agent_Information",
    53: ByteEnumField("message-type", 1, DHCPTypes),
    #             55: DHCPRequestListField("request-list"),
    255: "end"
    }
"""
DHCPRevOptions = {}
for k,v in DHCPOptions.iteritems():
    if type(v) is str:
        n = v
        v = None
    else:
        n = v.name
    DHCPRevOptions[n] = (k,v)
del(n)
del(v)
del(k)
    
    

class RandDHCPOptions(RandField):
    def __init__(self, size=None, rndstr=None):
        if size is None:
            size = RandNumExpo(0.05)
        self.size = size
        if rndstr is None:
            rndstr = RandBin(RandNum(0,255))
        self.rndstr=rndstr
        self._opts = DHCPOptions.values()
        self._opts.remove("pad")
        self._opts.remove("end")
    def _fix(self):
        op = []
        for k in range(self.size):
            o = random.choice(self._opts)
            if type(o) is str:
                op.append((o,self.rndstr*1))
            else:
                op.append((o.name, o.randval()._fix()))
        return op

class DHCPOptionsField(StrField):
    islist=1
    def i2repr(self,pkt,x):
        s = []
        for v in x:
            if type(v) is tuple and len(v) >= 2:
                if  DHCPRevOptions.has_key(v[0]) and isinstance(DHCPRevOptions[v[0]][1],Field):
                    f = DHCPRevOptions[v[0]][1]
                    vv = ",".join(f.i2repr(pkt,val) for val in v[1:])
                else:
                    vv = ",".join(repr(val) for val in v[1:])
                r = "%s=%s" % (v[0],vv)
                s.append(r)
            else:
                s.append(sane(v))
        return "[%s]" % (" ".join(s))
        
    def getfield(self, pkt, s):
        return "", self.m2i(pkt, s)
    def m2i(self, pkt, x):
        opt = []
        while x:
            o = ord(x[0])
            if o == 255:
                opt.append("end")
                x = x[1:]
                continue
            if o == 0:
                opt.append("pad")
                x = x[1:]
                continue
            if len(x) < 2 or len(x) < ord(x[1])+2:
                opt.append(x)
                break
            elif DHCPOptions.has_key(o):
                f = DHCPOptions[o]
                if isinstance(f, str):
                    olen = ord(x[1])
                    opt.append( (f,x[2:olen+2]) )
                    x = x[olen+2:]
                else:
                    olen = ord(x[1])
                    lval = [f.name]
                    try:
                        left = x[2:olen+2]
                        while left:
                            left, val = f.getfield(pkt,left)
                            lval.append(val)
                    except:
                        opt.append(x)
                        break
                    else:
                        otuple = tuple(lval)
                    opt.append(otuple)
                    x = x[olen+2:]
            else:
                olen = ord(x[1])
                opt.append((o, x[2:olen+2]))
                x = x[olen+2:]
        return opt
    def i2m(self, pkt, x):
        if type(x) is str:
            return x
        s = ""
        for o in x:
            if type(o) is tuple and len(o) >= 2:
                name = o[0]
                lval = o[1:]
                if isinstance(name, int):
                    onum, oval = name, "".join(lval)
                elif DHCPRevOptions.has_key(name):
                    onum, f = DHCPRevOptions[name]
                    if  f is not None:
                        lval = [f.addfield(pkt,"",f.any2i(pkt,val)) for val in lval]
                    oval = "".join(lval)
                else:
                    warning("Unknown field option %s" % name)
                    continue
                s += chr(onum)
                s += chr(len(oval))
                s += oval
            elif (type(o) is str and DHCPRevOptions.has_key(o) and 
                  DHCPRevOptions[o][1] == None):
                s += chr(DHCPRevOptions[o][0])
            elif type(o) is int:
                s += chr(o)+"\0"
            elif type(o) is str:
                s += o
            else:
                warning("Malformed option %s" % o)
        return s

class DHCP(Packet):
    name = "DHCP options"
    fields_desc = [ DHCPOptionsField("options","") ]
, length_from=lambda p:p.len-4

class DHCP(Packet):
     name = "DHCP"
     fields_desc = [ PacketListField("DHCP options", [],  DHCPOptions)]
"""
    
    
    
class DHCPOptions(Packet):
    name = "DHCP Options"
    fields_desc = [ ByteEnumField("code" , None , _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="value", adjust=lambda p,x:x),
                    StrLenField("value","",length_from=lambda p:p.len)]
    
    
    def extract_padding(self, pay):
        return "",pay
    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.code.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls
    
    
class PAD(DHCPOptions):
    name = "Option: (0) PAD"
    fields_desc = [ ByteEnumField("code", 0, _DHCP_options_code),
                    #StrLenField("padding","")
                    #StrField("padding","",remain=0,)#length_from=lambda p:p.len
                                ]

class SUBMASK(DHCPOptions):
    name = "Option: (1) Subnet Mask(SUBMASK)"
    fields_desc = [ ByteEnumField("code", 1, _DHCP_options_code),
                    ByteField("len",4),
                    IPField("subnet_mask","0.0.0.0")]
#to be modified to adapt multi-router_ip
class ROUTER(DHCPOptions):
    name = "Option: (3) Router Options(ROUTER)"
    fields_desc = [ ByteEnumField("code", 3, _DHCP_options_code),
                    ByteField("len",4),
                    IPField("router_ip","0.0.0.0")]
#to be modified to adapt multi-dns_ip    
class DHCPDNS(DHCPOptions):
    name = "Option: (6) Domain Name Server(DHCPDNS)"
    fields_desc = [ ByteEnumField("code", 6, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="dns_ip", adjust=lambda p,x:x),
                    FieldListField("dns_ip",[],IPField("ip",None), count_from=lambda p:p.len/4) ]
    
    
class HOSTNAME(DHCPOptions):
    name = "Option: (12) Host name(HOSTNAME)"
    fields_desc = [ ByteEnumField("code", 12, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="hostname", adjust=lambda p,x:x),
                    StrLenField("hostname","",length_from=lambda p:p.len)]
class DOMAINNAME(DHCPOptions):
    name = "Option: (15) Domain Name(DOMAINNAME)"
    fields_desc = [ ByteEnumField("code", 15, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="hostname", adjust=lambda p,x:x),
                    StrLenField("domainname","",length_from=lambda p:p.len)]
class SWAPSERV(DHCPOptions):
    name = "Option: (16) Swap Server(SWAPSERV)"
    fields_desc = [ ByteEnumField("code", 16, _DHCP_options_code),
                    ByteField("len",4),
                    IPField("swap_serv","0.0.0.0")]
                    
class StaticRouteItem(Packet):
    name = "StaticRouteItem"
    fields_desc = [ IPField("dst",""),
                    IPField("gateway","") ]
    
    def extract_padding(self, pay):
        return "",pay
        
class ClasslessStaticRouteItem(Packet):
    name = "ClasslessStaticRouteItem"
    fields_desc = [ ByteField("mask_len",0),
                    NetField("subnet","",length_from=lambda p:p.mask_len),
                    IPField("gateway","") ]   
    def extract_padding(self, pay):
        return "",pay                    
        
class StaticRoute(DHCPOptions):
    name = "Option: (33) Static Route(StaticRoute)"
    
    fields_desc = [ ByteEnumField("code", 33, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="value", adjust=lambda p,x:x),
                    PacketListField("values","", StaticRouteItem, length_from=lambda p:p.len)]
                    
class ClasslessStaticRoute(DHCPOptions):
    name = "Option: (121) Classless Static Route(ClasslessStaticRoute)"    
    fields_desc = [ ByteEnumField("code", 121, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="value", adjust=lambda p,x:x),
                    PacketListField("values","", ClasslessStaticRouteItem, length_from=lambda p:p.len)]    
          
class MSClasslessStaticRoute(ClasslessStaticRoute):
    name = "Option: (249) Microsoft Classless Static Route(MSClasslessStaticRoute)"    
    fields_desc = [ByteEnumField("code",249,_DHCP_options_code)] + ClasslessStaticRoute.fields_desc[1:]
    
#maybe need to be modified    
class VENDSPEC(DHCPOptions):
    name = "Option: (43) Vendor Specific Information(VENDSPEC)"
    fields_desc = [ ByteEnumField("code", 43, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="vendspec", adjust=lambda p,x:x),
                    FieldListField("vendspec",[],ByteEnumField("code", None, _DHCP_options_code),count_from=lambda p:p.len)]
    
class VENDCLSID(DHCPOptions):
    name = "Option: (60) Vendor Class Identifier(VENDCLSID)"
    fields_desc = [ ByteEnumField("code", 60, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="vendor_class_id", adjust=lambda p,x:x),
                    StrLenField("vendor_class_id","",length_from=lambda p:p.len)]
    
class RQSTADDR(DHCPOptions):
    name = "Option: (50) Requested IP Address(RQSTADDR)"
    fields_desc = [ ByteEnumField("code", 50, _DHCP_options_code),
                    ByteField("len",4),
                    IPField("requested_addr","0.0.0.0")]
class LEASETIME(DHCPOptions):
    name = "Option: (51) IP Address Lease Time(LEASETIME)"
    fields_desc = [ ByteEnumField("code", 51, _DHCP_options_code),
                    ByteField("len",4),
                    IntField("lease_time", 43200)]
class MSGTYPE(DHCPOptions):
    name = "Option: (53) Message Type(MSGTYPE)"
    fields_desc = [ ByteEnumField("code", 53, _DHCP_options_code),
                    ByteField("len",1),
                    ByteEnumField("type",None,DHCPTypes)]
                    
class SERVID(DHCPOptions):
    name = "Option: (54) Server Identifier(SERVID)"
    fields_desc = [ ByteEnumField("code", 54, _DHCP_options_code),
                    ByteField("len",4),
                    IPField("server_id","0.0.0.0")]
    
#55 to be modified(RFC2132 is not enough)
class PARARQST(DHCPOptions):
    name = "Option: (55) Parameter Request List(PARARQST)"
    fields_desc = [ ByteEnumField("code", 55, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="paralist", adjust=lambda p,x:x),
                    FieldListField("paralist",[],ByteEnumField("code", None, _DHCP_options_code),count_from=lambda p:p.len)]
class MDMS(DHCPOptions):
    name = "Option: (57) Maximum DHCP Message Size(MDMS)"
    fields_desc = [ ByteEnumField("code", 57, _DHCP_options_code),
                    ByteField("len",2),
                    ShortField("mdms", 576)]
      
class RENEWTIME(DHCPOptions):
    name = "Option: (58) Renewal (T1) Time Value(RENEWTIME)"
    fields_desc = [ ByteEnumField("code", 58, _DHCP_options_code),
                    ByteField("len",4),
                    IntField("renew_time", 43200)]      #what default time should be?
    
class REBINDTIME(DHCPOptions):
    name = "Option: (59) Rebinding (T2) Time Value(REBINDTIME)"
    fields_desc = [ ByteEnumField("code", 59, _DHCP_options_code),
                    ByteField("len",4),
                    IntField("rebind_time", 43200)]     #what default time should be?
    
#61 to be modified
class CLIENTID(DHCPOptions):
    name = "Option: (61) Client Identifier(CLIENTID)"
    fields_desc = [ ByteEnumField("code", 61, _DHCP_options_code),
                    ByteField("len",7),
                    ByteEnumField("hwtype",None,{1:"Ethernet"}),                   
                    MACField("clientmac",None)]
class CLIENTFQDN(DHCPOptions):
    name = "Option: (81) Client Fully Qualified Domain Name(CLIENTFQDN)"
    fields_desc = [ ByteEnumField("code", 81, _DHCP_options_code),
                    BitFieldLenField("len" , None, 8, length_of="name", adjust=lambda p,x:x+3),
                    ByteField("flags",None),
                    ByteField("rcode1",None),
                    ByteField("rcode2",None),
                    StrLenField("name","",length_from=lambda p:p.len-3)]
    
#116 to be modified (not in RFC 2132)
#116 updated according to RFC 2563
class AUTOCONFIG(DHCPOptions):
    name = "Option: (116) DHCP Auto Configuration(AUTOCONFIG)"
    fields_desc = [ ByteEnumField("code", 116, _DHCP_options_code),
                    ByteField("len",1),
                    ByteEnumField("autoconfig",None,{0:"Do Not Auto Configure",1:"Auto Configure"})] 
                        
class END(DHCPOptions):
    name = "Option: (255) END"
    fields_desc = [ ByteEnumField("code", 255, _DHCP_options_code)                    
                    ]    
class PRIVATE(DHCPOptions):
    name = "Option: (3) Private Options(PRIVATE)"
    fields_desc = [ ByteEnumField("code", 241, _DHCP_options_code),
                    ByteField("len",4),
                    IntField("value",0)]
                    
class DHCP(Packet):
    name = "DHCP"
    fields_desc = [ PacketListField("options", [],  DHCPOptions)]
#"""length_from=lambda p:len(p[:p[END]]))"""
                            
                    
                    
        
bind_layers( UDP,           BOOTP,         dport=67, sport=68)
bind_layers( UDP,           BOOTP,         dport=68, sport=67)
bind_bottom_up( UDP, BOOTP, dport=67, sport=67)
bind_layers( BOOTP,         DHCP,          options='c\x82Sc')


    
def ipaddresspool(start=100,end=200):
    
    ipbase = '192.168.1.'
    ippool = []
    
    for i in range(start,end+1):
        ippad = str(i)  
        ip = ipbase + ippad
        ippool.append(ip)
    
    return ippool
 
def compute_len(pl):                              #compute length of DHCP options excluding [Raw]
    
    n  = len(pl[DHCP].options)                    #how many options in DHCP
    
    lv = 0
    if pl[DHCP].options[n-1].code == 255:
        lf  = 2 * (n-1)                           # length of 'code' and 'len' in all options(fixed length) excluding End 
        for i in range(n-1):
            lv += pl[DHCP].options[i].len         #sum of length of data in each option(variable length) excluding End
        ls = lf + lv + 1                          # sum of full length including End, excluding Raw. 1 is length of End.
        
    elif pl[DHCP].options[n-2].code == 255:
        lf = 2 * (n-2)
        if pl[DHCP].options[n-1].code == 0:
            for i in range(n-1):
                lv += pl[DHCP].options[i].len      #sum of length of data in each option(variable length)
            ls = lf + lv + 2                       # sum of full length including Pad and End, excluding Raw. 2 is the length of End and Pad.
        else:
            ls = lf + lv + 1
            
    return ls   
def compute_pad(pp):                      #compute number of DHCP options pad
    pl = pp
    la = compute_len(pl)
    
    if la < 60:                           #should be 64,but DHCP magic cookie takes 4 Bytes which is also in options
        np = 60 - la                      #number of pads(0)
        
    return np                       
class FAKE_DHCP():
    
    'this produce fake dhcp packet to make Automaton to power off.'
    def __init__(self):   
        
        self.p = Ether()/IP()/UDP()/BOOTP()/DHCP()
        self.p[DHCP].options = []
        
        msgtype   = MSGTYPE(code=53,len=1,type=20)
              
        self.p[DHCP].options = [msgtype]
        
class DHCP_OFFER():
    'Build a dhcp offer packet'
    
    def __init__(self):   
        
        self.p = Ether()/IP()/UDP()/BOOTP()/DHCP()
        self.p[DHCP].options = []
        
        self.p[Ether].src    = '08:00:27:37:be:ab'
        self.p[Ether].dst    = 'ff:ff:ff:ff:ff:ff'
        self.p[IP].src       = '172.31.81.200'
        self.p[IP].dst       = '255.255.255.255'
        self.p[BOOTP].op     = 2
        self.p[BOOTP].chpad  = '\x00'*10
        self.p[BOOTP].sname  = '\x00'*64
        self.p[BOOTP].file   = '\x00'*128
        
       
        self.msgtype   = MSGTYPE(code=53,len=1,type=2)
        self.servid    = SERVID(code=54,len=4,server_id='192.168.250.30')
        self.leasetime = LEASETIME(code=51,len=4,lease_time=25200) 
        self.submask   = SUBMASK(code=1,len=4,subnet_mask='255.255.255.0')
        self.router    = ROUTER(code=3,len=4,router_ip='192.168.250.1') 
        self.dns       = DHCPDNS(code=6,len=4,dns_ip='192.168.250.1')
        self.end       = END(code=255)
        
        self.p[DHCP].options = [self.msgtype,self.servid,self.leasetime,self.submask,self.router,self.dns,self.end]
        
        self.np = compute_pad(self.p)                      #compute the number of pads
        
        if self.np == 1:
            self.pad      = PAD()
            self.pad.code = 0
            self.p[DHCP].options.append(self.pad)
            
        else:
            self.raw      = Raw()
            self.raw.load = '\x00'*self.np       
            self.p[DHCP].options.append(self.raw)

            
class DHCP_ACK(DHCP_OFFER):
    'Build a dhcp ack packet'
    def __init__(self):
        DHCP_OFFER.__init__(self)
        self.p[MSGTYPE].type = 5  
            
class DHCP_NAK(DHCP_OFFER):  
    'Build a dhcp nak packet'
    def __init__(self):
        DHCP_OFFER.__init__(self)
        self.p[DHCP].options.remove(self.leasetime)
        self.p[DHCP].options.remove(self.submask)
        self.p[DHCP].options.remove(self.router)
        self.p[DHCP].options.remove(self.dns)
        try:
             self.p[DHCP].options.remove(self.pad)
        except:
            self.p[DHCP].options.remove(self.raw)
        
        self.np = compute_pad(self.p)                      #compute the number of pads
        
        if self.np == 1:
            pad      = PAD()
            pad.code = 0
            self.p[DHCP].options.append(pad)
            
        else:
            raw      = Raw()
            raw.load = '\x00'*self.np       
            self.p[DHCP].options.append(raw)
  
class DHCP_Server(Automaton):
    
    def parse_args(self,ipstart=100,ipend=200,gw='192.168.250.1',subnet_mask='255.255.255.0',\
                   dns='192.168.250.1',server_id='192.168.250.30',router_ip='192.168.250.1',\
                   offer_xid_wrong=0,ack_xid_wrong=0,*args, **kargs):
        
        Automaton.parse_args(self, *args, **kargs)
        
        self.ipstart     = ipstart
        self.ipend       = ipend
        self.gw          = gw
        self.subnet_mask = subnet_mask
        self.dns         = dns
        self.server_id   = server_id
        self.router_ip   = router_ip
        self.offer_xid_wrong = offer_xid_wrong
        self.ack_xid_wrong = ack_xid_wrong
        
        self.ippoolstatic = ipaddresspool(self.ipstart,self.ipend)
        self.ippool = ipaddresspool(self.ipstart,self.ipend)
        self.offerip  = ''
        self.database = {}        #store the assigned IP and corresponding MAC
        self.raise_end = 0
    
    def master_filter(self, pkt):
        return (BOOTP in pkt and pkt[BOOTP].options == "c\x82Sc")
    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        
        print'This is the beginning of the automata.'    
        raise self.WAITING()
    
    #WAITING
    @ATMT.state()
    def WAITING(self):
        print "This is WAITING state."
        
        #self.run()
        
    
        
    @ATMT.receive_condition(WAITING)
    def receive_discover(self, pkt):
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 1:               
                print"I've got DHCP Discover,and should send\
                DHCP Offer if ippool is not empty."           
                raise self.RCVD_DISCOVER(pkt)
            
    @ATMT.receive_condition(WAITING)
    def receive_request(self, pkt):
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 3:
                #if pkt.haslayer(SERVID) and pkt[SERVID].server_id == self.server_id:         #request without servid when client reboot           
                print"I've got DHCP Request,and should send DHCP ACK or NAK."           
                raise self.RCVD_REQUEST(pkt) 
                   
    @ATMT.receive_condition(WAITING)
    def receive_decline(self, pkt):
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 4:               
                print"I've got DHCP Decline,and should mark the ip unavailable,also delete the responding MAC-IP relationship."           
                raise self.RCVD_DECLINE(pkt)  
    
    @ATMT.receive_condition(WAITING)
    def receive_release(self, pkt):
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 7:               
                print"I've got DHCP Release,and should make the IP available in ippool if it is assigned by me."           
                raise self.RCVD_RELEASE(pkt)
    
    @ATMT.receive_condition(WAITING)
    def receive_inform(self, pkt):
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 8:               
                print"I've got DHCP Inform,and should send ack without lease time option and not fill in 'yiaddr'"           
                raise self.RCVD_RELEASE(pkt)
     
    @ATMT.receive_condition(WAITING)
    def receive_end(self, pkt):
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 20:               
                print"I've got end,and should power off the DHCP server."           
                raise self.END()       
    
    
    
    @ATMT.state()
    def RCVD_DISCOVER(self,pkt):
        self.ippool = ipaddresspool(self.ipstart,self.ipend)
        if self.ippool ==[]:
            print"No ip address available and would not send DHCP offer"
        else:
            print"now build the DHCP offer"
            
            offerinstance = DHCP_OFFER()
            offer = offerinstance.p
            offer[Ether].dst = pkt[Ether].src
            
            if self.offer_xid_wrong == 0:
                offer[BOOTP].xid    = pkt[BOOTP].xid
            
            if pkt[BOOTP].flags == 1:
                offer[BOOTP].flags  = 1
                
            if pkt[Ether].src in self.database and self.database[pkt[Ether].src] in self.ippool:
                offer[BOOTP].yiaddr =  self.database[pkt[Ether].src]
            elif pkt.haslayer(RQSTADDR) and pkt[RQSTADDR].requested_addr in self.ippool:
                offer[BOOTP].yiaddr =  pkt[RQSTADDR].requested_addr
                self.database[pkt[Ether].src] = offer[BOOTP].yiaddr    
            else:
                offer[BOOTP].yiaddr = self.ippool[0]
                self.database[pkt[Ether].src] = offer[BOOTP].yiaddr
                
            self.offerip = offer[BOOTP].yiaddr
            self.ippool.remove(self.offerip)
            offer[BOOTP].chaddr = pkt[Ether].src
            
            print "now show the DHCP offer"
            offer.show2()
            
            print"now send the DHCP offer"
            sendp(offer)
            
        raise self.WAITING()   
    
    @ATMT.state()
    def RCVD_REQUEST(self,pkt):
        
        if pkt.haslayer(RQSTADDR) and (pkt[RQSTADDR].requested_addr not in self.ippoolstatic or (pkt[Ether].src in self.database and self.database[pkt[Ether].src] != pkt[RQSTADDR].requested_addr )):
            print"now build the DHCP NAK,for requested ip exceeds the ip pool"
            print self.ippoolstatic[0]
            nakinstance = DHCP_NAK()
            nak = nakinstance.p
            nak[Ether].dst = pkt[Ether].src
            nak[BOOTP].xid    = pkt[BOOTP].xid
            if pkt[BOOTP].flags == 1:
                nak[BOOTP].flags  = 1
            nak[BOOTP].chaddr = pkt[Ether].src
            if pkt[Ether].src in self.database:
                self.ippool.append(self.database[pkt[Ether].src])
                self.ippool.sort(cmp=None, key=None, reverse=False)
                
            print "now show the DHCP NAK"
            nak.show2()
            print"now send the DHCP NAK"
            sendp(nak)
        
            
        elif pkt.haslayer(RQSTADDR)==0 or (pkt.haslayer(RQSTADDR) and pkt[RQSTADDR].requested_addr in self.ippoolstatic):
            print"now build the DHCP ACK"
            
            ackinstance = DHCP_ACK()
            ack = ackinstance.p
            ack[Ether].dst = pkt[Ether].src
            if self.ack_xid_wrong == 0:
                ack[BOOTP].xid = pkt[BOOTP].xid
            if pkt[BOOTP].flags == 1:
                print"should be Broadcast"
                ack[BOOTP].flags = 1
            if self.offerip == '':
                ack[BOOTP].yiaddr = self.ippool[0]
            else:
                ack[BOOTP].yiaddr = self.offerip
            ack[BOOTP].chaddr = pkt[Ether].src
            ack[MSGTYPE].type  = 5
            print "now show the DHCP ACK"
            ack.show2()
            print"now send the DHCP ACK"
            sendp(ack)
            
            self.database[pkt[Ether].src] = ack[BOOTP].yiaddr
        raise self.WAITING()     
    
    @ATMT.state()
    def RCVD_DECLINE(self,pkt):
        del self.database[pkt[Ether].src]
        raise self.WAITING()
        
    @ATMT.state()  
    def RCVD_RELEASE(self,pkt):
        if pkt[Ether].src in self.database:
            iprestore = pkt[BOOTP].ciaddr
            self.ippool.append(iprestore)
        raise self.WAITING()
    
    @ATMT.state()    
    def RCVD_INFORM(self,pkt):
        print"now build the DHCP ACK"
        ackinstance = DHCP_ACK()
        ack = ackinstance.p
        ack[Ether].dst = pkt[Ether].src
        ack[BOOTP].xid    = pkt[BOOTP].xid
        if pkt[BOOTP].flags == 1:
            ack[BOOTP].flags  = 1
        if self.offerip == '':
            ack[BOOTP].yiaddr = self.ippool[0]
        else:
            ack[BOOTP].yiaddr = self.offerip
        ack[BOOTP].chaddr = pkt[Ether].src
        ack[MSGTYPE].type  = 5
        ack[DHCP].options.pop(2)
        
        np = compute_pad(ack)                      #compute the number of pads
        if np == 1:
            pad      = PAD()
            pad.code = 0
            ack[DHCP].options.append(pad)
            
        else:
            raw      = Raw()
            raw.load = '\x00'*np
            #p[DHCP].options.insert(4,raw)
            ack[DHCP].options.append(raw)
            print "now show the DHCP ACK"
            ack.show2()
            print"now send the DHCP ACK"
            sendp(ack)
    
    @ATMT.timeout(WAITING, 600)
    def timeout_waiting(self):
        print"10 minutes passed, I don't get what I want, I'll raise ERROR state."
        raise self.ERROR()
    
    # ERROR
    @ATMT.state(error=1)
    def ERROR(self):
        print 'Time out.'
        
    @ATMT.action(timeout_waiting)
    def on_ERROR(self):
        print "Error happened, the automata will be ended."
        
    # END
    @ATMT.state(final=1)
    def END(self):
        print 'This is the END state of the automata.'
        
    def main_changepara(self):
    
        while True:
            show_paras_list()
            cmd = raw_input()
            if int(cmd)==1:
                ipstartnew = change_ippool_start()
                print ipstartnew
                #a.ipstart = ipstart
                self.ipstart = ipstartnew
def end_dhcp_server():
    end = FAKE_DHCP()
    sendp(end.p)                 
def keyboard_interrupt():
        
        print "You can input 'quit' to power off the server."
        keyinput = raw_input()
        
        if keyinput == 'quit':
            end_dhcp_server()
        else:
            print "Wrong input."
            keyboard_interrupt()
            
class DHCPClient(Automaton):
    
    _seq_number = 0
    
    def parse_args(self, mac=None, vendcls_id=None, broadcast=0, iface=None, retry=5, 
                         hostname='client1',
                         dhcp_options=None,
                         *args, **kargs):
        '''
        initial dhcpclient
        
        Arguments:
            mac(str)                : client mac in BOOTP packet chaddr Field, format as '00-00-00-00-00-01',
                                        if your net adapter is wireless, you should give a valid mac
            iface                   : choose which net_adapter to send and recieve packet,
                                        if your net adapter is wireless, it's better for you to assign the parameter
            broadcast(int)          : 1 -----dhcp-server should broadcast dhcp-offer and dhcp-ack
                                      0 -----dhcp-server should unicast dhcp-offer and dhcp-ack
            vendcls_id              : 
        '''
        Automaton.parse_args(self, *args, **kargs)
        
        self.__class__._seq_number += 1
        self.xid = self.__class__._seq_number % 32768
        
        
        self.vendcls_id = vendcls_id
        self.broadcast  = broadcast
        self.hostname   = hostname
        self._iface      = iface or conf.iface
        if conf.iface != self._iface and conf.use_dnet:
            conf.iface = scapy.arch.pcapdnet.convent_to_eth(self._iface)
        
        if mac is None:
            # will be none?
            self.mac        = str(scapy.arch.ifaces.get(conf.iface).mac)
        else:
            self.mac        = mac.replace('-', ':')
        
        self._max_retry = retry
        self._cur_retry = 0
        self._dhcp_options = dhcp_options
    
    def master_filter(self, pkt):
        return (BOOTP in pkt and pkt[BOOTP].options == dhcpmagic 
            and pkt[UDP].sport == 67 and self.xid == pkt[BOOTP].xid)
    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        
        log_scapy.info('This is the beginning of the automata.')  
        raise self.SEND_DISCOVER()
        
    # Send Discover
    @ATMT.state()
    def SEND_DISCOVER(self):
        # record retry times
        self._cur_retry += 1
        
        discover = Ether()/IP()/UDP(sport=68, dport=67)/BOOTP(xid=self.xid)/DHCP()
        
        # discover[DHCP].options = []
        
        # discover[Ether].src    = self.mac
        discover[Ether].dst    = 'ff:ff:ff:ff:ff:ff'
        discover[IP].src       = '0.0.0.0'
        discover[IP].dst       = '255.255.255.255'
        discover[BOOTP].chaddr = self.mac
        discover[BOOTP].flags  = self.broadcast
        
       
       
        self.msgtype    = MSGTYPE(code=53, len=1, type=1)
        self.autoconfig = AUTOCONFIG(autoconfig=1) 
        self.clientmac  = CLIENTID(clientmac=self.mac)
        self.rqstaddr   = RQSTADDR()
        self.hostname   = HOSTNAME(hostname=self.hostname)
        self.end        = END(code=255)
        
        default_options = [self.msgtype, self.clientmac, self.autoconfig, 
                                  self.rqstaddr, self.hostname]        
                           
        append_options = []                            
        if self._dhcp_options:
        
            for option in self._dhcp_options:
                for i in range(len(default_options)):                    
                    if option.__class__.__name__ == default_options[i].__class__.__name__:
                        default_options[i] = option
                        
                else:
                    append_options.append(option)
                    
            
        
        
        discover[DHCP].options = default_options + append_options
        if self.vendcls_id is not None:
           self.vendclsid  = VENDCLSID(vendor_class_id=self.vendcls_id)
           discover[DHCP].options.append(self.vendclsid)
        discover[DHCP].options.append(self.end)
        
        log_scapy.info("Send the DHCP Discover.")
        sendp(discover,iface=self._iface )
            
        raise self.WAITING()
        # raise self.RCVD_ACK()
    
    #WAITING
    @ATMT.state()
    def WAITING(self):
        log_scapy.debug("This is WAITING state.")
        
        #self.run()
        
    
        
    @ATMT.receive_condition(WAITING)
    def receive_offer(self, pkt):
       
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 2:               
                
                log_scapy.debug("I've got DHCP Offer, and should send Request.")  
                self.your_client_ip = pkt[BOOTP].yiaddr
                self.server_id = pkt[SERVID].server_id
                raise self.RCVD_OFFER(pkt)
                
    @ATMT.timeout(WAITING, 5)
    def timeout_waiting(self):
        log_scapy.debug("This is timeout condition: I don't get what I want, I'll retry or raise ERROR state.")
        if self._cur_retry < self._max_retry:
            raise self.SEND_DISCOVER()
        else:
            raise self.ERROR()
        
    # ERROR
    @ATMT.state(error=1)
    def ERROR(self):
        log_scapy.info("This is ERROR state:Time out.")
   
    @ATMT.action(timeout_waiting)
    def on_ERROR(self):
        log_scapy.debug("This is action:Error happened, the automata will be ended.")
            
    @ATMT.receive_condition(WAITING)
    def receive_ack(self, pkt):
        if pkt[MSGTYPE].code == 53:
            if pkt[MSGTYPE].type == 5:
                #if pkt.haslayer(SERVID) and pkt[SERVID].server_id == self.server_id: #request without servid when client reboot           
                log_scapy.debug("I've got DHCP ACK.")
                raise self.RCVD_ACK()
    
    @ATMT.state()
    def RCVD_OFFER(self, pkt):
    
        # send request
        request = Ether()/IP()/UDP(sport=68, dport=67)/BOOTP(xid=self.xid)/DHCP()
        
        request[DHCP].options = []
        
        # request[Ether].src    = '00:00:00:00:00:01'
        request[Ether].dst    = 'ff:ff:ff:ff:ff:ff'
        request[IP].src       = '0.0.0.0'
        request[IP].dst       = '255.255.255.255'
        # request[BOOTP].op     = 2
        # request[BOOTP].chpad  = '\x00'*10
        # request[BOOTP].sname  = '\x00'*64
        # request[BOOTP].file   = '\x00'*128
        request[BOOTP].chaddr = self.mac
        request[BOOTP].flags  = self.broadcast
       
        self.msgtype   = MSGTYPE(code=53, len=1, type=3)
        self.rqstaddr    = RQSTADDR(requested_addr=self.your_client_ip)
        self.server_id = SERVID(server_id=self.server_id)
        
        request[DHCP].options = [self.msgtype, self.clientmac, self.server_id, 
                                 self.rqstaddr, self.hostname]
        if self.vendcls_id is not None:
            request[DHCP].options.append(self.vendclsid)
            
        request[DHCP].options.append(self.end)
        log_scapy.info("Send the DHCP Request")
        # request.show()
        sendp(request,iface=self._iface )
            
        raise self.WAITING()   
    
    @ATMT.state(final=1)
    def RCVD_ACK(self):
        # raise self.WAITING()
        log_scapy.info('This is the END state of the automata.')
       
"""def main():
    raise_end = 0
    a = DHCP_Server(offer_xid_wrong = 0,ack_xid_wrong=0)
    keyinput = threading.Thread(target=keyboard_interrupt)
    keyinput.start()
    #auto = threading.Thread(target = a.run)
    #auto.start()
    #change = threading.Thread(target=a.main_changepara)
    #auto.start()
    #change.start()
    a.run()
    keyinput.join()
    #change = threading.Thread(target=show_paras_list)
    #change.start()
    
if __name__=='__main__':
    main() 
"""
"""
def dhcp_request(iface=None,**kargs):
    if conf.checkIPaddr != 0:
        warning("conf.checkIPaddr is not 0, I may not be able to match the answer")
    if iface is None:
        iface = conf.iface
    fam,hw = get_if_raw_hwaddr(iface)
    return srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)
                 /BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"]),iface=iface,**kargs)

class BOOTP_am(AnsweringMachine):
    function_name = "bootpd"
    filter = "udp and port 68 and port 67"
    send_function = staticmethod(sendp)
    def parse_options(self, pool=Net("192.168.1.128/25"), network="192.168.1.0/24",gw="192.168.1.1",
                      domain="localnet", renewal_time=60, lease_time=1800):
        if type(pool) is str:
            poom = Net(pool)
        self.domain = domain
        netw,msk = (network.split("/")+["32"])[:2]
        msk = itom(int(msk))
        self.netmask = ltoa(msk)
        self.network = ltoa(atol(netw)&msk)
        self.broadcast = ltoa( atol(self.network) | (0xffffffff&~msk) )
        self.gw = gw
        if isinstance(pool,Gen):
            pool = [k for k in pool if k not in [gw, self.network, self.broadcast]]
            pool.reverse()
        if len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases = {}
    def is_request(self, req):
        if not req.haslayer(BOOTP):
            return 0
        reqb = req.getlayer(BOOTP)
        if reqb.op != 1:
            return 0
        return 1
    def print_reply(self, req, reply):
        print "Reply %s to %s" % (reply.getlayer(IP).dst,reply.dst)
    def make_reply(self, req):        
        mac = req.src
        if type(self.pool) is list:
            if not self.leases.has_key(mac):
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool
            
        repb = req.getlayer(BOOTP).copy()
        repb.op="BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        del(repb.payload)
        rep=Ether(dst=mac)/IP(dst=ip)/UDP(sport=req.dport,dport=req.sport)/repb
        return rep

class DHCP_am(BOOTP_am):
    function_name="dhcpd"
    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP in req:
            dhcp_options = [(op[0],{1:2,3:5}.get(op[1],op[1]))
                            for op in req[DHCP].options
                            if type(op) is tuple  and op[0] == "message-type"]
            dhcp_options += [("server_id",self.gw),
                             ("domain", self.domain),
                             ("router", self.gw),
                             ("name_server", self.gw),
                             ("broadcast_address", self.broadcast),
                             ("subnet_mask", self.netmask),
                             ("renewal_time", self.renewal_time),
                             ("lease_time", self.lease_time), 
                             "end"
                             ]
            resp /= DHCP(options=dhcp_options)
        return resp
    
"""
