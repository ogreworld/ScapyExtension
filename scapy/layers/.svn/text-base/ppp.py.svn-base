## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## Modified and improved by chenzongze@tp-link.net 

import struct
from scapy.packet import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.fields import *



class PPPoE(Packet):
    name = "PPP over Ethernet"
    fields_desc = [ BitField("version", 1, 4),
                    BitField("type", 1, 4),
                    ByteEnumField("code", 0, {0:"Session"}),
                    XShortField("sessionid", 0x0),
                    ShortField("len", None) ]

    def post_build(self, p, pay):
        p += pay
        
        if self.len is None:
            l = len(p)-6
            p = p[:4]+struct.pack("!H", l)+p[6:]
        return p
        
_pppoed_tag_type = {0x0000:'End-Of-List',
                     0x0101:'Service-Name',
                     0x0102:'AC-Name',
                     0x0103:'Host-Uniq',
                     0x0104:'AC-Cookie',
                     0x0105:'Vendor-Specific',
                     0x0110:'Relay-Session-Id',
                     0x0201:'Service-Name-Error',
                     0x0202:'AC-System-Error',
                     0x0203:'Generic-Error',                     
                    }
                    
class PPPoED_TAG(Packet):
    name = "PPP over Ethernet Discovery TAG"
    fields_desc = [
                    XShortEnumField('tag_type',0x0000,_pppoed_tag_type),
                    ShortField('tag_length',None),
                    StrLenField('tag_value',None,length_from = lambda ptk :ptk.tag_length)
                    ]
    def extract_padding(self, pay):
        return "",pay                
    def post_build(self, p, pay):
        p += pay
        if self.tag_length is None:
            l = len(p)-4
            p = p[:2]+struct.pack("!H",l)+p[4:]     
        return p
        
class PPPoED(PPPoE):
    name = "PPP over Ethernet Discovery"
    fields_desc = [ BitField("version", 1, 4),
                    BitField("type", 1, 4),
                    ByteEnumField("code", 0, {0:"Session Data" }),
                    XShortField("sessionid", 0x0),
                    ShortField("len", None),
                    #ConditionalField( PacketListField("TAG", [],  PPPoED_TAG, length_from=lambda p:p.len),lambda pkt:pkt.len!=0)
                    PacketListField("TAG", [],  PPPoED_TAG, length_from=lambda p:p.len)
                   ]


class PPPoES(PPPoE):
    name = "PPP over Ethernet Session"
    fields_desc = [ BitField("version", 1, 4),
                    BitField("type", 1, 4),
                    ByteEnumField("code", 0x09, {0x09:"PADI",0x07:"PADO",0x19:"PADR",0x65:"PADS",0xa7:"PADT"}),
                    XShortField("sessionid", 0x0),
                    ShortField("len", None),
                    #ConditionalField( PacketListField("TAG", [],  PPPoED_TAG, length_from=lambda p:p.len),lambda pkt:pkt.len!=0)
                    #PacketListField("TAG", [],  PPPoED_TAG, length_from=lambda p:p.len)
                   ]    
                   
_PPP_proto = { 0x0001: "Padding Protocol",
               0x0003: "ROHC small-CID [RFC3095]",
               0x0005: "ROHC large-CID [RFC3095]",
               0x0021: "Internet Protocol version 4",
               0x0023: "OSI Network Layer",
               0x0025: "Xerox NS IDP",
               0x0027: "DECnet Phase IV",
               0x0029: "Appletalk",
               0x002b: "Novell IPX",
               0x002d: "Van Jacobson Compressed TCP/IP",
               0x002f: "Van Jacobson Uncompressed TCP/IP",
               0x0031: "Bridging PDU",
               0x0033: "Stream Protocol (ST-II)",
               0x0035: "Banyan Vines",
               0x0037: "reserved (until 1993) [Typo in RFC1172]",
               0x0039: "AppleTalk EDDP",
               0x003b: "AppleTalk SmartBuffered",
               0x003d: "Multi-Link [RFC1717]",
               0x003f: "NETBIOS Framing",
               0x0041: "Cisco Systems",
               0x0043: "Ascom Timeplex",
               0x0045: "Fujitsu Link Backup and Load Balancing (LBLB)",
               0x0047: "DCA Remote Lan",
               0x0049: "Serial Data Transport Protocol (PPP-SDTP)",
               0x004b: "SNA over 802.2",
               0x004d: "SNA",
               0x004f: "IPv6 Header Compression",
               0x0051: "KNX Bridging Data [ianp]",
               0x0053: "Encryption [Meyer]",
               0x0055: "Individual Link Encryption [Meyer]",
               0x0057: "Internet Protocol version 6",
               0x0059: "PPP Muxing [RFC3153]",
               0x005b: "Vendor-Specific Network Protocol (VSNP) [RFC3772]",
               0x0061: "RTP IPHC Full Header [RFC3544]",
               0x0063: "RTP IPHC Compressed TCP [RFC3544]",
               0x0065: "RTP IPHC Compressed Non TCP [RFC3544]",
               0x0067: "RTP IPHC Compressed UDP 8 [RFC3544]",
               0x0069: "RTP IPHC Compressed RTP 8 [RFC3544]",
               0x006f: "Stampede Bridging",
               0x0071: "Reserved [Fox]",
               0x0073: "MP+ Protocol [Smith]",
               0x007d: "reserved (Control Escape) [RFC1661]",
               0x007f: "reserved (compression inefficient [RFC1662]",
               0x0081: "Reserved Until 20-Oct-2000 [IANA]",
               0x0083: "Reserved Until 20-Oct-2000 [IANA]",
               0x00c1: "NTCITS IPI [Ungar]",
               0x00cf: "reserved (PPP NLID)",
               0x00fb: "single link compression in multilink [RFC1962]",
               0x00fd: "compressed datagram [RFC1962]",
               0x00ff: "reserved (compression inefficient)",
               0x0201: "802.1d Hello Packets",
               0x0203: "IBM Source Routing BPDU",
               0x0205: "DEC LANBridge100 Spanning Tree",
               0x0207: "Cisco Discovery Protocol [Sastry]",
               0x0209: "Netcs Twin Routing [Korfmacher]",
               0x020b: "STP - Scheduled Transfer Protocol [Segal]",
               0x020d: "EDP - Extreme Discovery Protocol [Grosser]",
               0x0211: "Optical Supervisory Channel Protocol (OSCP)[Prasad]",
               0x0213: "Optical Supervisory Channel Protocol (OSCP)[Prasad]",
               0x0231: "Luxcom",
               0x0233: "Sigma Network Systems",
               0x0235: "Apple Client Server Protocol [Ridenour]",
               0x0281: "MPLS Unicast [RFC3032]  ",
               0x0283: "MPLS Multicast [RFC3032]",
               0x0285: "IEEE p1284.4 standard - data packets [Batchelder]",
               0x0287: "ETSI TETRA Network Protocol Type 1 [Nieminen]",
               0x0289: "Multichannel Flow Treatment Protocol [McCann]",
               0x2063: "RTP IPHC Compressed TCP No Delta [RFC3544]",
               0x2065: "RTP IPHC Context State [RFC3544]",
               0x2067: "RTP IPHC Compressed UDP 16 [RFC3544]",
               0x2069: "RTP IPHC Compressed RTP 16 [RFC3544]",
               0x4001: "Cray Communications Control Protocol [Stage]",
               0x4003: "CDPD Mobile Network Registration Protocol [Quick]",
               0x4005: "Expand accelerator protocol [Rachmani]",
               0x4007: "ODSICP NCP [Arvind]",
               0x4009: "DOCSIS DLL [Gaedtke]",
               0x400B: "Cetacean Network Detection Protocol [Siller]",
               0x4021: "Stacker LZS [Simpson]",
               0x4023: "RefTek Protocol [Banfill]",
               0x4025: "Fibre Channel [Rajagopal]",
               0x4027: "EMIT Protocols [Eastham]",
               0x405b: "Vendor-Specific Protocol (VSP) [RFC3772]",
               0x8021: "Internet Protocol Control Protocol",
               0x8023: "OSI Network Layer Control Protocol",
               0x8025: "Xerox NS IDP Control Protocol",
               0x8027: "DECnet Phase IV Control Protocol",
               0x8029: "Appletalk Control Protocol",
               0x802b: "Novell IPX Control Protocol",
               0x802d: "reserved",
               0x802f: "reserved",
               0x8031: "Bridging NCP",
               0x8033: "Stream Protocol Control Protocol",
               0x8035: "Banyan Vines Control Protocol",
               0x8037: "reserved (until 1993)",
               0x8039: "reserved",
               0x803b: "reserved",
               0x803d: "Multi-Link Control Protocol",
               0x803f: "NETBIOS Framing Control Protocol",
               0x8041: "Cisco Systems Control Protocol",
               0x8043: "Ascom Timeplex",
               0x8045: "Fujitsu LBLB Control Protocol",
               0x8047: "DCA Remote Lan Network Control Protocol (RLNCP)",
               0x8049: "Serial Data Control Protocol (PPP-SDCP)",
               0x804b: "SNA over 802.2 Control Protocol",
               0x804d: "SNA Control Protocol",
               0x804f: "IP6 Header Compression Control Protocol",
               0x8051: "KNX Bridging Control Protocol [ianp]",
               0x8053: "Encryption Control Protocol [Meyer]",
               0x8055: "Individual Link Encryption Control Protocol [Meyer]",
               0x8057: "IPv6 Control Protocol [Hinden]",
               0x8059: "PPP Muxing Control Protocol [RFC3153]",
               0x805b: "Vendor-Specific Network Control Protocol (VSNCP) [RFC3772]",
               0x806f: "Stampede Bridging Control Protocol",
               0x8073: "MP+ Control Protocol [Smith]",
               0x8071: "Reserved [Fox]",
               0x807d: "Not Used - reserved [RFC1661]",
               0x8081: "Reserved Until 20-Oct-2000 [IANA]",
               0x8083: "Reserved Until 20-Oct-2000 [IANA]",
               0x80c1: "NTCITS IPI Control Protocol [Ungar]",
               0x80cf: "Not Used - reserved [RFC1661]",
               0x80fb: "single link compression in multilink control [RFC1962]",
               0x80fd: "Compression Control Protocol [RFC1962]",
               0x80ff: "Not Used - reserved [RFC1661]",
               0x8207: "Cisco Discovery Protocol Control [Sastry]",
               0x8209: "Netcs Twin Routing [Korfmacher]",
               0x820b: "STP - Control Protocol [Segal]",
               0x820d: "EDPCP - Extreme Discovery Protocol Ctrl Prtcl [Grosser]",
               0x8235: "Apple Client Server Protocol Control [Ridenour]",
               0x8281: "MPLSCP [RFC3032]",
               0x8285: "IEEE p1284.4 standard - Protocol Control [Batchelder]",
               0x8287: "ETSI TETRA TNP1 Control Protocol [Nieminen]",
               0x8289: "Multichannel Flow Treatment Protocol [McCann]",
               0xc021: "Link Control Protocol",
               0xc023: "Password Authentication Protocol",
               0xc025: "Link Quality Report",
               0xc027: "Shiva Password Authentication Protocol",
               0xc029: "CallBack Control Protocol (CBCP)",
               0xc02b: "BACP Bandwidth Allocation Control Protocol [RFC2125]",
               0xc02d: "BAP [RFC2125]",
               0xc05b: "Vendor-Specific Authentication Protocol (VSAP) [RFC3772]",
               0xc081: "Container Control Protocol [KEN]",
               0xc223: "Challenge Handshake Authentication Protocol",
               0xc225: "RSA Authentication Protocol [Narayana]",
               0xc227: "Extensible Authentication Protocol [RFC2284]",
               0xc229: "Mitsubishi Security Info Exch Ptcl (SIEP) [Seno]",
               0xc26f: "Stampede Bridging Authorization Protocol",
               0xc281: "Proprietary Authentication Protocol [KEN]",
               0xc283: "Proprietary Authentication Protocol [Tackabury]",
               0xc481: "Proprietary Node ID Authentication Protocol [KEN]"}


class HDLC(Packet):
    fields_desc = [ XByteField("address",0xff),
                    XByteField("control",0x03)  ]

class PPP(Packet):
    name = "PPP Link Layer"
    fields_desc = [ ShortEnumField("proto", 0x0021, _PPP_proto) ]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and _pkt[0] == '\xff':
            cls = HDLC
        return cls

_PPP_conftypes = { 1:"Configure-Request",
                   2:"Configure-Ack",
                   3:"Configure-Nak",
                   4:"Configure-Reject",
                   5:"Terminate-Request",
                   6:"Terminate-Ack",
                   7:"Code-Reject",
                   8:"Protocol-Reject",
                   9:"Echo-Request",
                   10:"Echo-Reply",
                   11:"Discard-Request",
                   14:"Reset-Request",
                   15:"Reset-Ack",
                   }


### PPP IPCP stuff (RFC 1332)

# All IPCP options are defined below (names and associated classes) 
_PPP_ipcpopttypes = {     1:"IP-Addresses (Deprecated)",
                          2:"IP-Compression-Protocol",
                          3:"IP-Address",
                          4:"Mobile-IPv4", # not implemented, present for completeness
                          129:"Primary-DNS-Address",
                          130:"Primary-NBNS-Address",
                          131:"Secondary-DNS-Address",
                          132:"Secondary-NBNS-Address"}


class PPP_IPCP_Option(Packet):
    name = "PPP IPCP Option"
    fields_desc = [ ByteEnumField("type" , None , _PPP_ipcpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    StrLenField("data", "", length_from=lambda p:max(0,p.len-2)) ]
    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls

# ipcp option for ip header compress in RFC1332
class PPP_IPCP_Option_IPCompress(PPP_IPCP_Option):
    name = "PPP IPCP Option: IP-Compression-Protocol"
    fields_desc = [ ByteEnumField("type" , 2 , _PPP_ipcpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    StrLenField("data","", length_from=lambda pkt:pkt.len-2), ]
                    
                    
_PPP_ipcpopt_iphc_vj_types = {  0x0021: "Type IP" ,#RFC 1332 sec 4
                    0x002d: "Compressed TCP/IP" ,#RFC 1332 sec 4
                    0x002f: "Uncompressed TCP", #RFC 1332 sec 4
                    }
# Van Jacobson TCP/IP header compression in RFC1332
class PPP_IPCP_Option_IPCompress_VJ(PPP_IPCP_Option_IPCompress):
    name = "PPP IPCP Option: Van Jacobson TCP/IP header compression"
    fields_desc = [ ByteEnumField("type" , 2 , _PPP_ipcpopttypes),
                    ByteField("len", 6),
                    XShortEnumField("IP_Compression_Protocol",0x0021, _PPP_ipcpopt_iphc_vj_types), 
                    XByteField("Max_Slot_Id",0),
                    XByteField("Comp_Slot_Id",0),
                   ]

class PPP_IPCP_Option_IPAddress(PPP_IPCP_Option):
    name = "PPP IPCP Option: IP Address"
    fields_desc = [ ByteEnumField("type" , 3 , _PPP_ipcpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    IPField("data","0.0.0.0"),
                    ConditionalField(StrLenField("garbage","", length_from=lambda pkt:pkt.len-6), lambda p:p.len!=6) ]

class PPP_IPCP_Option_DNS1(PPP_IPCP_Option):
    name = "PPP IPCP Option: DNS1 Address"
    fields_desc = [ ByteEnumField("type" , 129 , _PPP_ipcpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    IPField("data","0.0.0.0"),
                    ConditionalField(StrLenField("garbage","", length_from=lambda pkt:pkt.len-6), lambda p:p.len!=6) ]

class PPP_IPCP_Option_DNS2(PPP_IPCP_Option):
    name = "PPP IPCP Option: DNS2 Address"
    fields_desc = [ ByteEnumField("type" , 131 , _PPP_ipcpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    IPField("data","0.0.0.0"),
                    ConditionalField(StrLenField("garbage","", length_from=lambda pkt:pkt.len-6), lambda p:p.len!=6) ]

class PPP_IPCP_Option_NBNS1(PPP_IPCP_Option):
    name = "PPP IPCP Option: NBNS1 Address"
    fields_desc = [ ByteEnumField("type" , 130 , _PPP_ipcpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    IPField("data","0.0.0.0"),
                    ConditionalField(StrLenField("garbage","", length_from=lambda pkt:pkt.len-6), lambda p:p.len!=6) ]

class PPP_IPCP_Option_NBNS2(PPP_IPCP_Option):
    name = "PPP IPCP Option: NBNS2 Address"
    fields_desc = [ ByteEnumField("type" , 132 , _PPP_ipcpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    IPField("data","0.0.0.0"),
                    ConditionalField(StrLenField("garbage","", length_from=lambda pkt:pkt.len-6), lambda p:p.len!=6) ]


class PPP_IPCP(Packet):
    fields_desc = [ ByteEnumField("code" , 1, _PPP_conftypes),
                    XByteField("id", 0 ),
                    FieldLenField("len" , None, fmt="H", length_of="options", adjust=lambda p,x:x+4 ),
                    PacketListField("options", [],  PPP_IPCP_Option, length_from=lambda p:p.len-4,) ]

                    
                    





### PPP IPV6CP stuff (RFC 5072)

# All IPV6CP options are defined below (names and associated classes) 
_PPP_ipv6cpopttypes = {     1:"Interface-Identifier",
                            2:"IPv6-Compression-Protocol",
                       }
# IPv6-Compression-Protocol types
_PPP_ipv6cpoptcptypes = {   0x0003:"Robust Header Compression", # RFC3241
                            #0x004f:"Historical",
                            0x0061:"IP Header Compression", # RFC2507,RFC3544
                        }

class PPP_IPV6CP_Option(Packet):
    name = "PPP IPV6CP Option"
    fields_desc = [ ByteEnumField("type" , None , _PPP_ipcpopttypes),
                FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                StrLenField("data", "", length_from=lambda p:max(0,p.len-2)) ]
    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls

class PPP_IPV6CP_Option_IID_Field(StrFixedLenField):

    def __init__(self, name, default):
        StrFixedLenField.__init__(self, name, default, length=8)
            
    def i2repr(self, pkt, v):
    
        return self.i2h(pkt,v)
        
    def i2h(self, pkt, x):
        '''Convert internal value to human value'''
        return "%x%x:%x%x:%x%x:%x%x" % (ord(x[0]),ord(x[1]),ord(x[2]),ord(x[3]),ord(x[4]),ord(x[5]),ord(x[6]),ord(x[7]),)
        
    def h2i(self, pkt, x):
        '''Convert human value to internal value'''
        if not isinstance(x,str):
            raise ValueError("PPP_IPV6CP_Option_IID_Field must be a str")
        xs = x.split(':')
        if not len(xs) == 4:
            raise ValueError("PPP_IPV6CP_Option_IID_Field must have format like this 1111:2222:3333:4444")
        ret = []
        for s in xs:
            s = ("0000000%s" % s)[-4:]
            s0 = chr( int(s[0],16) * 16 + int(s[1],16))
            s1 = chr( int(s[2],16) * 16 + int(s[3],16))
            ret.extend([s0,s1])
        return ''.join(ret)
        
class PPP_IPV6CP_Option_IID(PPP_IPV6CP_Option):
    name = "PPP IPV6CP Option: Interface_Identifier"
    fields_desc = [ ByteEnumField("type" , 1 , _PPP_ipv6cpopttypes),
                    FieldLenField("len", 10, length_of="Interface_Identifier", fmt="B", adjust=lambda p,x:x+2),
                    PPP_IPV6CP_Option_IID_Field("Interface_Identifier", "00:00:00:00")]

class PPP_IPV6CP(Packet):
    fields_desc = [ ByteEnumField("code" , 1, _PPP_conftypes),
                    XByteField("id", 0 ),
                    FieldLenField("len" , None, fmt="H", length_of="options", adjust=lambda p,x:x+4 ),
                    PacketListField("options", [],  PPP_IPV6CP_Option, length_from=lambda p:p.len-4,) ]
                    


                    
### ECP

_PPP_ecpopttypes = { 0:"OUI",
                     1:"DESE", }

class PPP_ECP_Option(Packet):
    name = "PPP ECP Option"
    fields_desc = [ ByteEnumField("type" , None , _PPP_ecpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    StrLenField("data", "", length_from=lambda p:max(0,p.len-2)) ]
    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls

class PPP_ECP_Option_OUI(PPP_ECP_Option):
    fields_desc = [ ByteEnumField("type" , 0 , _PPP_ecpopttypes),
                    FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+6),
                    StrFixedLenField("oui","",3),
                    ByteField("subtype",0),
                    StrLenField("data", "", length_from=lambda p:p.len-6) ]
                    


class PPP_ECP(Packet):
    fields_desc = [ ByteEnumField("code" , 1, _PPP_conftypes),
                    XByteField("id", 0 ),
                    FieldLenField("len" , None, fmt="H", length_of="options", adjust=lambda p,x:x+4 ),
                    PacketListField("options", [],  PPP_ECP_Option, length_from=lambda p:p.len-4,) ]

    
_PPP_LCP_codefield = {1:"Configure-Request",
                      2:"Configure-Ack",
                      3:"Configure-Nak",
                      4:"Configure-Reject",
                      5:"Terminate-Request",
                      6:"Terminate-Ack",
                      7:"Code-Reject",
                      8:"Protocol-Reject",
                      9:"Echo-Request",
                      10:"Echo-Reply",
                      11:"Discard-Request",
                      12:"Identification",
                      14:"Reset-Request",
                      15:"Reset-Ack"}


_PPP_LCP_optionaltype = {0:"RESERVED",
                         1:"Maximum-Receive-Unit",
						 2:"Asynchronous Control Character Map",
                         3:"Authentication-Protocol",
                         4:"Quality-Protocol",
                         5:"Magic-Number",
                         7:"Protocol-Field-Compression",
                         8:"Address-and-Control-Field-Compression",
						 9:"Field Check Sequence",
                         13:"Callback",
						 15:"Compound Frames",
                         17:"Multilink MRRU",
						 18:"Short Sequence Number Header Format Option",
                         19:"Multilink endpoint discriminator",
                         23:"Link discriminator for BAP"}

class PPP_LCP_Option(Packet):
    name = "PPP LCP Option"
    fields_desc = [ ByteEnumField("type" , None , _PPP_LCP_optionaltype),
                    #FieldLenField("len", None, length_of="data", fmt="B", adjust=lambda p,x:x+2),
                    #StrLenField("data", "", length_from=lambda p:max(0,p.len-2))
					]
    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls

class PPP_LCP(Packet):
    name = "PPP Link Control Protocol"
    fields_desc = [ ByteEnumField("code" , None,_PPP_LCP_codefield),
                    XByteField("identifier", 0),
                    ShortField("len" , None),
                    ConditionalField(PacketListField("options", [],  PPP_LCP_Option, length_from=lambda p:p.len-4), lambda p:p[PPP_LCP].code in range(1,5)),
					ConditionalField(StrLenField("data","",length_from=lambda p:p.len-4), lambda p:p[PPP_LCP].code in [5,6]),
					ConditionalField(StrLenField("rejectedpack","",length_from=lambda p:p.len-4), lambda p:p[PPP_LCP].code==7),
					ConditionalField(ShortField("rejectedproto",None),lambda p:p[PPP_LCP].code==8),
					ConditionalField(StrLenField("rejectedinfo","",length_from=lambda p:p.len-6), lambda p:p[PPP_LCP].code==8),
					ConditionalField(XIntField("magicnum",None),lambda p:p[PPP_LCP].code in [9,10,11,12,15]),
					ConditionalField(StrLenField("Data","",length_from=lambda p:p.len-8), lambda p:p[PPP_LCP].code in range(9,12)),
					ConditionalField(StrLenField("message","",length_from=lambda p:p.len-8), lambda p:p[PPP_LCP].code in [12,15]),
					#ConditionalField(XIntField("magicnum",None),lambda p:p[PPP_LCP].code==15),
					#ConditionalField(StrLenField("message","",length_from=lambda p:p.len-8), lambda p:p[PPP_LCP].code==15)
					#code ,14,to be added
					] 
    """
    def do_build(self):      

        avpval = self.getfieldval( (self.fields_desc[-1]).name) # if AVPs exists
            
        if len(avpval):
            self.overloaded_fields["type"]=1
            self.overloaded_fields["seq_present"]=1 
            self.overloaded_fields["len_present"]=1
        #other function can be added here to extend the intelligence 
        return Packet.do_build(self)
    """
    def post_build(self, p, pay):
        
        if self.len is None:
            l = len(pay)+len(p)
            p = p[:2]+struct.pack("!H",l)+ p[4:]            
        return p+pay
		
class MRU(PPP_LCP_Option):
    name = "Maximum Receive Unit(MRU)"
    fields_desc = [ ByteEnumField("type" , 1,_PPP_LCP_optionaltype),
                    ByteField("len", 4),
                    ShortField("mru" , None)]
					
class AUTHPROTO(PPP_LCP_Option):
    name = "Authentication Protocol(AUTHPROTO)"
    fields_desc = [ ByteEnumField("type" , 3,_PPP_LCP_optionaltype),
                    #BitFieldLenField("len" , None, 8, length_of="data", adjust=lambda p,x:x+4 ),
                    ByteField("len",5),
                    XShortEnumField("authproto" , None,{0xc023:"Password Authentication Protocol",0xc223:"Challenge Handshake Authentication Protocol"}),
					#StrLenField("data","",length_from=lambda p:p.len-4)
                    ByteEnumField("data", 0, {  0: "unused",
                                                1: "unused",
                                                2: "unused",
                                                3: "unused",
                                                4: "unused",
                                                5: "MD5",
                                                0x80: "MS-CHAP",
                                                0x82: "MS-CHAP-2",
                                                }),
                    ]
					
class QUALPROTO(PPP_LCP_Option):
    name = "Quality Protocol(QUALPROTO)"
    fields_desc = [ ByteEnumField("type" , 4,_PPP_LCP_optionaltype),
                    BitFieldLenField("len" , None, 8, length_of="data", adjust=lambda p,x:x+4 ),
                    XShortEnumField("qualproto" , None,{0xc025:"Link Quality Report"}),
					StrLenField("data","",length_from=lambda p:p.len-4)]
					
class MAGICNUM(PPP_LCP_Option):
    name = "Magic Number(MAGICNUM)"
    fields_desc = [ ByteEnumField("type" , 5,_PPP_LCP_optionaltype),
                    ByteField("len", 6),
                    XIntField("magicnum" , None)]
					
class PFC(PPP_LCP_Option):
    name = "Protocol Field Compression(PFC)"
    fields_desc = [ ByteEnumField("type" , 7,_PPP_LCP_optionaltype),
                    ByteField("len", 2)]
					
class ACCM(PPP_LCP_Option):
    name = "Asynchronous Control Character Map(ACCM)"
    fields_desc = [ ByteEnumField("type" , 2,_PPP_LCP_optionaltype),
	                ByteField("len", 6),
					XIntField("accm" , 0xF0F0F0F0)]

class ACFC(PPP_LCP_Option):
    name = "Address and Control Field Compression(ACFC)"
    fields_desc = [ ByteEnumField("type" , 8,_PPP_LCP_optionaltype),
                    ByteField("len", 2)]

class FCS(PPP_LCP_Option):
    name = "Field Check Sequence(FCS)"
    fields_desc = [ ByteEnumField("type" , 9,_PPP_LCP_optionaltype),
                    ByteField("len", 3),
                    ByteField("fcs" , 0xFF)]					
					
class CALLBACK(PPP_LCP_Option):
    name = "Callback"
    fields_desc = [ ByteEnumField("type" , 13,_PPP_LCP_optionaltype),
                    BitFieldLenField("len" , None, 8, length_of="message", adjust=lambda p,x:x+3 ),
                    ByteEnumField("operation" , None,{ 0:"location is determined by user authentication",
					                                   1:"Dialing string",
													   2:"Location identifier",
													   3:"E.164 number",
													   4:"Distinguished name"}),
					StrLenField("message","",length_from=lambda p:p.len-3)]
					
class COMPOUNDFRAMES(PPP_LCP_Option):
    name = "Compound Frames"
    fields_desc = [ ByteEnumField("type" , 15,_PPP_LCP_optionaltype),
                    ByteField("len", 2)]

class MRRU(PPP_LCP_Option):
    name = "Multilink MRRU(MRRU)"
    fields_desc = [ ByteEnumField("type" , 17,_PPP_LCP_optionaltype),
                    ByteField("len", 4),
                    ShortField("mrru" , None)]		

class SSNHFO(PPP_LCP_Option):
    name = "Short Sequence Number Header Format Option(SSNHFO)"
    fields_desc = [ ByteEnumField("type" , 18,_PPP_LCP_optionaltype),
                    ByteField("len", 2)]					
					
class EDO(PPP_LCP_Option):
    name = "Endpoint Discriminator Option(EDO)"
    fields_desc = [ ByteEnumField("type" , 19,_PPP_LCP_optionaltype),
                    BitFieldLenField("len" , None, 8, length_of="address", adjust=lambda p,x:x+4 ),
                    ByteEnumField("class" , None,{0:"Null Class",
					                               1:"Locally Assigned Address",
												   2:"Internet Protocol (IP) Address",
												   3:"IEEE 802.1 Globally Assigned MAC Address",
												   4:"PPP Magic-Number Block",
												   5:"Public Switched Network Directory Number"}),
					StrLenField("address","",length_from=lambda p:p.len-3)]

class LDB(PPP_LCP_Option):
    name = "Link discriminator for BAP(LDB)"
    fields_desc = [ ByteEnumField("type" , 23,_PPP_LCP_optionaltype),
                    ByteField("len", 4),
                    ShortField("linkdiscrim" , None)]					
					
_PPP_PAP_types = {1:"Authenticate-Request",
                  2:"Authenticate-Ack",
                  3:"Authenticate-Nak"}

class PPP_PAP(Packet):                                                               # RFC 1334
    name="PPP Password Authentication Protocol"
    fields_desc = [ ByteEnumField("code" , None,_PPP_PAP_types),
                    XByteField("identifier", 0),
                    ShortField("len" , None),
                    ConditionalField(BitFieldLenField("peer_id_len" , None, 8, length_of="peer_id", adjust=lambda p,x:x),lambda p:p[PPP_PAP].code==1),
                    ConditionalField(StrLenField("peer_id","",length_from=lambda p:p.peer_id_len), lambda p:p[PPP_PAP].code==1),
                    ConditionalField(BitFieldLenField("passwd_len" , None, 8, length_of="peer_id", adjust=lambda p,x:x),lambda p:p[PPP_PAP].code==1),
                    ConditionalField(StrLenField("password","",length_from=lambda p:p.passwd_len), lambda p:p[PPP_PAP].code==1),
                    ConditionalField(BitFieldLenField("msg_len" , None, 8, length_of="message", adjust=lambda p,x:x),lambda p:p[PPP_PAP].code in range(2,4)),
                    ConditionalField(StrLenField("message","",length_from=lambda p:p.msg_len), lambda p:p[PPP_PAP].code in range(2,4))
                    
                    #ConditionalField(StrLenField("message","",length_from=lambda p:p.len-8), lambda p:p[PPP_LCP].code==15)
                    #code ,14,to be added
                    ] 
    
_PPP_CHAP_types = { 1:   "Challenge",
                    2:  "Response",
                    3:  "Success",
                    4:  "Failure"}

class PPP_CHAP_Data(Packet):
    name = "PPP CHAP data"
    fields_desc = [ByteField("value_size",None),
                   StrLenField("value","",length_from=lambda p:p.value_size),
                   StrField("username","")]
    @classmethod
    def extract_padding(self,pay):
        return "",pay
        
class PPP_CHAP(Packet):                                                         # RFC 1994
    name = "PPP Challenge Handshake Authentication Protocol"
    fields_desc = [ ByteEnumField("code" , None,_PPP_CHAP_types),
                    XByteField("identifier", 0),
                    ShortField("len" , None),
                    ConditionalField( PacketLenField("data", None, PPP_CHAP_Data, length_from=lambda p:p.len -4),   
                                      lambda p:p[PPP_CHAP].code in [1,2] ),
                                      
                    ConditionalField( StrLenField("message","", length_from=lambda p:p.len -4),
                                      lambda p:p[PPP_CHAP].code in [3,4] ),
                   ]
                                                           

bind_layers( Ether,         PPPoED,        type=0x8863)
#bind_layers( Ether,         PPPoE,         type=0x8864)
bind_layers( Ether,         PPPoES,        type=0x8864)       
bind_layers( CookedLinux,   PPPoED,        proto=0x8863)
bind_layers( CookedLinux,   PPPoES,         proto=0x8864)
bind_layers( PPPoES,         PPP,           code=0)
#bind_layers( GRE,           HDLC,          proto=0x880b)
bind_layers( GRE,           PPP,          proto=0x880b)
bind_layers( HDLC,          PPP,           )
bind_layers( PPP,           IP,            proto=33)
bind_layers( PPP,           PPP_IPCP,      proto=0x8021)
bind_layers( PPP,           PPP_ECP,       proto=0x8053)
bind_layers( Ether,         PPP_IPCP,      type=0x8021)
bind_layers( Ether,         PPP_ECP,       type=0x8053)
bind_layers( PPP,           PPP_LCP,       proto=0xc021)
bind_layers( PPP,           PPP_PAP,       proto=0xc023)
bind_layers( PPP,           PPP_CHAP,      proto=0xc223)
bind_layers( PPP,           IPv6,          proto=0x0057 )
bind_layers( PPP,           PPP_IPV6CP,          proto=0x8057 )