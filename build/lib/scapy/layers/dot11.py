## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import re,struct

from scapy.packet import *
from scapy.fields import *
from scapy.plist import PacketList
from scapy.layers.l2 import *


try:
    from Crypto.Cipher import ARC4
except ImportError:
    log_loading.info("Can't import python Crypto lib. "
                     "Won't be able to decrypt WEP.")


### Fields

class Dot11AddrMACField(MACField):
    def is_applicable(self, pkt):
        return 1
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return MACField.addfield(self, pkt, s, val)
        else:
            return s        
    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return MACField.getfield(self, pkt, s)
        else:
            return s,None

class Dot11Addr2MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type == 1:
            # RTS, PS-Poll, CF-End, CF-End+CF-Ack
            return pkt.subtype in [ 0xb, 0xa, 0xe, 0xf] 
        return 1

class Dot11Addr3MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type in [0,2]:
            return 1
        return 0

class Dot11Addr4MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type == 2:
            if pkt.FCfield & 0x3 == 0x3: # To-DS and From-DS are set
                return 1
        return 0
    

### Layers


class PrismHeader(Packet):
    """ iwpriv wlan0 monitor 3 """
    name = "Prism header"
    fields_desc = [ LEIntField("msgcode",68),
                    LEIntField("len",144),
                    StrFixedLenField("dev","",16),
                    LEIntField("hosttime_did",0),
                  LEShortField("hosttime_status",0),
                  LEShortField("hosttime_len",0),
                    LEIntField("hosttime",0),
                    LEIntField("mactime_did",0),
                  LEShortField("mactime_status",0),
                  LEShortField("mactime_len",0),
                    LEIntField("mactime",0),
                    LEIntField("channel_did",0),
                  LEShortField("channel_status",0),
                  LEShortField("channel_len",0),
                    LEIntField("channel",0),
                    LEIntField("rssi_did",0),
                  LEShortField("rssi_status",0),
                  LEShortField("rssi_len",0),
                    LEIntField("rssi",0),
                    LEIntField("sq_did",0),
                  LEShortField("sq_status",0),
                  LEShortField("sq_len",0),
                    LEIntField("sq",0),
                    LEIntField("signal_did",0),
                  LEShortField("signal_status",0),
                  LEShortField("signal_len",0),
              LESignedIntField("signal",0),
                    LEIntField("noise_did",0),
                  LEShortField("noise_status",0),
                  LEShortField("noise_len",0),
                    LEIntField("noise",0),
                    LEIntField("rate_did",0),
                  LEShortField("rate_status",0),
                  LEShortField("rate_len",0),
                    LEIntField("rate",0),
                    LEIntField("istx_did",0),
                  LEShortField("istx_status",0),
                  LEShortField("istx_len",0),
                    LEIntField("istx",0),
                    LEIntField("frmlen_did",0),
                  LEShortField("frmlen_status",0),
                  LEShortField("frmlen_len",0),
                    LEIntField("frmlen",0),
                    ]
    def answers(self, other):
        if isinstance(other, PrismHeader):
            return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)

###############################################
# RadioTap Field
###############################################
class RaTFlags(Packet):
    name = "Present flags"
    fields_desc = [ BitEnumField("lock_quality", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("dBm_AntNoise", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("dBm_AntSignal", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("FHSS", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("channel", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("rate", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("flags", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("TSFT", None, 1, {0:"False", 1:"True"}),
                    
                    BitEnumField("b15", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("FCS_in_header", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("dB_AntNoise", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("dB_AntSignal", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("antenna", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("dBm_TX_Power", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("dB_TX_Attenuation", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("TX_Attenuation", None, 1,
                                 {0:"False", 1:"True"}),
                    
                    BitEnumField("b23", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b22", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b21", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b20", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b19", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b18", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b17", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b16", None, 1, {0:"False", 1:"True"}),
                    
                    BitEnumField("Ext", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b30", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b29", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b28", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b27", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b26", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b25", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("b24", None, 1, {0:"False", 1:"True"}),
                    
                ]

class Flags(Packet):
    name = "Flags"
    fields_desc = [ BitEnumField("short_GI", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("bad_fcs", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("data_pad", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("fcs_at_end", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("fragmentation", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("WEP", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("preamble", None, 1, {0:"Long", 1:"Short"}),
                    BitEnumField("CFP", None, 1, {0:"False", 1:"True"}),
                ]
                
class ChanType(Packet):
    name = "Channel Type"
    fields_desc = [ BitEnumField("is2G", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("OFDM", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("CCK", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("turbo", None, 1, {0:"False", 1:"True"}),
                    BitField("reserved", None, 4),
                    
                    BitEnumField("quarter_rate_channel", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("half_rate_channel", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("static_turbo", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("GSM", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("GFSK", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("dynamic_CCK_OFDM", None, 1,
                                 {0:"False", 1:"True"}),
                    BitEnumField("passive", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("is5G", None, 1, {0:"False", 1:"True"}),
                    
                ]

class MCS_Known(Packet):
    name = "MCS Known"
    fields_desc = [ BitField("reserved", None, 3),
                    BitEnumField("FEC_type", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("HT_format", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("guard_interval", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("MCS_index", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("bandwidth", None, 1, {0:"False", 1:"True"}),
                    ]
                    
class MCS_Flags(Packet):
    name = 'MCS Flags'
    fields_desc = [ BitField("reserved", None, 3),
                    BitEnumField("FEC_type", None, 1, {0:"BCC", 1:"LDPC"}),
                    BitEnumField("HT_format", None, 1, {0:"mixed", 1:"greenfiled"}),
                    BitEnumField("guard_interval", None, 1, {0:"long GI", 1:"short GI"}),
                    BitEnumField("bandwidth", None, 2, {0:"20", 1:"40", 2:"20L", 3:"20U"}),            
                    ]
                
class MCS(Packet):
    name = "MCS"
    fields_desc = [ PacketListField("MCS_knwon", None, MCS_Known,
                                    length_from=lambda x:1),
                    PacketListField("MCS_flags", None, MCS_Flags,
                                    length_from=lambda x:1),
                    ByteField("MCS_index", None)
                    ]
                
class RadioTap(Packet):
    name = "RadioTap dummy"
    fields_desc = [ ByteField('version', 0),
                    ByteField('pad', 0),
                    FieldLenField('len', None, 'notdecoded', '<H',
                                  adjust=lambda pkt,x:x+8),
                    PacketListField("present_flags", None, RaTFlags,
                                    length_from=lambda x:4),
                    ConditionalField(LELongField("timestamp", None),
                                     lambda x:x[RaTFlags].TSFT ==1),
                    ConditionalField(PacketListField("flags", None, Flags,
                                                     length_from=lambda x:1),
                                     lambda x:x[RaTFlags].flags==1),
                    ByteField("rate", None),
                    ConditionalField(LEShortField("channel_frequency", None),
                                     lambda x:x[RaTFlags].channel==1),
                    ConditionalField(PacketListField("channel_type", None,
                                                     ChanType,
                                                     length_from=lambda x:2),
                                     lambda x:x[RaTFlags].channel==1),
                    ConditionalField(ByteField("FHSS", None),
                                     lambda x:x[RaTFlags].FHSS==1),
                    ConditionalField(ByteField("singnal", None),
                                     lambda x:x[RaTFlags].dBm_AntSignal==1),
                    ConditionalField(ByteField("noise", None),
                                     lambda x:x[RaTFlags].dBm_AntNoise==1),
                    ConditionalField(ByteField("antenna", None),
                                     lambda x:x[RaTFlags].antenna==1),                 
                    StrLenField("reserved", "", length_from=lambda x:x.len-9
                                -8*x[RaTFlags].TSFT-x[RaTFlags].flags-4*x[RaTFlags].channel
                                -x[RaTFlags].FHSS-x[RaTFlags].dBm_AntSignal-x[RaTFlags].dBm_AntNoise
                                -x[RaTFlags].antenna-3*(x[RaTFlags].rate==0)),
                    ConditionalField(PacketListField("MCS", None,
                                                     MCS,
                                                     length_from=lambda x:3),
                                     lambda x:(x[RaTFlags].rate==0))
                ]

###############################################
# RadioTap Field
###############################################

###############################################
# Dot11 Field
###############################################

class Dot11SCField(LEShortField):
    def is_applicable(self, pkt):
        return pkt.type != 1 # control frame
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return LEShortField.addfield(self, pkt, s, val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return LEShortField.getfield(self, pkt, s)
        else:
            return s,None

class FCField(Packet):
    name = "Frame Control Field"
    fields_desc = [ BitEnumField("order", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("wep", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("MD", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("pw_mgt", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("retry", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("MF", None, 1, {0:"False", 1:"True"}),
                    BitEnumField("from_DS", None, 1, {0:"Long", 1:"Short"}),
                    BitEnumField("to_DS", None, 1, {0:"False", 1:"True"}),
                ]
            
class Dot11(Packet):
    name = "802.11"
    fields_desc = [
                    BitField("subtype", 0, 4),
                    BitEnumField("type", 0, 2,
                                 ["Management", "Control", "Data", "Reserved"]),
                    BitField("proto", 0, 2),
                    FlagsField("FCfield", 0, 8,
                               ["to_DS", "from_DS", "MF", "retry", "pw_mgt",
                                "MD", "wep", "order"]),
                    LEShortField("ID",0),
                    MACField("addr1", ETHER_ANY),
                    Dot11Addr2MACField("addr2", ETHER_ANY),
                    Dot11Addr3MACField("addr3", ETHER_ANY),
                    Dot11SCField("SC", 0),
                    Dot11Addr4MACField("addr4", ETHER_ANY),
                    ]
    def mysummary(self):
        return self.sprintf("802.11 %Dot11.type% %Dot11.subtype% "
                            "%Dot11.addr2% > %Dot11.addr1%")
    def guess_payload_class(self, payload):
        if self.type == 0x02 and (self.subtype >= 0x08
                                  and self.subtype <=0xF
                                  and self.subtype != 0xD):
            return Dot11QoS
        elif self.FCfield & 0x40:
            return Dot11WEP
        else:
            return Packet.guess_payload_class(self, payload)
    def answers(self, other):
        if isinstance(other,Dot11):
            if self.type == 0: # management
                if self.addr1.lower() != other.addr2.lower():
                    # check resp DA w/ req SA
                    return 0
                if (other.subtype,self.subtype) in [(0,1),(2,3),(4,5)]:
                    return 1
                if self.subtype == other.subtype == 11: # auth
                    return self.payload.answers(other.payload)
            elif self.type == 1: # control
                return 0
            elif self.type == 2: # data
                return self.payload.answers(other.payload)
            elif self.type == 3: # reserved
                return 0
        return 0
    def unwep(self, key=None, warn=1):
        if self.FCfield & 0x40 == 0:
            if warn:
                warning("No WEP to remove")
            return
        if  isinstance(self.payload.payload, NoPayload):
            if key or conf.wepkey:
                self.payload.decrypt(key)
            if isinstance(self.payload.payload, NoPayload):
                if warn:
                    warning("Dot11 can't be decrypted. Check conf.wepkey.")
                return
        self.FCfield &= ~0x40
        self.payload=self.payload.payload
        
    def extract_padding(self, pay):
        return pay[:-4], pay[-4:]

###############################################
# Dot11 Field
###############################################

class Dot11QoS(Packet):
    name = "802.11 QoS"
    fields_desc = [ BitField("TID",None,4),
                    BitField("EOSP",None,1),
                    BitField("Ack Policy",None,2),
                    BitField("Reserved",None,1),
                    ByteField("TXOP",None) ]
    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, Dot11):
            if self.underlayer.FCfield & 0x40:
                return Dot11WEP
        return Packet.guess_payload_class(self, payload)


"""
capability_list = [ "res8", "res9", "short-slot", "res11",
                    "res12", "DSSS-OFDM", "res14", "res15",
                   "ESS", "IBSS", "CFP", "CFP-req",
                   "privacy", "short-preamble", "PBCC", "agility"]
"""

reason_code = {0:"reserved",1:"unspec", 2:"auth-expired",
               3:"deauth-ST-leaving",
               4:"inactivity", 5:"AP-full", 6:"class2-from-nonauth",
               7:"class3-from-nonass", 8:"disas-ST-leaving",
               9:"ST-not-auth"}

status_code = {0:"success", 1:"failure", 10:"cannot-support-all-cap",
               11:"inexist-asso", 12:"asso-denied", 13:"algo-unsupported",
               14:"bad-seq-num", 15:"challenge-failure",
               16:"timeout", 17:"AP-full",18:"rate-unsupported" }


_InfoElt ={ 0:"SSID", 1:"Rates", 2: "FHset", 3:"DSset", 4:"CFset", 5:"TIM",
            6:"IBSSset", 7:"Country", 16:"challenge", 33:"Power Capability",
            36:"Supported Channels", 42:"ERPinfo", 45:"HT Capabilities",
            46:"QoS Capability", 47:"ERPinfo", 48:"RSNinfo", 50:"ESRates",
            221:"vendor",68:"reserved"
           }      

_InfoWPS = {0x104A:"Version", 0x1044:"WPS", 0x103B:"RspType", 0x1047:"UUID_E", 
            0x1021:"Manufacturer", 0x1023:"Model Name", 0x1024:"Model number",
            0x1042:"Serial Number", 0x1054:"Category", 0x1011:"Device Name",
            0x1008:"Config Methods", 0x103C:"RF Bands",
            0x1049:"Vendor Extension", 0x1053:"Selected Register Config Methods",
            0x1012:"Device Password ID", 0x1041:"Selected Register"}    

###############################################
# Information Element Field
###############################################            
            
class Dot11EltBak(Packet):
    name = "802.11 Information Element"
    fields_desc = [ ByteEnumField("ID", 0, _InfoElt),
                    FieldLenField("len", None, "info", "B"),
                    StrLenField("info", "", length_from=lambda x:x.len) ]
    def mysummary(self):
        if self.ID == 0:
            return "SSID=%s"%repr(self.info),[Dot11]
        else:
            return ""
    
    def __getitem__(self,att):
        
        if isinstance(att,str):
            att = self.con_s2i(self.fieldtype,'ID',att)
        out = []
        if 'ID' in self.fields.keys() and self.fields['ID']==att:
             ret={}
             for key in self.fields.keys():
                 val = self.fields[key]
                 ret[key]=self.con_i2s(self.fieldtype, key, val)
                 #return ret
             out.append(ret)
             if isinstance(self.payload,Dot11Elt):
                 ext = self.payload[att]
                 if ext is not None:
                     out.extend(ext)
             return out
        elif isinstance(self.payload,Dot11Elt):
            return (self.payload)[att]
        else:
            return None
        
    def con_i2s(self,fldtype,key,i):#Enum fields i2s
        IDfld=fldtype[key]
        
        if "i2s" in dir(IDfld) and i in IDfld.i2s.keys():
            return IDfld.i2s[i]
        return i
    def con_s2i(self,fldtype,key,s):
        IDfld=fldtype[key]
      
        if "s2i" in dir(IDfld) and s in IDfld.s2i.keys():
            return IDfld.s2i[s]
        return s
    
class Dot11Elt(Packet):
    name = "802.11 Information Element"
    fields_desc = [ ByteEnumField("ID", None, _InfoElt),
                    FieldLenField("len", None,"info","B"),
                    StrLenField("info","",length_from=lambda x:x.len)
                  ]
    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        if cls.ID.default == 221:
            cls.registered_options[cls.OUI.default] = cls
            # if cls.info[0:3] == '\x00P\xf2':
                # if cls.info[0:6] == '\x00P\xf2\x04\x10J':
                    # cls.registered_options[cls.info[0:6]] = cls
                # else:
                    # cls.registered_options[cls.info[0:3]] = cls
        else:
            cls.registered_options[cls.ID.default] = cls
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:

            o = ord(_pkt[0])
            if o != 221:
                return cls.registered_options.get(o, cls)
            else:
                o  = _pkt[2:6]
                return cls.registered_options.get(o, cls)
        return cls
      
class Elt_SSID(Dot11Elt):
    name = "802.11 Element SSID"
    fields_desc = [ ByteEnumField("ID", 0, _InfoElt),
                    FieldLenField("len", None,"SSID", fmt="B"),
                    StrLenField("SSID","",length_from=lambda x:x.len)
                ]

class Elt_Rates(Dot11Elt):
    name = "802.11 Element Supported Rates"
    fields_desc = [ ByteEnumField("ID", 1, _InfoElt),
                    FieldLenField("len", None,"rates", fmt="B"),
                    StrLenField("rates","",length_from=lambda x:x.len)
                ]    

class Elt_DSset(Dot11Elt):
    name = "802.11 Element DS Set"
    fields_desc = [ ByteEnumField("ID", 3, _InfoElt),
                    ByteField("len",0),
                    ByteField("cur_channel",0)
                ] 

class Elt_TIM(Dot11Elt):
    name = "802.11 Element Traffic Indication Map"
    fields_desc = [ ByteEnumField("ID", 5,_InfoElt),
                    FieldLenField("len", None,length_of="partv_bmp", fmt="B",
                                  adjust=lambda ptk,x:x+3),                    
                    ByteField("DTIM_count", None),
                    ByteField("DTIM_period", None),
                    ByteField("bitmap_ctrl", None),
                    StrLenField("partv_bmap",None,length_from=lambda x:x.len-3)
              #Partial Virtual Bitmap to be added
                   ]
               
class Elt_Country(Dot11Elt):
    name = "802.11 Element Country"
    fields_desc = [ ByteEnumField("ID", 7, _InfoElt),
                    ByteField("len", None),
                    StrLenField("country_code", "", length_from=lambda x:3),
                    ByteField("strt_channel", 0),
                    ByteField("num_of_channel", 0),
                    ByteField("max_tx_power", 0),
                    ConditionalField(StrLenField("reserved", "",
                                                 length_from=lambda x:x.len-6),
                                     lambda x:x.len>6),
                ]

class Elt_PowerCap(Dot11Elt):
    name = "802.11 Element Power Capability"
    fields_desc = [ ByteEnumField("ID", 33, _InfoElt),
                    ByteField("len", None),
                    ByteField("min_transmit_power_cap", None),
                    ByteField("max_transmit_power_cap", None),
                ]
                
class Elt_SuppChan(Dot11Elt):
    name = "802.11 Element Supported Channels"
    fields_desc = [ ByteEnumField("ID", 36, _InfoElt),
                    ByteField("len", None),
                    ByteField("first_channel", None),
                    ByteField("num_of_channels", None),
                ]
             
class ERP_Flags(Packet):
    name = "ERP Flags"
    fields_desc = [
                    BitField("reserved", None, 1),
                    BitField("reserved", None, 1),
                    BitField("reserved", None, 1),
                    BitField("reserved", None, 1),
                    BitField("reserved", None, 1),
                    BitEnumField("barker_preamble_mode", None, 1,
                                 {0:"No", 1:"Yes"}),
                    BitEnumField("use_of_protection", None, 1,
                                 {0:"Disable", 1:"Enable"}),
                    BitEnumField("non_ERP", None, 1,
                                 {0:"Not Present", 1:"Present"}),
                ]
                  
class Elt_ERP(Dot11Elt):
    name = "802.11 Element ERP Information"
    fields_desc = [ ByteEnumField("ID", 42, _InfoElt),
                    ByteField("len", None),
                    PacketListField("ERP_flags", None, ERP_Flags,
                                    length_from=lambda x:1),
                ]
                
class HTCAP_INFO(Packet):
    """this class belongs to class HTCap"""
    name = "HT Capabilities Info(HTCAP_INFO)"
    fields_desc = [
                   BitEnumField("Tx_STBC",None,1,
                                {0:"Not supported",1:"Supported"}),
                   BitEnumField("Short_GI_40",None,1,
                                {0:"Not supported",1:"Supported"}),
                   BitEnumField("Short_GI_20",None,1,
                                {0:"Not supported",1:"Supported"}),
                   BitEnumField("HT_greenfield",None,1,
                                {0:"Not supported",1:"Supported"}),
                   BitEnumField("SM_power_save",None,2,
                                {0:"static mode",1:"dynamic save",
                                 2:"reserved",3:"disabed"}),
                   BitEnumField("sp_channel_width",None,1,
                                {0:"Only 20Mz Supported",
                                 1:"Support 20Mz and 40Mz"}),
                   BitEnumField("LDPC_coding_cap",None,1,
                                {0:"Not supported",1:"Supported"}),
                   
                   BitEnumField("LSIG_TXOP_pro",None,1,
                                {0:"Not supported",1:"Supported"}),
                   BitField("Intolerant_40",None,1),
                   BitField("reserved",0,1),
                   BitField("DSSSCCK_mode_40",None,1),
                   BitEnumField("Max_AMSDU_len",None,1,
                                {0:"3839 octets",1:"7935 octets"}),
                   BitEnumField("HT_Delayed_blkack",None,1,
                                {0:"Not supported",1:"Supported"}),
                   BitEnumField("Rx_STBC",None,2,
                                {0:"No support",1:"Support 1 spatial stream",
                                 2:"Support 1 and 2 spatial stream",
                                 3:"Support 1,2 and 3 spatial stream"}),
                   ]
    
class A_MPDU(Packet):
    name = "A-MPDU Parameters Set(A_MPDU)"
    fields_desc =[ 
                  BitField("reserved",None,3),
                  BitField("min_spacing",None,3),
                  BitField("max_len",None,2),
                  ]
class MCS_SET(Packet):
    name = "Rx Supported Modulation and Coding Scheme Set(MCS_SET)"
    fields_desc =[ XBitField("Rx_MCS_bitmask",None,77),
                  BitField("reserved0",None,3),
                  XBitField("Rx_highest_rate",None,10),
                  BitField("reserved1",None,6),
                  BitField("Tx_MCS_set",None,1),
                  BitField("TxRx_MCSset_notequal",None,1),
                  BitField("Txmax_spa_strm",None,2),
                  BitField("Tx_unequal_module",None,1),
                  BitField("reserved2",None,27)
                  ]
class EXT_CAP(Packet):
    name = "HT Extended Capabilities Field(EXT_CAP)"
    fields_desc =[
                  BitEnumField("pco",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("pco_trans_time",None,2,
                               {0:"No transition",1:"400us",2:"1.5ms",3:"5ms"}),
                  BitField("reserved0",None,5),
                  BitEnumField("feedback",None,2,
                               {0:"No feedback",1:"reserved",2:"Unsolicited",
                                3:"Both"}),
                  BitEnumField("htc_support",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("rd_responder",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitField("reserved1",None,4)
                  
                  ]
class TB_CAP(Packet):
    name ="Transmit Beamforming Capabilities(TB_CAP)"
    fields_desc =[
                  BitEnumField("trans_bf_recv",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("recv_stg_sound",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("trans_stg_sound",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("recv_NDP",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("trans_NDP",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("trans_bf",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitField("calib",None,2),
                  BitEnumField("CSI_trans_bf",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("noncmpr_steer",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("cmpr_steer",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("trans_bf_CSI_feedback",None,2,
                               {0:"Not supported",1:"Delayed feedback",
                                2:"Immediate feedback",
                                3:"Delayed and immediate feedback"}),
                  BitEnumField("noncmpr_bf_feedback",None,2,
                               {0:"Not supported",1:"Delayed feedback",
                                2:"Immediate feedback",
                                3:"Delayed and immediate feedback"}),
                  BitEnumField("cmpr_bf_feedback",None,2,
                               {0:"Not supported",1:"Delayed feedback",
                                2:"Immediate feedback",
                                3:"Delayed and immediate feedback"}),
                  BitEnumField("min_grouping",None,2,
                               {0:"Not supported",1:"groups of 1,2",
                                2:"groups of 1,4",3:"groups of 1,2,4"}),
                  BitEnumField("CSI_bf_ant",None,2,
                               {0:"Single sounding",1:"2 antenna sounding",
                                2:"3 antenna sounding",3:"4 antenna sounding"}),
                  BitEnumField("noncmpr_steer_bfant",None,2,
                               {0:"Single sounding",1:"2 antenna sounding",
                                2:"3 antenna sounding",3:"4 antenna sounding"}),
                  BitEnumField("cmpr_steer_bfant",None,2,
                               {0:"Single sounding",1:"2 antenna sounding",
                                2:"3 antenna sounding",3:"4 antenna sounding"}),
                  BitEnumField("CSI_max_bf",None,2,
                               {0:"Single row CSI",1:"2 row CSI",
                                2:"3 row CSI",3:"4 row CSI"}),
                  BitEnumField("chnl_est_cap",None,2,
                               {0:"1 space-time stream",1:"2 space-time stream",
                                2:"3 space-time stream",
                                3:"4 space-time stream"}),
                  BitField("rsvd",None,3),
                  ]
class ASEL_CAP(Packet):
    name ="Antenna Selection Capabilities(ASEL_CAP)"
    fields_desc =[
                  BitEnumField("asel",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("CSI_feedback_asel",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("AI_feedback_asel",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("CSI_feedback",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("AI_feedback",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("recv_asel",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("trans_sound_PPDU",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitField("rsvd",None,1),
                  ]

class Elt_HTCap(Dot11Elt):
    name ="802.11 Element HT Capabilities"
    fields_desc = [ ByteEnumField("ID", 45,_InfoElt),
                    ByteField("len",None),
                    PacketListField("capinfo",None,HTCAP_INFO,
                                    length_from=lambda x:2),
                    PacketListField("a_mpdu",None,A_MPDU,
                                    length_from=lambda x:1),
                    PacketListField("mcs_set",None,MCS_SET,
                                    length_from=lambda x:16),
                    PacketListField("ext_cap",None,EXT_CAP,
                                    length_from=lambda x:2),
                    PacketListField("tb_cap",None,TB_CAP,
                                    length_from=lambda x:4),
                    PacketListField("asel_cap",None,ASEL_CAP,
                                    length_from=lambda x:1),                    
                ]    

class Elt_QoS(Dot11Elt):
    name = "802.11 Element QoS Capability"
    fields_desc = [ ByteEnumField("ID", 46, _InfoElt),
                    ByteField("len", None),
                    StrLenField("info", "", length_from=lambda x:1),
                ]
                
class RSN_CAP(Packet):
    name = "RSN Capabilities"
    fields_desc = [ BitField("reserved", None, 10),
                    BitField("GIKSA_replay_Ctr", None, 2),
                    BitField("PIKSA_replay_Ctr", None, 2),
                    BitEnumField("no_pairwise", None, 1,
                                 {0:"Not supported", 1:"Supported"}),
                    BitEnumField("pre_authentication", None, 1,
                                 {0:"Not supported", 1:"Supported"}),
                ]
                
class UnicastCipherSuite(Packet):
    name = "Unicast Cipher Suite"
    fields_desc = [ XIntField("unicast_cipher_suite",None)]
    
    def extract_padding(self, pay):
        return "",pay
    
class AuthKeyMgmtSuite(Packet):
    name = "Auth Key Management Suite"
    fields_desc = [ XIntField("auth_key_mgmt_suite",None)]    
    def extract_padding(self, pay):
        return "",pay    
    
class Elt_RSNInfo(Dot11Elt):
    name = "802.11 Element RSN Infomation"
    fields_desc = [ ByteEnumField("ID", 48, _InfoElt),
                    ByteField("len", None),
                    LEShortField("version", 1),               
                    XIntField("multicast_cipher_suite",""),
                    LEShortField("no_unicast_cipher_suites", 0),
                    PacketListField("unicast_cipher_suites", None, UnicastCipherSuite, 
                                        length_from=lambda x:x.no_unicast_cipher_suites * 4),                    
                    LEShortField("no_auth_key_mgmt_suites", None),
                    PacketListField("auth_key_mgmt_suites", None, AuthKeyMgmtSuite, 
                                        length_from=lambda x:x.no_auth_key_mgmt_suites * 4),                    
                    
                    PacketListField("RSN_capabilities", None, RSN_CAP,
                                    length_from=lambda x:2),
                ]
                
class Elt_ESRates(Dot11Elt):
    name = "802.11 Element Extended Supported Rates"
    fields_desc = [ ByteEnumField("ID", 50, _InfoElt),
                    ByteField("len", None),
                    StrLenField("rates", "", length_from=lambda x:x.len)
                ]

class SUBNET1(Packet):
    name = "HT Information Subnet(1 of 3)(SUBNET1)"
    fields_desc = [
                   BitField("service_interval",None,3),
                   BitEnumField("PSMP_sta_only", None, 1,
                                {0:"regardless", 1:"accepted"}),
                   BitEnumField("rifs_mode",None,1,
                                {0:"prohibited",1:"permitted"}),
                   BitEnumField("sta_chan_width",None,1,
                                {0:"20m", 1:"any"}),
                   BitEnumField("sec_chan_offset",None,2,
                                {0:"SCN",1:"SCA",2:"reserved",3:"SCB"}),
                   
                   ]

class SUBNET2(Packet):
    name = "HT Information Subnet(2 of 3)(SUBNET2)"
    fields_desc = [
                   BitField("rsvd1",None,11),
                   BitField("obs_nonsta_pre",None,1),
                   BitEnumField("rsvd0",None,1,
                                {0:"SCN",1:"SCA",2:"reserved",3:"SCB"}),
                   BitField("nongf_sta_pre",None,1),
                   BitEnumField("HT_protect",None,2,
                                {0:"no protection",1:"nonmember protection",
                                 2:"20 MHz protection",3:"non-HT mixed"}),
                   ]

class SUBNET3(Packet):
    name = "HT Information Subnet(3 of 3)(SUBNET3)"
    fields_desc = [
                   BitField("rsvd1",None,4),
                   BitEnumField("pco_phase",None,1,
                                {0:"Switch to or continue 20 Mhz",
                                 1:"Switch to or continue 40Mhz"}),
                   BitEnumField("pco_active",None,1,
                                {0:"Not active",1:"Active"}),
                   BitField("lsig_txop_pro",None,1),
                   BitEnumField("stbc_beacon",None,1,
                                {0:"in a primary beacon",
                                 1:"in an STBC beacon"}),
                   BitEnumField("dual_cts_pro",None,1,
                                {0:"Not required",1:"Required"}),
                   BitEnumField("dual_beacon",None,1,
                                {0:"no STBC beacon transmitted",
                                 1:"transmitted by the AP"}),
                   BitField("rsvd0",None,6),
                   
                   ]
class Elt_HTInfo(Dot11Elt):
    name ="802.11 Element HT Information"
    fields_desc = [ ByteEnumField("ID", 61,_InfoElt),
                    ByteField("len",None),
                    ByteField("primary_chan",None),
                    PacketListField("subnet1",None,SUBNET1,
                                    length_from=lambda x:1),
                    PacketListField("subnet2",None,SUBNET2,
                                    length_from=lambda x:2),
                    PacketListField("subnet3",None,SUBNET3,
                                    length_from=lambda x:2),
                    XBitField("basic_mcsset",None,16*8)
                ]    

class QoS_Info(Packet):
    name = "Qos Info"
    fields_desc = [ BitEnumField("U-APSD", None, 1,
                                 {0:"Not supported", 1:"Supported"}),
                    BitField("reserved", None, 3),
                    BitField("parameter_set_count", None, 4),
                    ByteField("reserved", None),
                ]
                
class ACI_AIFSN(Packet):
    name = "ACI/AIFSN"
    fields_desc = [ BitField("reserved", None, 1),
                    BitField("ACI", None, 2),
                    BitEnumField("admission_control", None, 1,
                                 {0:"Not mandatory", 1:"Mandatory"}),
                    BitField("AIFSN", None, 4),
                ]
                
class ECW_MinMax(Packet):
    name = "ECW Min/Max"
    fields_desc = [ BitField("ECW_max", None, 4),
                    BitField("ECW_min", None, 4),
                ]
                
class AC_BE(Packet):
    name = "Access Category - Best Effort"
    fields_desc = [ PacketListField("ACI_AIFSN", None, ACI_AIFSN,
                                    length_from=lambda x:1),
                    PacketListField("ECW_minmax", None, ECW_MinMax,
                                    length_from=lambda x:1),
                    StrLenField("TXOP_limit", "", length_from=lambda x:2),
                ]
                
class AC_BG(AC_BE):
    name = "Access Category - Backgroud"

class AC_Video(AC_BE):
    name = "Access Category - Video"
    
class AC_Voice(AC_BE):
    name = "Access Category - Voice"
                
class WMM(Dot11Elt):
    name = "802.11 Element 221 WMM"
    fields_desc = [ ByteEnumField("ID", 221, _InfoElt),
                    ByteField("len", 24),
                    StrLenField("OUI", "\x00P\xf2\x02", length_from=lambda x:4),
                    ByteField("OUI_subtype", None),
                    ByteField("version", None),
                    PacketListField("QoS_info", None, QoS_Info,
                                    length_from=lambda x:2),
                    PacketListField("access_category_best_effort", None, AC_BE,
                                    length_from=lambda x:4),
                    PacketListField("access_category_background", None, AC_BG,
                                    length_from=lambda x:4),
                    PacketListField("access_category_video", None, AC_Video,
                                    length_from=lambda x:4),
                    PacketListField("access_category_voice", None, AC_Voice,
                                    length_from=lambda x:4),
                ]
                
class WPA(Dot11Elt):
    name = "802.11 Element 221 WPA"
    fields_desc = [ ByteEnumField("ID", 221, _InfoElt),
                    ByteField("len", 0),
                    StrLenField("OUI", "\x00\x50\xf2\x01", length_from=lambda x:4),
                    LEShortField("version", None),
                    XIntField("multicast_cipher_suite",""),
                    LEShortField("no_unicast_cipher_suites", 0),
                    PacketListField("unicast_cipher_suites", None, UnicastCipherSuite, 
                                        length_from=lambda x:x.no_unicast_cipher_suites * 4),                    
                    LEShortField("no_auth_key_mgmt_suites", None),
                    PacketListField("auth_key_mgmt_suites", None, AuthKeyMgmtSuite, 
                                        length_from=lambda x:x.no_auth_key_mgmt_suites * 4)                    
                

                ]           
                
                
class WPSElt(Packet):
    name = "802.11 Wi-Fi protected setup"
    fields_desc = [ ShortEnumField("ID", None, _InfoWPS),
                    FieldLenField("len", None,"value","H"),
                    StrLenField("value","",length_from=lambda x:x.len)
                  ]
    def extract_padding(self, pay):
        return "",pay

    registered_options = {}
    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.ID.default] = cls
        
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = 256*ord(_pkt[0]) + ord(_pkt[1])
            return cls.registered_options.get(o, cls)
        return cls
        
class WPS_Version(WPSElt):
    name = "Version"
    fields_desc = [ ShortEnumField("ID", 0x104A, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_Config(WPSElt):
    name = "Wi-Fi Protected Setup"
    fields_desc = [ ShortEnumField("ID", 0x1044, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_RspType(WPSElt):
    name = "Response Type"
    fields_desc = [ ShortEnumField("ID", 0x103B, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_UUID_E(WPSElt):
    name = "UUID_E"
    fields_desc = [ ShortEnumField("ID", 0x1047, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_ManFac(WPSElt):
    name = "Manufacturer"
    fields_desc = [ ShortEnumField("ID", 0x1021, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_ModelName(WPSElt):
    name = "Model Name"
    fields_desc = [ ShortEnumField("ID", 0x1023, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_ModelNum(WPSElt):
    name = "Model Number"
    fields_desc = [ ShortEnumField("ID", 0x1024, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]        

class WPS_SerialNum(WPSElt):
    name = "Serial Number"
    fields_desc = [ ShortEnumField("ID", 0x1042, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]                  
                
class WPS_Category(WPSElt):
    name = "Category"
    fields_desc = [ ShortEnumField("ID", 0x1054, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]

class WPS_DevName(WPSElt):
    name = "Device Name"
    fields_desc = [ ShortEnumField("ID", 0x1011, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_ConfMeths(WPSElt):
    name = "Config Methods"
    fields_desc = [ ShortEnumField("ID", 0x1008, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_RFBands(WPSElt):
    name = "RF Bands"
    fields_desc = [ ShortEnumField("ID", 0x103C, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
class WPS_VenExt(WPSElt):
    name = "Vendor Extension"
    fields_desc = [ ShortEnumField("ID", 0x1049, _InfoWPS),
                    ShortField("len", None),
                    StrLenField("value", "", length_from=lambda x:x.len),
                ]
                
_InfoDevPwd = {0x0000:"Default", 0x0001:"User-specified",
               0x0002:"Machine-specified", 0x0003:"Pekey",
               0x0004:"PushButton", 0x0005:"Registrar-specified"} 
               
class WPS_DevPwdID(WPSElt):
    name = "Device Password ID"
    fields_desc = [ ShortEnumField("ID", 0x1012, _InfoWPS),
                    ShortField("len", None),
                    ShortEnumField("value", 0, _InfoDevPwd),
                ]  
                
class WPS_SltRgtr(WPSElt):
    name = "Selected Registrar"
    fields_desc = [ ShortEnumField("ID", 0x1041, _InfoWPS),
                    ShortField("len", None),
                    ByteField("value", 0),
                ]     

class WPSConfigMethodsField(Packet):
    name ="Selected Registrar Config Methods"
    fields_desc =[
                  BitField('reserved', 0, 3),
                  BitEnumField("physical_sidplay_pin",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("virtual_display_pin",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("physical_push_button",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("virtual_push_button",None,1,
                               {0:"Not supported",1:"Supported"}),             
                  BitEnumField("keypad",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("push_button",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("nfc_interface",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("integrated_nfc",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("ethernet_nfc",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("display",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("label",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("ethernet",None,1,
                               {0:"Not supported",1:"Supported"}),
                  BitEnumField("usba",None,1,
                               {0:"Not supported",1:"Supported"}),
                  ]
                  
class WPS_SltRgtrConfMeths(WPSElt):
    name = "Selected Registrar Config Methods"
    fields_desc = [ ShortEnumField("ID", 0x1053, _InfoWPS),
                    ShortField("len", None),
                    PacketListField("value", None, WPSConfigMethodsField,
                                    length_from=lambda x:x.len),
                ]   
                
class WPS(Dot11Elt):
    name = '802.11 Element 221 WPS'
    fields_desc = [ ByteEnumField("ID", 221, _InfoElt),
                    ByteField("len", None),
                    StrLenField("OUI", "\x00P\xf2\x04", length_from=lambda x:4),
                    PacketListField("options", [], WPSElt,
                                    length_from=lambda x:x.len-4),
                ]

###############################################
# Information Element Field
###############################################    

###############################################
# Management Frame Field
###############################################    
                
class Dot11Info(Dot11Elt):
    name = "802.11 Information Options "        
        
class _CapInfo(Packet):
    name = "802.11 Element Capability Information"
    fields_desc = [ BitEnumField("channel_agility", None,1,
                                 {0:"0 Channel Agility Not Used",
                                  1:"1 Channel Agility Used"}),
                    BitEnumField("PBCC", None,1,
                                 {0:"0 PBCC Not Allowed", 1:"1 PBCC Allowed"}),
                    BitEnumField("short_preamble", None,1,
                                 {0:"0 Not Short Preamble",
                                  1:"1 Short Preamble"}),
                    BitEnumField("privacy", None,1,
                                 {0:"0 Privacy Disabled",
                                  1:"1 Privacy Enabled"}),
                    BitField("CF_poll_req", None,1),
                    BitField("CF_pollable", None,1),
                    BitField("IBSS", None,1),
                    BitField("ESS", None,1),
                    
                    BitEnumField("immediate_blockACK", None,1,
                                 {0:"0 Immediate Block ACK Not Allowed",
                                  1:"1 Immediate Block ACK Allowed"}),
                    BitEnumField("delayed_blockACK", None,1,
                                 {0:"0 Delayed Block ACK Not Allowed",
                                  1:"1 Delayed Block ACK Allowed"}),
                    BitEnumField("DSSS_ODFM", None,1,
                                 {0:"0 DSSS-ODFM is Not Allowed",
                                  1:"1 DSSS-ODFM Allowed"}),
                    BitField("reserved", None,1),
                    BitEnumField("auto_power_save", None,1,
                                 {0:"0 APSD Is Not Supported",
                                  1 :"1 APSD Is Supported"}),
                    BitEnumField("short_slot_time", None,1,
                                 {0:"0 Short Slot Time Not Used",
                                  1:"1 Short Slot Time Used"}),
                    BitEnumField("QoS", None,1,
                                 {0:"0 QoS Not Supported",
                                  1:"1 QoS Supported"}),
                    BitEnumField("spectrum_mgmt", None,1,
                                 {0:"0 Spectrum Mgmt Disabled",
                                  1:"1 Spectrum Mgmt Enabled"}),
                    
                   ]               
    
class Dot11Beacon(Packet):
    name = "802.11 Beacon"
    fields_desc = [ LELongField("timestamp", 0),
                    LEShortField("beacon_interval", 0x0064),
                    _CapInfo,
                    PacketListField("options", [],  Dot11Elt),
                    ]

    
class Dot11ATIM(Packet):
    name = "802.11 ATIM"

class Dot11Disas(Packet):
    name = "802.11 Disassociation"
    fields_desc = [ LEShortEnumField("reason", 1, reason_code),
                   PacketListField("options", [],  Dot11Elt),
                   
                    ]

class Dot11AssoReq(Packet):
    name = "802.11 Association Request"
    fields_desc = [ _CapInfo,
                    LEShortField("listen_interval", 0x00c8),
                    PacketListField("options", [],  Dot11Elt)]


class Dot11AssoResp(Packet):
    name = "802.11 Association Response"
    fields_desc = [ _CapInfo,
                    LEShortField("status", 0),
                    LEShortField("AID", 0),
                    PacketListField("options", [],  Dot11Elt)]

class Dot11ReassoReq(Packet):
    name = "802.11 Reassociation Request"
    fields_desc = [ _CapInfo,
                    LEShortField("listen_interval", 0x00c8),
                    MACField("current_AP", ETHER_ANY),
                    PacketListField("options", [],  Dot11Elt) ]


class Dot11ReassoResp(Dot11AssoResp):
    name = "802.11 Reassociation Response"
    fields_desc = [PacketListField("options", [],  Dot11Elt)
                   ]
class Dot11ProbeReq(Packet):
    name = "802.11 Probe Request"
    fields_desc = [PacketListField("options", [],  Dot11Elt)
                   ]
    
class Dot11ProbeResp(Packet):
    name = "802.11 Probe Response"
    fields_desc = [ LongField("timestamp", 0),
                    ShortField("beacon_interval", 0x0064),
                    _CapInfo,
                    PacketListField("options", [],  Dot11Elt), 
                    ]
    
class Dot11Auth(Packet):
    name = "802.11 Authentication"
    fields_desc = [ LEShortEnumField("algo", 0, ["open", "sharedkey"]),
                    LEShortField("seqnum", 0),
                    LEShortEnumField("status", 0, status_code),
                    PacketListField("options", [],  Dot11Elt) 
                    ]
    def answers(self, other):
        if self.seqnum == other.seqnum+1:
            return 1
        return 0

class Dot11Deauth(Packet):
    name = "802.11 Deauthentication"
    fields_desc = [ LEShortEnumField("reason", 1, reason_code),
                   PacketListField("options", [],  Dot11Elt)
                    ]

class Dot11Action(Packet):
    name = "802.11 Action"
    fields_desc = [ LEShortField("action", 1),
                    PacketListField("options", [],  Dot11Elt)
                ]

###############################################
# Management Frame Field
###############################################                 
                
class Dot11WEP(Packet):
    name = "802.11 WEP packet"
    fields_desc = [ StrFixedLenField("iv", "\0\0\0", 3),
                    ByteField("keyid", 0),
                    StrField("wepdata",None,remain=4),
                    IntField("icv",None) ]

    def post_dissect(self, s):
#        self.icv, = struct.unpack("!I",self.wepdata[-4:])
#        self.wepdata = self.wepdata[:-4]
        self.decrypt()

    def build_payload(self):
        if self.wepdata is None:
            return Packet.build_payload(self)
        return ""

    def post_build(self, p, pay):
        if self.wepdata is None:
            key = conf.wepkey
            if key:
                if self.icv is None:
                    pay += struct.pack("<I",crc32(pay))
                    icv = ""
                else:
                    icv = p[4:8]
                c = ARC4.new(self.iv+key)
                p = p[:4]+c.encrypt(pay)+icv
            else:
                warning("No WEP key set (conf.wepkey).. "
                        "strange results expected..")
        return p
            

    def decrypt(self,key=None):
        if key is None:
            key = conf.wepkey
        if key:
            c = ARC4.new(self.iv+key)
            self.add_payload(LLC(c.decrypt(self.wepdata)))

class IV(Packet):
    name = "IV"
    fields_desc = [ ByteField("rc4key[0]", None),
                    ByteField("rc4key[1]", None),
                    ByteField("rc4key[1]", None),
                ]
                
class Key_Index(Packet):
    name = "Key Index"
    fields_desc = [ BitField("key_id", None, 2),
                    BitField("ext_iv", None, 1),
                    BitField("reserved", None, 4),
                ]
            
class Dot11TKIP(Packet):
    name = "802.11 TKIP packet"
    fields_desc = [ PacketListField("IV", None, IV, length_from=lambda x:3),
                    PacketListField("key_index", None, Key_Index,
                                    length_from=lambda x:1),
                    StrLenField("extended_iv", "", length_from=lambda x:4),
                    StrField("tkip_data", None, remain=12),
                    StrLenField("MIC", "", length_from=lambda x:8),
                    IntField("ICV", None),
                ]

bind_layers( PrismHeader,   Dot11,         )
bind_layers( RadioTap,      Dot11,         )
bind_layers( Dot11,         LLC,           type=2)
bind_layers( Dot11QoS,      LLC,           )
bind_layers( Dot11,         Dot11AssoReq,    subtype=0, type=0)
bind_layers( Dot11,         Dot11AssoResp,   subtype=1, type=0)
bind_layers( Dot11,         Dot11ReassoReq,  subtype=2, type=0)
bind_layers( Dot11,         Dot11ReassoResp, subtype=3, type=0)
bind_layers( Dot11,         Dot11ProbeReq,   subtype=4, type=0)
bind_layers( Dot11,         Dot11ProbeResp,  subtype=5, type=0)
bind_layers( Dot11,         Dot11Beacon,     subtype=8, type=0)
bind_layers( Dot11,         Dot11ATIM,       subtype=9, type=0)
bind_layers( Dot11,         Dot11Disas,      subtype=10, type=0)
bind_layers( Dot11,         Dot11Auth,       subtype=11, type=0)
bind_layers( Dot11,         Dot11Deauth,     subtype=12, type=0)
bind_layers( Dot11,         Dot11Action,     subtype=13, type=0)

#bind_layers( Dot11,         Dot11TKIP,       subtype=0, type=2)
#bind_layers( Dot11,         Dot11WEP,        subtype=8, type=2)

bind_layers( Dot11Beacon,     Dot11Elt,    )
bind_layers( Dot11AssoReq,    Dot11Elt,    )
bind_layers( Dot11AssoResp,   Dot11Elt,    )
bind_layers( Dot11ReassoReq,  Dot11Elt,    )
bind_layers( Dot11ReassoResp, Dot11Elt,    )
bind_layers( Dot11ProbeReq,   Dot11Elt,    )
bind_layers( Dot11ProbeResp,  Dot11Elt,    )
bind_layers( Dot11Auth,       Dot11Elt,    )
#bind_layers( Dot11Elt,        Dot11Elt,    )


conf.l2types.register(105, Dot11)
conf.l2types.register_num2layer(801, Dot11)
conf.l2types.register(119, PrismHeader)
conf.l2types.register_num2layer(802, PrismHeader)
conf.l2types.register(127, RadioTap)
conf.l2types.register_num2layer(803, RadioTap)


class WiFi_am(AnsweringMachine):
    """Before using this, initialize "iffrom" and "ifto" interfaces:
iwconfig iffrom mode monitor
iwpriv orig_ifto hostapd 1
ifconfig ifto up
note: if ifto=wlan0ap then orig_ifto=wlan0
note: ifto and iffrom must be set on the same channel
ex:
ifconfig eth1 up
iwconfig eth1 mode monitor
iwconfig eth1 channel 11
iwpriv wlan0 hostapd 1
ifconfig wlan0ap up
iwconfig wlan0 channel 11
iwconfig wlan0 essid dontexist
iwconfig wlan0 mode managed
"""
    function_name = "airpwn"
    filter = None
    
    def parse_options(self, iffrom, ifto, replace, pattern="",
                      ignorepattern=""):
        self.iffrom = iffrom
        self.ifto = ifto
        ptrn = re.compile(pattern)
        iptrn = re.compile(ignorepattern)
        
    def is_request(self, pkt):
        if not isinstance(pkt,Dot11):
            return 0
        if not pkt.FCfield & 1:
            return 0
        if not pkt.haslayer(TCP):
            return 0
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        pay = str(tcp.payload)
        if not self.ptrn.match(pay):
            return 0
        if self.iptrn.match(pay):
            return 0

    def make_reply(self, p):
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = str(tcp.payload)
        del(p.payload.payload.payload)
        p.FCfield="from_DS"
        p.addr1,p.addr2 = p.addr2,p.addr1
        p /= IP(src=ip.dst,dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq+len(pay),
                 flags="PA")
        q = p.copy()
        p /= self.replace
        q.ID += 1
        q.getlayer(TCP).flags="RA"
        q.getlayer(TCP).seq+=len(replace)
        return [p,q]
    
    def print_reply(self):
        print p.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%")

    def send_reply(self, reply):
        sendp(reply, iface=self.ifto, **self.optsend)

    def sniff(self):
        sniff(iface=self.iffrom, **self.optsniff)



plst=[]
def get_toDS():
    global plst
    while 1:
        p,=sniff(iface="eth1",count=1)
        if not isinstance(p,Dot11):
            continue
        if p.FCfield & 1:
            plst.append(p)
            print "."


#    if not ifto.endswith("ap"):
#        print "iwpriv %s hostapd 1" % ifto
#        os.system("iwpriv %s hostapd 1" % ifto)
#        ifto += "ap"
#        
#    os.system("iwconfig %s mode monitor" % iffrom)
#    

def airpwn(iffrom, ifto, replace, pattern="", ignorepattern=""):
    """Before using this, initialize "iffrom" and "ifto" interfaces:
iwconfig iffrom mode monitor
iwpriv orig_ifto hostapd 1
ifconfig ifto up
note: if ifto=wlan0ap then orig_ifto=wlan0
note: ifto and iffrom must be set on the same channel
ex:
ifconfig eth1 up
iwconfig eth1 mode monitor
iwconfig eth1 channel 11
iwpriv wlan0 hostapd 1
ifconfig wlan0ap up
iwconfig wlan0 channel 11
iwconfig wlan0 essid dontexist
iwconfig wlan0 mode managed
"""
    
    ptrn = re.compile(pattern)
    iptrn = re.compile(ignorepattern)
    def do_airpwn(p, ifto=ifto, replace=replace, ptrn=ptrn, iptrn=iptrn):
        if not isinstance(p,Dot11):
            return
        if not p.FCfield & 1:
            return
        if not p.haslayer(TCP):
            return
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = str(tcp.payload)
#        print "got tcp"
        if not ptrn.match(pay):
            return
#        print "match 1"
        if iptrn.match(pay):
            return
#        print "match 2"
        del(p.payload.payload.payload)
        p.FCfield="from_DS"
        p.addr1,p.addr2 = p.addr2,p.addr1
        q = p.copy()
        p /= IP(src=ip.dst,dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq+len(pay),
                 flags="PA")
        q = p.copy()
        p /= replace
        q.ID += 1
        q.getlayer(TCP).flags="RA"
        q.getlayer(TCP).seq+=len(replace)
        
        sendp([p,q], iface=ifto, verbose=0)
#        print "send",repr(p)        
#        print "send",repr(q)
        print p.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%")

    sniff(iface=iffrom,prn=do_airpwn)

            
        
conf.stats_dot11_protocols += [Dot11WEP, Dot11Beacon, ]


        


class Dot11PacketList(PacketList):
    def __init__(self, res=None, name="Dot11List", stats=None):
        if stats is None:
            stats = conf.stats_dot11_protocols

        PacketList.__init__(self, res, name, stats)
    def toEthernet(self):
        data = map(lambda x:x.getlayer(Dot11),
                   filter(lambda x : x.haslayer(Dot11) and
                          x.type == 2, self.res))
        r2 = []
        for p in data:
            q = p.copy()
            q.unwep()
            r2.append(Ether()/q.payload.payload.payload) #Dot11/LLC/SNAP/IP
        return PacketList(r2,name="Ether from %s"%self.listname)
        
        
