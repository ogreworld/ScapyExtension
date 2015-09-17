#!/usr/bin/env python PPTP

import struct
from scapy.packet import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.fields import *

_PPTP_controlmsg_type={1:'Start-Control-Connection-Request',
                       2:'Start-Control-Connection-Reply',
                       3:'Stop-Control-Connection-Request',
                       4:'Stop-Control-Connection-Reply',
                       5:'Echo-Request',
                       6:'Echo-Reply',
                       7:'Outgoing-Call-Request',
                       8:'Outgoing-Call-Reply',
                       9:'Incoming-Call-Request',
                       10:'Incoming-Call-Reply',
                       11:'Incoming-Call-Connected',
                       12:'Call-Clear-Request',
                       13:'Call-Disconnect-Notify',
                       14:'WAN-Error-Notify',
                       15:'Set-Link-Info'}

_PPTP_msg_type={1:'Control',
		2:'Management'
}


_PPTP_framing_cap_type={1:'Asynchronous Framing-Supported',2:'Synchronous Framing Supported'}
_PPTP_bearer_cap_type={1:'Analog Access Supported',2:'Digital Access Supported'}
  
_PPTP_result_code={
                   1:'Successful channel establishment',
                   2:'General error --Error Code indicates the problem',
                   3:'Command channel already exists',
                   4:'Requester is not authorized to establish a command channel',
                   5:'The protocol version of the requester is not supported'
                   }
_PPTP_general_error_code={
                          0:'None',
                          1:'Not-Connected',
                          2:'Bad-Format',
                          3:'Bad-Value',
                          4:'No-Resource',
                          5:'Bad-Call ID',
                          6:'PAC-Error'
                          }
class PPTP(Packet):
    name="PPTP Packet"
    fields_desc=[ #FieldLenField("len", None, length_of="plist", fmt="H", adjust=lambda p,x:x+2),
                 ShortField("len",None),
                 ShortEnumField("msg_type",1,_PPTP_msg_type),
                 XIntField("cookie",0x1A2B3C4D),
                 ShortEnumField("ctrlmsg_type",1,_PPTP_controlmsg_type),
                 ShortField("reserved0",0),
                #ConditionalField(PacketListField('plist',None,PPTP_START_REQ,length_from=lambda p:p.len),lambda p:p.ctrlmsg_type==1)
                ]
    def post_build(self, p, pay):
        if self.len is None:
            l = len(pay)+len(p)
            p = struct.pack("!H",l)+ p[2:]
        return p+pay
        
class PPTP_START_REQ(Packet):
	name="PPTP_START_REQ"
	fields_desc=[
                 XShortField("version",0x0100),
                 ShortField("reserved1",0),
                 IntEnumField("framing_cap",1,_PPTP_framing_cap_type),
                 IntEnumField("bearer_cap",1,_PPTP_bearer_cap_type),
                 ShortField("max_channel",0),
                 ShortField("fw_revision",1),
                 StrFixedLenField("hostname","",64),
                 StrFixedLenField("vender","",64)
                 ]


class PPTP_START_REP(Packet):
    name="PPTP_START_REP"
    fields_desc=[
                 XShortField("version",0x0100),
                 ByteEnumField("result_code",0,_PPTP_result_code),
                 ByteEnumField("error_code",0,_PPTP_general_error_code),
                 IntEnumField("framing_cap",1,_PPTP_framing_cap_type),
                 IntEnumField("bearer_cap",1,_PPTP_bearer_cap_type),
                 ShortField("max_channel",0),
                 ShortField("fw_revision",1),
                 StrFixedLenField("hostname","",64),
                 StrFixedLenField("vender","",64)
                 ]


class PPTP_STOP_REQ(Packet):
    name="PPTP_STOP_REQ"
    fields_desc=[
                 ByteEnumField("reason",None,{1:'none',2:'Stop-Protocol',3:'Stop_Local_Shutdown'}),
                 ByteField("reserved1",0),
                 ShortField("reserved2",0)
                 ]

class PPTP_STOP_REP(Packet):
    name="PPTP_STOP_REP"
    fields_desc=[
                 ByteEnumField("result_code",None,{1:'OK',2:'Gernaral Error'}),
                 ByteEnumField("error_code",0,_PPTP_general_error_code),
                 ShortField("reserved1",0)
                 ]

class PPTP_ECHO_REQ(Packet):
    name="PPTP_ECHO_REQ"
    fields_desc=[XIntField("id",0)]

class PPTP_ECHO_REP(Packet):
    name="PPTP_ECHO_REP"
    fields_desc=[
                 XIntField("id",0),
                 ByteEnumField("result_code",0,{1:'OK',2:'General Error'}),
                 ByteEnumField("error_code",0,_PPTP_general_error_code),
                 ShortField("reserved1",0)
                 ]

class PPTP_OUTCALL_REQ(Packet):
    name="PPTP_OUTCALL_REQ"
    fields_desc=[
                 ShortField("call_id",0),
                 ShortField("call_sn",0),
                 IntField("min_bps",0),
                 IntField("max_bps",0),
                 IntEnumField("bearer_type",3,{1:"Call to be placed on an analog channel",
                                               2:"Call to be placed on an digital channel",
                                               3:"Call to be placed on any type of channel"}),
                 IntEnumField("framing_type",3,{1:"Call to use asynchronous framing",
                                                2:"Call to use Synchronous framing",
                                                3:"Call can use either type of framing"}),
                 ShortField("recv_winsize",0),
                 ShortField("processing_delay",0),
                 ShortField("phone_num_len",0),
                 ShortField("reserved1",0),
                 StrFixedLenField("phone_num","",64),
                 StrFixedLenField("subaddress","",64)
                ]	

class PPTP_OUTCALL_REP(Packet):
    name="PPTP_OUTCALL_REP"
    fields_desc=[
                 ShortField("call_id",0),
                 ShortField("pcall_id",0),
                 ByteEnumField("result_code",0,{1:"Connected",
                                                2:"General Error",
                                                3:"No Carrier",
                                                4:"Busy",
                                                5:"No Dial Tone",
                                                6:"Time-out",
                                                7:"Do Not Accept"}),
                 ByteField("error_code",0),
                 ShortField("cause_code",0),
                 IntField("connect_speed",0),
                 ShortField("recv_winsize",0),
                 ShortField("processing_delay",0),
                 IntField("phy_channel_id",0)
                ]				

class PPTP_INCALL_REQ(Packet):
    name="PPTP_INCALL_REQ"
    fields_desc=[
                 ShortField("call_id",0),
                 ShortField("call_sn",0),
                 IntEnumField("bearer_type",1,{1:"Call is on an analog channel",
                                               2:"Call is on a digital channel",}),
                 IntField("phy_channel_id",0),
                 ShortField("dialed_num_len",0),
                 ShortField("dialing_num_len",0),
                 StrFixedLenField("dialed_num","",64),
                 StrFixedLenField("dialing_num","",64),
                 StrFixedLenField("subaddress","",64)
                ]

class PPTP_INCALL_REP(Packet):
    name="PPTP_INCALL_REP"
    fields_desc=[
                 ShortField("call_id",0),
                 ShortField("pcall_id",0),
                 ByteEnumField("result_code",0,{1:"Connect",
                                                2:"General Error",
                                                3:"Do Not Accept"}),
                 ByteField("error_code",0),
                 ShortField("recv_winsize",0),
                 ShortField("transmit_delay",0),
                 ShortField("reserved1",0)
                ]				
                
class PPTP_INCALL_CONNECTED(Packet):
    name="PPTP_INCALL_CONNECTED"
    fields_desc=[
                 ShortField("pcall_id",0),
                 ShortField("reserved1",0),
                 IntField("connect_spd",0),
                 ShortField("recv_winsize",0),
                 ShortField("transmit_delay",0),
                 IntEnumField("framing_type",0,{1:"Call uses asynchronous framing",
                                                2:"Call uses synchronous framing",}),
                ]
                 
class PPTP_CALLCLR_REQ(Packet):
    name="PPTP_CALLCLR_REQ"
    fields_desc=[
                 ShortField("call_id",0),
                 ShortField("reserved1",0)
                ]
                   
class PPTP_CALLDIS_NTFY(Packet):
    name="PPTP_CALLDIS_NTFY"
    fields_desc=[
                 ShortField("call_id",0),
                 ByteEnumField("result_code",0,{1:"Lost Carrier",
                                                2:"General Error",
                                                3:"Admin Shutdown",
                                                4:"Request"}),
                 ByteField("error_code",0),
                 ShortField("cause_code",0),
                 ShortField("reserved1",0),
                 StrFixedLenField("call_statis","",128)
                 
                ]
                   
class PPTP_WANERR_NTFY(Packet):
    name="PPTP_WANERR_NTFY"
    fields_desc=[
                 ShortField("pcall_id",0),
                 ShortField("reserved1",0),
                 IntField("crc_errors",0),
                 IntField("framing_errors",0),
                 IntField("hardware_overruns",0),
                 IntField("buffer_overruns",0),
                 IntField("timeout_errors",0),
                 IntField("alignment_errors",0),
                ]
                   
class PPTP_SLI(Packet):
    name="PPTP Set-Link-Info"
    fields_desc=[
                 ShortField("pcall_id",0),
                 ShortField("reserved1",0),
                 XIntField("send_accm",0),
                 XIntField("recv_accm",0)
                 ]

bind_layers( PPTP,    PPTP_START_REQ,    ctrlmsg_type=1)
bind_layers( PPTP,    PPTP_START_REP,    ctrlmsg_type=2)
bind_layers( PPTP,    PPTP_STOP_REQ,    ctrlmsg_type=3)
bind_layers( PPTP,    PPTP_STOP_REP,    ctrlmsg_type=4)
bind_layers( PPTP,    PPTP_ECHO_REQ,    ctrlmsg_type=5)
bind_layers( PPTP,    PPTP_ECHO_REP,    ctrlmsg_type=6)
bind_layers( PPTP,    PPTP_OUTCALL_REQ,    ctrlmsg_type=7)
bind_layers( PPTP,    PPTP_OUTCALL_REP,    ctrlmsg_type=8)
bind_layers( PPTP,    PPTP_INCALL_REQ,    ctrlmsg_type=9)
bind_layers( PPTP,    PPTP_INCALL_REP,    ctrlmsg_type=10)
bind_layers( PPTP,    PPTP_INCALL_CONNECTED,    ctrlmsg_type=11)
bind_layers( PPTP,    PPTP_CALLCLR_REQ,    ctrlmsg_type=12)
bind_layers( PPTP,    PPTP_CALLDIS_NTFY,    ctrlmsg_type=13)
bind_layers( PPTP,    PPTP_WANERR_NTFY,    ctrlmsg_type=14)
bind_layers( PPTP,    PPTP_SLI,      ctrlmsg_type=15)
					
bind_layers( TCP,           PPTP,          sport=1723)
bind_layers( TCP,           PPTP,          dport=1723)	
                 