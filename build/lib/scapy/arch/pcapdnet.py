## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import time,struct,sys
if not sys.platform.startswith("win"):
    from fcntl import ioctl
from scapy.data import *
from scapy.config import conf
from scapy.utils import warning
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception
import scapy.arch



    
if conf.use_pcap:    



    try:
        import pcap
    except ImportError,e:
        try:
            import pcapy as pcap
        except ImportError,e2:
            if conf.interactive:
                log_loading.error("Unable to import pcap module: %s/%s" % (e,e2))
                conf.use_pcap = False
            else:
                raise
    if conf.use_pcap:
        
        # From BSD net/bpf.h
        #BIOCIMMEDIATE=0x80044270
        BIOCIMMEDIATE=-2147204496

        if hasattr(pcap,"pcap"): # python-pypcap
            class _PcapWrapper_pypcap:
                def __init__(self, device, snaplen, promisc, to_ms):
                    # Normal pypcap module has no timeout parameter,
                    # only the specially patched "scapy" variant has.                 
                    if "scapy" in pcap.__version__.lower():
                        self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1, timeout_ms=to_ms)
                    else:
                        self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1)                    
                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)
            open_pcap = lambda *args,**kargs: _PcapWrapper_pypcap(*args,**kargs)
        elif hasattr(pcap,"pcapObject"): # python-libpcap
            class _PcapWrapper_libpcap:
                def __init__(self, *args, **kargs):
                    self.pcap = pcap.pcapObject()
                    self.pcap.open_live(*args, **kargs)
                def setfilter(self, filter):
                    self.pcap.setfilter(filter, 0, 0)
                def next(self):
                    c = self.pcap.next()
                    if c is None:
                        return
                    l,pkt,ts = c 
                    return ts,pkt
                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)
            open_pcap = lambda *args,**kargs: _PcapWrapper_libpcap(*args,**kargs)
        elif hasattr(pcap,"open_live"): # python-pcapy
            class _PcapWrapper_pcapy:
                def __init__(self, *args, **kargs):
                    self.pcap = pcap.open_live(*args, **kargs)
                def next(self):
                    try:
                        c = self.pcap.next()
                    except pcap.PcapError:
                        return None
                    else:
                        h,p = c
                        s,us = h.getts()
                        return (s+0.000001*us), p
                def fileno(self):
                    warning("fileno: pcapy API does not permit to get capure file descriptor. Bugs ahead! Press Enter to trigger packet reading")
                    return 0
                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)
            open_pcap = lambda *args,**kargs: _PcapWrapper_pcapy(*args,**kargs)

        
        class PcapTimeoutElapsed(Scapy_Exception):
            pass
    
        class L2pcapListenSocket(SuperSocket):
            desc = "read packets at layer 2 using libpcap"
            def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
                self.type = type
                self.outs = None
                #print 'L2pcapListenSocket'
                if iface is None:                                            
                    iface = conf.iface
                else:
                    iface = convent_to_eth(iface)
                self.iface = iface
                if promisc is None:
                    promisc = conf.sniff_promisc
                self.promisc = promisc
                self.ins = open_pcap(iface, 1600, self.promisc, 100)
                try:
                    ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
                except:
                    pass
                if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
                    if conf.except_filter:
                        if filter:
                            filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                        else:
                            filter = "not (%s)" % conf.except_filter
                    if filter:
                        self.ins.setfilter(filter)
        
            def close(self):
                del(self.ins)
                
            def recv(self, x=MTU):
                ll = self.ins.datalink()
                if ll in conf.l2types:
                    cls = conf.l2types[ll]
                else:
                    cls = conf.default_l2
                    warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
        
                pkt = None
                while pkt is None:
                    pkt = self.ins.next()
                    if pkt is not None:
                        ts,pkt = pkt
                    if scapy.arch.WINDOWS and pkt is None:
                        raise PcapTimeoutElapsed
                
                try:
                    pkt = cls(pkt)
                except KeyboardInterrupt:
                    raise
                except:
                    if conf.debug_dissector:
                        raise
                    pkt = conf.raw_layer(pkt)
                pkt.time = ts
                return pkt
        
            def send(self, x):
                raise Scapy_Exception("Can't send anything with L2pcapListenSocket")
        
    
        conf.L2listen = L2pcapListenSocket

        
    

if conf.use_dnet:
    

        
    try:
        import dnet
    except ImportError,e:
        if conf.interactive:
            log_loading.error("Unable to import dnet module: %s" % e)
            conf.use_dnet = False
            def get_if_raw_hwaddr(iff):
                "dummy"
                return (0,"\0\0\0\0\0\0")
            def get_if_raw_addr(iff):
                "dummy"
                return "\0\0\0\0"
            def get_if_list():
                "dummy"
                return []
            def get_if_name(hwaddr):
                "dummy"
                return ""
        else:
            raise
    else:
        def get_if_raw_hwaddr(iff):
            if iff == scapy.arch.LOOPBACK_NAME:
                return (772, '\x00'*6)
            try:
                l = dnet.intf().get(iff)
                l = l["link_addr"]
            except:
                raise Scapy_Exception("Error in attempting to get hw address for interface [%s]" % iff)
            return l.type,l.data
        def get_if_raw_addr(ifname):
            i = dnet.intf()
            return i.get(ifname)["addr"].data
        def get_if_list():
            return [i.get("name", None) for i in dnet.intf()]
            
        def get_if_name(hwaddr):
            return 

    def get_mac_addr(iface):
        outputs = os.popen("ipconfig/all").read()
        mac_pattern = "[\s\S]*?(\w{2}-\w{2}-\w{2}-\w{2}-\w{2}-\w{2})[\s\S]*" 
        pattern = '[\s\S]*?( %s:)%s' % (iface, mac_pattern)
        match = re.search(pattern, outputs)
        if match:
            return match.group(2).replace("-", ":")
        else:
            raise Scapy_Exception("None mac address of iface %s found" %(iface) )

    def is_ip(ip):
        if ip.__class__ is not str:
            return False                    
        ip_pattern = '^(\d+\.\d+\.\d+.\d+)$'
        r = re.search(ip_pattern, ip)
        return r is not None

                
    def get_eth_name(iface):
        if is_ip(iface):            
            for net,msk,gw,ifc,addr,metric in conf.route.routes:
                if iface == addr or iface == gw:
                    return ifc
            raise Scapy_Exception("None eth of %s found " %(iface) )
            
        macaddr = get_mac_addr(iface).lower()
        
        for (name,intf) in scapy.arch.ifaces.items():
            if str(intf.mac).lower() == macaddr:
                return name
        # for intf in dnet.intf():
            # if intf.get("link_addr") == dnet.addr(macaddr):
                # return intf["name"]
        else:
            raise Scapy_Exception("None eth of %s found " %(iface) )
            
    def convent_to_eth(iface):
        
        if isinstance(iface,unicode):
            iface = str(iface)
        if iface == scapy.arch.LOOPBACK_NAME or iface in get_if_list():
            return iface
        return get_eth_name(iface) 
    
if conf.use_pcap and conf.use_dnet:
    class L3dnetSocket(SuperSocket):
        desc = "read/write packets at layer 3 using libdnet and libpcap"
        def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
            self.iflist = {}
            self.intf = dnet.intf()
           
            if iface is None:
                iface = conf.iface
                self.__use_iface = False
            else:
                iface = convent_to_eth(iface)
                self.__use_iface = True
                                
                
            
            
            self.iface = iface
            self.ins = open_pcap(iface, 1600, 0, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            if nofilter:
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    filter = "ether proto %i" % type
                else:
                    filter = None
            else:
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    if filter:
                        filter = "(ether proto %i) and (%s)" % (type,filter)
                    else:
                        filter = "ether proto %i" % type
            if filter:
                self.ins.setfilter(filter)
        def send(self, x):
            iff,a,gw  = x.route(iface_hint=self.iface)
            
            
            ismulticast = False
            iff = self.iface
            IP = scapy.layers.inet.IP
            if self.__use_iface and iff != self.iface :
                if x.haslayer(IP) and x[IP].src == a :
                    x[IP].src = scapy.arch.ifaces.get( self.iface ).ip
                    
            elif self.__use_iface :
                if x.haslayer(IP):
                    ddd = scapy.utils.atol(x[IP].dst)
                    if 0xe0000000L <= ddd and ddd  <= 0xefffffffL :
                        #multicast
                        x[IP].src = scapy.arch.ifaces.get(iff).ip
                        ismulticast = True
                
                
            if iff is None:
                iff = conf.iface
            
            ifs,cls = self.iflist.get(iff,(None,None))
            if ifs is None:
                iftype = self.intf.get(iff)["type"]
                if iftype == dnet.INTF_TYPE_ETH:
                    try:
                        cls = conf.l2types[1]
                    except KeyError:
                        warning("Unable to find Ethernet class. Using nothing")
                    ifs = dnet.eth(iff)
                else:
                    ifs = dnet.ip()
                self.iflist[iff] = ifs,cls
            if cls is None:
                sx = str(x)
            else:
                xx = cls()/x
                if ismulticast and xx.haslayer(scapy.layers.l2.Ether):
                    xx[scapy.layers.l2.Ether].src = scapy.arch.get_if_hwaddr(self.iface)
                sx = str(xx)
            x.sent_time = time.time()
            ifs.send(sx)
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
    
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
    
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt.payload
    
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv()
            self.ins.setnonblock(0)
            return p
    
        def close(self):
            if hasattr(self, "ins"):
                del(self.ins)
            if hasattr(self, "outs"):
                del(self.outs)
    
    class L2dnetSocket(SuperSocket):
        desc = "read/write packets at layer 2 using libdnet and libpcap"
        def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
            #print 'L2dnetSocket'
            if iface is None:
                iface = conf.iface
                self.__use_iface = False
            else:
                iface = convent_to_eth(iface)
                self.__use_iface = True

                
            self.iface = iface
            self.ins = open_pcap(iface, 1600, 0, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            if nofilter:
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    filter = "ether proto %i" % type
                else:
                    filter = None
            else:
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    if filter:
                        filter = "(ether proto %i) and (%s)" % (type,filter)
                    else:
                        filter = "ether proto %i" % type
            if filter:
                self.ins.setfilter(filter)
            self.outs = dnet.eth(iface)
            
            
        def send(self, x):
        
            pkt_src_mac_field,pkt_src_mac_val = x.getfield_and_val('src')
            if self.__use_iface and pkt_src_mac_val is None:
                iff = self.iface
                if iff:
                    try:
                        src_mac = scapy.arch.get_if_hwaddr(iff)
                    except:
                        pass
                if src_mac is None:
                    src_mac = "00:00:00:00:00:00"
                x.src = scapy.fields.MACField.i2h(pkt_src_mac_field, x, src_mac)
            
            if x.haslayer('IP') :
                pkt_src_ip_field,pkt_src_ip_val = x['IP'].getfield_and_val('src')
                if isinstance(pkt_src_ip_field,scapy.fields.Emph):
                    pkt_src_ip_field = pkt_src_ip_field.fld
                if self.__use_iface and pkt_src_ip_val is None:
                    iff = self.iface
                    if iff:
                        try:
                            src_ip = scapy.arch.get_if_addr(iff)
                        except:
                            pass
                    x['IP'].src = scapy.fields.SourceIPField.i2h(pkt_src_ip_field, x, src_ip)
                
            SuperSocket.send(self, x)
            
            
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
    
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
            
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt
    
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv(MTU)
            self.ins.setnonblock(0)
            return p
    
        def close(self):
            if hasattr(self, "ins"):
                del(self.ins)
            if hasattr(self, "outs"):
                del(self.outs)

    conf.L3socket=L3dnetSocket
    conf.L2socket=L2dnetSocket

        
    
