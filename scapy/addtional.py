from scapy.all import *


import time
import threading
 
class MtSniffer(threading.Thread):
    def __init__(self, *args, **kargv):
        threading.Thread.__init__(self)
        self.args = args
        self.kargv = kargv        
        
    def run(self):
        try:
            sniff_ret = sniff( *self.args, **self.kargv)            
        except Exception, ex:
            conf.tsniff_result = 'Sniff error:%s' % ex
        else:
            conf.tsniff_result = sniff_ret
    
@conf.commands.register
def tsniff(*args, **kargs):
    '''start sniffing in a new thread.'''
    
    conf.sniff_thd = thd = MtSniffer(*args, **kargs)    
    conf.tsniff_result = False
    thd.setDaemon(True)
    thd.start()
    
    # wait for starting sniffing, timeout is 15
    max_retry = retry = 15
    while retry:
        time.sleep(1)
        if is_sniffing() or not thd.isAlive():
            return
        else:
            retry -= 1
        
    raise RuntimeError('Start sniffing failed in %s seconds.' % max_retry)
    
    
@conf.commands.register
def tsend(*args, **kargs):
    ''' threaded send '''    
    conf.stop_send = False
    if hasattr(conf,'send_thd') and conf.send_thd.isAlive():
        msg = "Only one send thread is allowed, contact chenzongze@tp-link.net if you really need more"
        raise RuntimeError(msg)
    conf.send_thd = thd = threading.Thread(target=send, args=args, kwargs=kargs)    
    thd.setDaemon(True)
    thd.start()
    return True    
    
@conf.commands.register
def tsendp(*args, **kargs):
    ''' threaded sendp '''       
    conf.stop_send = False
    if hasattr(conf,'send_thd') and conf.send_thd.isAlive():
        msg = "Only one send thread is allowed, contact chenzongze@tp-link.net if you really need more"
        raise RuntimeError(msg)    
    conf.send_thd = thd = threading.Thread(target=sendp, args=args, kwargs=kargs)    
    thd.setDaemon(True)
    thd.start()
    return True   
    
@conf.commands.register
def stop_send():
    conf.stop_send = True
    if not hasattr(conf, 'send_thd'):
        raise RuntimeError("You must call tsend or tsendp before call this method")
    max_retry = retry = 15
    while retry:    
        retry -= 1
        if conf.send_thd.isAlive(): 
            time.sleep(1)
        else:
            conf.stop_send = False
            return True
            
    conf.stop_send = False
    raise RuntimeError("Fail to stop send in %d seconds" % max_retry)
            
            
    
@conf.commands.register
def get_tsniff_result():    
    return conf.tsniff_result
    
@conf.commands.register
def join_tsniff(timeout=None):
    '''Join threaded sniff.'''
    
    # judge type of timeout
    if timeout is not None and not isinstance(timeout, int):
        raise ValueError('timeout should be integer or None.')
    
    # wait for finishing sniff
    if timeout is None:
        while isinstance(get_tsniff_result(), bool):
            time.sleep(1)
    else:
        while isinstance(get_tsniff_result(), bool) and timeout:
            time.sleep(1)
            timeout -= 1
    
    # judge if sniff is finished. If not, stop sniffing.
    if isinstance(get_tsniff_result(), bool):
        stop_sniff()
        
    # get sniff result
    result = get_tsniff_result()
    if isinstance(result, bool):
        raise RuntimeError('Terminate sniffing because of timeout.')
    elif isinstance(result, str):
        raise RuntimeError('Sniff fail: %s' % result)
    else:
        return result
        
@conf.commands.register
def eval_lfilter(lfilter_str):
    return eval(lfilter_str)