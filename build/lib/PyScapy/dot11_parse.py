#!/usr/bin/env python
# -*- coding: UTF-8 -*

################################################################################
# Copyright (C), 2011-2012, TP-LINK Technologies Co., Ltd.
#
# Filename:     dot11_parse.py
# Version:      1.0.2
# Description:  parse the dot11 packet
# Author:       libo
# History:
#       1.2012-01-31, libo, First created.
#       2.2012-05-11, libo, add some function
#       3.2012-05-28, libo, use mcs.py instead of mcs.xls
#       4.2012-07-11, libo, add get_src_addr, get_dst_addr, get_bssid,
#                               get_recv_addr, get_send_addr
#       5.2012-10-25, libo, modify get_cur_rate for 5g
################################################################################

''' parse for Dot11'''

import re
import os
from data.mcs import MCS_LIST

from scapy.all import *

import logging
logging.basicConfig(level=logging.DEBUG)

__version__ = '1.0.5alpha'
__author__  = 'libo'


LAYERS     = {'assoresp':'Dot11AssoResp', 'reassoreq':'Dot11ReassoReq', 
              'reassoresp':'Dot11ReassoResp', 'probereq':'Dot11ProbeReq',
              'proberesp':'Dot11ProbeResp', 'beacon':'Dot11Beacon', 
              'atim':'Dot11ATIM', 'disas':'Dot11Disas', 'auth':'Dot11Auth', 
              'deauth':'Dot11Deauth', 'action':'Dot11Action'
            }
        
        
logger = logging.getLogger(__name__)
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                     'data/'))

BAND_2G4 = '2g4'
BAND_5G  = '5g'

def __get_property(pkt, layer, prop):
    ''' get the property of the layer'''
    try:
        return eval("pkt[%s].%s"%(layer, prop))
    except Exception, ex:
        logger.warn('get property %s in layer %s failed' %(prop, layer))
        raise ex

def creat_packet(pkt_type):
    ''' creat a packet with type pkt_type
        
        Arguments:
            pkt_type(str): string of packet type or pcap filename, 
                           eg.'beacon', 'beacon_11n.pcap'
        Returns:
            class 'scapy.layers.dot11.Dot11' or raise Error
    '''
    if LAYERS.has_key(pkt_type):
        return Dot11()/eval(''.join([LAYERS[pkt_type], '()']))
    else:
        raise ValueError('packet type "%s" is not correct' %(pkt_type, ))
        
def get_pkt_model(pkt_model=None):
    ''' get the packet model
    
        Arguments:
            pkt_model(str): the packet model file without suffix
        Returns:
            pkt_model=None: the packet model list
            else          : the packet model object or raise Error
    '''
    pkt_list = os.listdir('%s/packet/'%DATA_DIR)
    tmp_str  = [x.rfind('.') for x in pkt_list]
    pkt_list = [pkt_list[x][:tmp_str[x]] for x in range(len(pkt_list))]
    if pkt_model is None:
        return pkt_list
    elif pkt_model in pkt_list:
        return rdpcap('%s/packet/%s.pcap' %(DATA_DIR, pkt_model))[0]
    else:
        raise ValueError('the packet model "%s" is not exist'%(pkt_model, ))
    
def show_model():
    ''' show the packet model
    '''
    return str(get_model())

def get_ssid(pkt):
    ''' get the ssid of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means ssid or raise Error
    '''
    return __get_property(pkt, 'Elt_SSID', 'SSID')
    
def get_time_stamp(pkt):
    ''' get the time stamp of the packet
    
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means time stamp or raise Error
    '''
    return __get_property(pkt, 'RadioTap', 'timestamp')

def get_cur_rate(pkt):
    ''' get the current rate of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(float):
            return a float number which means current rate or raise Error
    '''
    
    rate_mark = __get_property(pkt, 'RaTFlags', 'rate')
    if rate_mark == 0:
        bandwidth = get_bandwidth(pkt)
        short_gi  = get_short_gi_status(pkt)
        index     = __get_property(pkt, 'MCS', 'MCS_index')
        tmp_num   = 2*(bandwidth/20-1) + short_gi
        return MCS_LIST[index][tmp_num]  
    else:
        return __get_property(pkt, 'RadioTap', 'rate')/2.0

def get_cur_chan(pkt):
    ''' get the current channel of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means current channel or raise Error
    '''
    if pkt.haslayer(Elt_DSset):
        return __get_property(pkt, 'Elt_DSset', 'cur_channel')
    else:
        freq = get_cur_freq(pkt)
        if freq > 5000:
            return (freq-5000)/5
        elif freq > 4000:
            return (freq-4000)/5
        else:
            return (freq-2407)/5
        

def get_cur_freq(pkt):
    ''' get the current channel frequency of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means current channel frequency or 
            raise Error
    '''
    return __get_property(pkt, 'RadioTap', 'channel_frequency')

def get_singnal(pkt):
    ''' get the singnal of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means singnal or raise Error
    '''
    return __get_property(pkt, 'RadioTap', 'singnal')-256

def get_chan_type(pkt):
    ''' get the channel type of the packet(2.4G/5G)
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(float):
            return 2.4 if it's 2.4g, 5.0 if it's 5g or raise Error
    '''
    return 2.4*(__get_property(pkt, 'ChanType', 'is2G')) +\
           5*(__get_property(pkt, 'ChanType', 'is5G'))
               
def get_primary_chan(pkt):
    ''' get the primary channel of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means primary channel or raise Error
    '''
    return __get_property(pkt, 'Elt_HTInfo', 'primary_chan')
    
def get_sec_chan_offset(pkt):
    ''' get the primary channel of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            0: no present
            1: above
            2: reserved
            3: below
            or raise Error
    '''
    return __get_property(pkt, 'SUBNET1', 'sec_chan_offset')
    
def get_beacon_interval(pkt):
    ''' get the beacon interval of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means beacon interval
    '''
    return __get_property(pkt, 'Dot11Beacon', 'beacon_interval')
    
def get_dtim_count(pkt):
    ''' get the DTIM count of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means DTIM count
    '''
    return __get_property(pkt, 'Elt_TIM', 'DTIM_count')
    
def get_dtim_period(pkt):
    ''' get the DTIM period of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means DTIM period
    '''
    return __get_property(pkt, 'Elt_TIM', 'DTIM_period')
           
def get_addr1(pkt):
    ''' get the address1 of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means address1 or raise Error
            eg.'ff:ff:ff:ff:ff:ff'
    '''
    return __get_property(pkt, 'Dot11', 'addr1')

def get_addr2(pkt):
    ''' get the address2 of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means address2 or raise Error
            eg.'ff:ff:ff:ff:ff:ff'
    '''
    return __get_property(pkt, 'Dot11', 'addr2')
    
def get_addr3(pkt):
    ''' get the address3 of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means address3 or raise Error
            eg.'ff:ff:ff:ff:ff:ff'
    '''
    return __get_property(pkt, 'Dot11', 'addr3')
    
def get_addr4(pkt):
    ''' get the address4 of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means address4 or raise Error
            eg.'ff:ff:ff:ff:ff:ff'
    '''
    return __get_property(pkt, 'Dot11', 'addr4')


def get_country(pkt):
    ''' get the country code of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means country code or raise Error
    '''
    return __get_property(pkt, 'Elt_Country', 'country_code')

def get_bandwidth(pkt):
    ''' get the sp channel width of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(int):
            return a int number which means bandwidth or raise Error
    '''
    if pkt.haslayer(HTCAP_INFO):
        return 20*(__get_property(pkt, 'HTCAP_INFO', 'sp_channel_width')+1)
    else:
        return 20*(__get_property(pkt, 'MCS_Flags', 'bandwidth')+1)
        
def get_short_gi_status(pkt):
    ''' get the short GI status of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(bool):
            return a bool value which means short GI status or raise Error
    '''
    return __get_property(pkt, 'MCS_Flags', 'guard_interval')
    
def get_short_gi_supported_20(pkt):
    ''' get the 20M short gi supported in beacon
    
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(bool):
            return a bool value which means 20M short GI supported or raise Error
    '''
    return __get_property(pkt, 'HTCAP_INFO', 'Short_GI_20')
    
def get_short_gi_supported_40(pkt):
    ''' get the 40M short gi supported in beacon
    
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(bool):
            return a bool value which means 40M short GI supported or raise Error
    '''
    return __get_property(pkt, 'HTCAP_INFO', 'Short_GI_40')
    
def get_wireless_mode(pkt):
    ''' get the wireless mode of the packet(a,b,g,n)
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means wireless mode or raise Error
    '''
    if pkt.haslayer(HTCAP_INFO):
        return 'n'
    elif pkt.haslayer(Elt_Rates):
        rates = __get_property(pkt, 'Elt_Rates', 'rates')
        if '\x8b' in rates:
            if '\x24' in rates:
                return 'g'
            else:
                return 'b'
        else:
            return 'a'
    else:
        if __get_property(pkt, 'ChanType', 'dynamic_CCK_OFDM'):
            return 'n'
        elif __get_property(pkt, 'ChanType', 'OFDM'):
            return 'g'
        elif __get_property(pkt, 'ChanType', 'CCK'):
            return 'b'
        
def get_wps_config(pkt):
    ''' get the wifi protected setup config of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(bool):
            return an bool value which means WPS config or raise Error
            False means 'UnConfiged', True means 'Configed'
    '''
    return bool(ord(__get_property(pkt, 'WPS_Config', 'value'))-1)
        
def get_model_name(pkt):
    ''' get the model name of the packet source
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means model name or raise Error
    '''
    return __get_property(pkt, 'WPS_ModelName', 'value')

def get_manufacturer(pkt):
    ''' get the manufacturer of the packet source
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means manufacturer or raise Error
    '''
    return __get_property(pkt, 'WPS_ManFac', 'value')
    
def get_device_name(pkt):
    ''' get the device name of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means device name or raise Error
    '''
    return __get_property(pkt, 'WPS_DevName', 'value')
    
def get_serial_num(pkt):
    ''' get the serial number of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means serial number or raise Error
    '''
    return __get_property(pkt, 'WPS_SerialNum', 'value')
    
def get_config_methods(pkt):
    ''' get the config methods of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means config methods or raise Error
    '''
    return __get_property(pkt, 'WPS_ConfMeths', 'value')
    
def get_packet_type(pkt):
    ''' get the type of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means packet type or None, eg.'beacon'
    '''
    if not pkt.haslayer('Dot11'):
        return None
    pkt_type = str(pkt[Dot11].payload.__class__)
    pkt_type = re.findall("dot11\.(.*?)'>", pkt_type)
    if pkt_type:
        return pkt_type[0]
    
def set_ssid(pkt, ssid):
    ''' set the ssid of the packet, ssid should be a string
        
        Arguments:
            pkt      :  class 'scapy.layers.dot11.Dot11'
            ssid(str): a string of ssid, eg.'TP-LINK'
        Returns:
            return a packet with SSID=ssid or raise ValueError
    '''
    if not isinstance(ssid, str):
        raise ValueError("the type of ssid is wrong")
    pkt[Elt_SSID].SSID = ssid
    if get_ssid(pkt) == ssid:
        logger.debug("successfully set ssid to %s" %(ssid, ))
        return pkt
    else:
        raise Exception("failed to set ssid to %s" %(ssid, ))
        
def set_addr1(pkt, mac_addr):
    ''' set the address1 of the packet
        
        Arguments:
            pkt           : class 'scapy.layers.dot11.Dot11'
            mac_addr(str) : a string of mac address, eg. 'ff:ff:ff:ff:ff:ff'
        Returns:
            return a packet with addr1=mac_addr or raise ValueError
    '''
    if not isinstance(mac_addr, str) and \
       re.match("^\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}$", mac_addr):
        raise ValueError("the type of mac_addr is wrong")
    pkt[Dot11].addr1 = mac_addr
    if get_addr1(pkt) == mac_addr:
        logger.debug("successfully set addr1 to %s" %(mac_addr, ))
        return pkt
    else:
        raise Exception("failed to set addr1 to %s" %(mac_addr, ))
        
def set_addr2(pkt, mac_addr):
    ''' set the address2 of the packet
        
        Arguments:
            pkt           : class 'scapy.layers.dot11.Dot11'
            mac_addr(str) : a string of mac address, eg.'ff:ff:ff:ff:ff:ff'
        Returns:
            return a packet with addr2=mac_addr or raise ValueError
    '''
    if not isinstance(mac_addr, str) and \
       re.match("^\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}$", mac_addr):
        raise ValueError("the type of mac_addr is wrong")
    pkt[Dot11].addr2 = mac_addr
    if get_addr2(pkt) == mac_addr:
        logger.debug("successfully set addr2 to %s" %(mac_addr, ))
        return pkt
    else:
        raise Exception("failed to set addr2 to %s" %(mac_addr, ))
        
def set_addr3(pkt, mac_addr):
    ''' set the address3 of the packet
        
        Arguments:
            pkt           : class 'scapy.layers.dot11.Dot11'
            mac_addr(str) : a string of mac address, eg.'ff:ff:ff:ff:ff:ff'
        Returns:
            return a packet with addr3=mac_addr or raise ValueError
    '''
    if not isinstance(mac_addr, str) and \
       re.match("^\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}$", mac_addr):
        raise ValueError("the type of mac_addr is wrong")
    pkt[Dot11].addr3 = mac_addr
    if get_addr3(pkt) == mac_addr:
        logger.debug("successfully set addr3 to %s" %(mac_addr, ))
        return pkt
    else:
        raise Exception("failed to set addr3 to %s" %(mac_addr, ))

def set_addr4(pkt, mac_addr):
    ''' set the address4 of the packet
        
        Arguments:
            pkt           : class 'scapy.layers.dot11.Dot11'
            mac_addr(str) : a string of mac address, eg.'ff:ff:ff:ff:ff:ff'
        Returns:
            return a packet with addr4=mac_addr or raise ValueError
    '''
    if not isinstance(mac_addr, str) and \
       re.match("^\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}$", mac_addr):
        raise ValueError("the type of mac_addr is wrong")
    pkt[Dot11].addr4 = mac_addr
    if get_addr4(pkt) == mac_addr:
        logger.debug("successfully set addr4 to %s" %(mac_addr, ))
        return pkt
    else:
        raise Exception("failed to set addr4 to %s" %(mac_addr, ))        
        
def is_to_ds(pkt):
    ''' get the value of to-DS parameter
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(bool):
            return a bool value which means is to ds or not
    '''
    to_DS = __get_property(pkt, 'Dot11', 'FCfield')
    return bool(to_DS&1)
    
def is_from_ds(pkt):
    ''' get the value of from-DS parameter
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(bool):
            return a bool value which means is from ds or not
    '''
    from_DS = __get_property(pkt, 'Dot11', 'FCfield')
    return bool(from_DS&2)
    
def get_src_addr(pkt):
    ''' get the source address of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means source address
    '''
    
    if not is_from_ds(pkt):
        return get_addr2(pkt)
    elif not is_to_ds(pkt):
        return get_addr3(pkt)
    else:
        return get_addr4(pkt)
        
    
def get_dst_addr(pkt):
    ''' get the destination address of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means destination address
    '''
    
    if not is_to_ds(pkt):
        return get_addr1(pkt)
    else:
        return get_addr3(pkt)
    
def get_bssid(pkt):
    ''' get the bssid of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means bssid
    '''
    
    if is_to_ds(pkt) and not is_from_ds(pkt):
        return get_addr1(pkt)
    elif is_from_ds(pkt) and not is_to_ds(pkt):
        return get_addr2(pkt)
    elif not is_from_ds(pkt) and not is_to_ds(pkt):
        return get_addr3(pkt)

def get_recv_addr(pkt):
    ''' get the recieve address of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means recieve address
    '''
    
    if is_from_ds(pkt) and is_to_ds(pkt):
        return get_addr1(pkt)
    
def get_send_addr(pkt):
    ''' get the send address of the packet
        
        Arguments:
            pkt: class 'scapy.layers.dot11.Dot11'
        Returns(str):
            return a string which means send address
    '''
    
    if is_from_ds(pkt) and is_to_ds(pkt):
        return get_addr2(pkt)
        
def dot11_filter(pkt_seq, expression):
    ''' the filter for dot11 packets,pkt_seq is supposed to be a list
        
        Arguments:
            pkt_seq    : a sequence of class 'scapy.layers.dot11.Dot11'
            expression : expressions of filter, 
                         eg.'beacon or probereq'
                            'no proberesp and no probereq'
                            'beacon and addr1="ff:ff:ff:ff:ff:ff"'
                            'beacon and ssid="tp-link"'
        Returns:
            return a sequence which satisfy the expressions
    '''
    
    # split the expression
    expression = expression.split(' or ')
    expression = [x.split(' and ') for x in expression]
    
    # filter the packets
    pkt_filt   = []
    for pkt in pkt_seq:
        if not pkt.haslayer(Dot11):
            continue
            
        # use the expression for the packet
        for exp in expression:
            result = True
            for condition in exp:
                condition = condition.lower()
                if '=' in condition:
                    position   = condition.index('=')
                    attr, value = condition[:position], condition[position+1:]
                    
                    try:
                        pkt_value = eval("get_%s(pkt)"%attr)
                    except:
                        continue
                    if pkt_value != eval(value):
                        result = False
                        break
                    else:
                        continue
                        
                if 'no ' in condition:
                    new_condition = condition.replace('no ', '')
                else:
                    new_condition = condition
                
                if ((LAYERS.has_key(new_condition) and 
                    LAYERS[new_condition] == get_packet_type(pkt)) or
                    pkt.haslayer(new_condition.upper())):
                    if 'no ' in condition:
                        result = False
                        break
                elif 'no ' in condition:
                    continue
                else:
                    result = False
                    break

            if result:
                pkt_filt.append(pkt)
    return pkt_filt
    
class WirelessClient(object):
    ''' simulate a wireless client
    '''
    
    def __init__(self, linkname='wlan', band=BAND_2G4):
        self.linkname = linkname
        self.band     = band
        
    def __sendp_packet(self, pkt):
        sendp(pkt, iface=self.linkname)
        
    def __change_channel(self, pkt, new_chan):
        pkt[Elt_HTInfo].primary_chan = new_chan
        pkt[Elt_DSset].cur_channel   = new_chan
        
    def set_band(self, band):
        self.band = band
        
    def send_beacon(self, channel=None, ssid_list=None, bssid_list=None, client_num=None, timeout=None, inter=0, loop=False, count=None):
        pkt   = get_pkt_model('beacon_%s'%self.band)
        default_ssid    = get_ssid(pkt)
        default_bssid   = get_bssid(pkt)
        default_channel = get_cur_chan(pkt)
        
        # creat ssid, bssid
        if client_num is not None:
            ssid_list  = []
            bssid_list = []
            end_num = int('1' + str(client_num))
            str_len = len(str(end_num))
            for i in range(end_num - client_num, end_num):
                ssid_list.append(default_ssid[:-str_len] + str(i))
                new_bssid = default_bssid.replace(':', '')[:-str_len] + str(i)
                bssid_list.append(':'.join([new_bssid[x:x+2] for x in range(6)]))
        elif ssid_list is None:
            ssid_list  = [default_ssid]
            bssid_list = [default_bssid]
                
        # creat channel
        if channel is None:
            channel = [default_channel]
        elif not isinstance(channel, list) and not isinstance(channel, tuple):
            channel = list(channel)
            
        # creat pkt
        pkt_list = []
        for i in range(len(ssid_list)):
            tmp_pkt = RadioTap(str(pkt))
            set_ssid(tmp_pkt, ssid_list[i])
            set_addr2(tmp_pkt, bssid_list[i])
            set_addr3(tmp_pkt, bssid_list[i])
            self.__change_channel(tmp_pkt, channel[i%len(channel)])
            pkt_list.append(tmp_pkt)
            
        # send pkt
        tsendp(pkt_list, iface=self.linkname, timeout=timeout, inter=inter, loop=loop, count=count)
    
