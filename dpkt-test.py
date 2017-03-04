#!/usr/bin/python
# -*- coding: utf-8 -*-

import dpkt,socket
import string
import binascii
import sys

#メイン関数
def main(filename):

    pcr = dpkt.pcap.Reader(open(filename,'rb'))

    #パケット数
    packet_count = 0

    #パケット処理
    for ts,buf in pcr:
        packet_count += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        try:
            #IPデータの場合
            if type(eth.data) == dpkt.ip.IP:
                ip = eth.data
                # ipheader(ip)
                #TCPの場合
                if type(ip.data) == dpkt.tcp.TCP:
                    tcp = ip.data
                    #HTTPの場合
                    #HTTP Request
                    if tcp.dport == 80 and len(tcp.data) > 0:
                        http_req = dpkt.http.Request(tcp.data)
                        print '--------------------\n'
                        print http_req.method
                        print 'uri:'+http_req.uri
                        print http_req.body
                        print 'referer:'+http_req.headers['referer']


                    #ペイロードが0以外
                    if len(tcp.data) != 0:
                        thex = binascii.b2a_hex(tcp.data)
                        # payload(thex)
                elif type(ip.data) == dpkt.udp.UDP:
                    udp = ip.data
                    #payload != 0
                    if len(udp.data) != 0:
                        uhex = binascii.b2a_hex(udp.data)
                        # payload(uhex)
                elif type(ip.data) == dpkt.icmp.ICMP:
                    icmp = ip.data
                    if len(icmp.data) != 0:
                        ihex = binascii.hexlify(str(icmp.data))
                        # payload(ihex[8:])
        except:
            continue
    #sqlobj.close()
    print '処理終了:',packet_count

#IPヘッダ処理
def ipheader(header):
    #ヘッダの処理
    src = socket.inet_ntoa(header.src)
    dst = socket.inet_ntoa(header.dst)

    #TCP
    if type(header.data) == dpkt.tcp.TCP:
        print 'TCP %s:%s => %s:%s (len:%s)' % (src,header.data.sport,dst,header.data.dport,len(header.data.data))
        tcp = header.data

        #HTTP
        if tcp.dport == 80 and len(tcp.data) > 0:
            try:
                http_req = dpkt.http.Request(tcp.data)
                print 'HTTP Request\nMETHOD:%s\nURI:%s\nHEADERS:%s' % (http_req.method,http_req.uri,http_req.headers)
            except:
                print 'error-Request'
        if tcp.sport == 80 and len(tcp.data) > 0:
            try:
                http_res = dpkt.http.Response(tcp.data)
                print 'HTTP Response\nSTATUS:%s\nREASON:%s\nHEADERS:%s\n' % (http_res.status,http_res.reason,http_res.headers)
            except :
                print 'error-Response'

    #UDP
    elif type(header.data) == dpkt.udp.UDP:
        print 'UDP %s:%s => %s:%s (len:%s)' % (src,header.data.sport,dst,header.data.dport,len(header.data.data))
    #ICMP
    elif type(header.data) == dpkt.icmp.ICMP:
        print'ICMP %s:type:%s,code %s => %s (len:%s)' % (src,header.data.type,header.data.code,dst,len(header.data.data))
    #その他
    else:
        print '%s => %s' % (src,dst)

#ペイロード
def payload(thex):
        #ペイロードの処理
        return


#メイン関数
if __name__ == '__main__':
    if (len(sys.argv) != 2):
        print 'ファイルを指定してください'
        exit()
    #第２引数をファイル名にする
    filename = sys.argv[1]

    main(filename)

