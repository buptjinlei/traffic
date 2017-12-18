import pyshark as ps
import json
def get_burst(cap,burst_length):
    burst_list = []
    flow_list = []
    startTime = cap[0].sniff_timestamp
    for pkt in cap:     
        if float(pkt.sniff_timestamp)*1000-float(startTime)*1000>burst_length:
            burst_list.append(flow_list)            
            flow_list=[]
        startTime = pkt.sniff_timestamp
        flow_list.append(pkt)
    burst_list.append(flow_list)     # bugfix: the last burst misssed
    return burst_list


# burst to flow
def burst2flow(burst):
    #print("burst to flow :len burst",len(burst))
    dict_={}
    #flow_list = [[] for i in range(len(burst))]
    flow_list = []
    for pkt in burst:
        isdsd = common_attribute(pkt)
        tuple_=tuple(isdsd)
        if tuple_ in dict_ :                       
            dict_[tuple_].append(pkt)
        else:
            dict_[tuple_]=[pkt]  
    l=[]
    for i in dict_:
        if i not in l and i!=tuple([-1,-1,-1,-1]):
            tmp=[]
            tmp.append(dict_[i])
            index=tuple([i[2],i[3],i[0],i[1]])
            try:
                tmp.append(dict_[index])
            except:
                tmp.append([])
            l.append(index)
            flow_list.append(tmp) 
    return flow_list

# cap->flow 
def get_flow(burst_list):
    flow_ret=[]
    print("get_flow len burst_list",len(burst_list))
    for burst in burst_list:
        flow_ret.append(burst2flow(burst))
    return flow_ret

# ret ip port 
def common_attribute(pkt):   
    if pkt.__contains__("udp"):
        if pkt.__contains__("ip"):
            src = pkt.ip.src
            #print(src)
            dst = pkt.ip.dst
            srcport = pkt.udp.srcport
            dstport = pkt.udp.dstport
        else:
            src = -1 #none
            dst = -1
            srcport = -1
            dstport = -1
            pass
    elif pkt.__contains__("tcp"):
        if pkt.__contains__("ip"):
            src = pkt.ip.src
            dst = pkt.ip.dst
            srcport = pkt.tcp.srcport
            dstport = pkt.tcp.dstport
        else:
            src = -1 #none
            dst = -1
            srcport = -1
            dstport = -1
            pass
    else :
        src = -1 #none
        dst = -1
        srcport = -1
        dstport = -1
    ret = [src,srcport,dst,dstport]
    return ret

def get_future(flowinburst):
    length_=[]
    burst_features =[]
    flow_features = []
    for j in range(len(flowinburst)):    # traversal burst
        for i in range(len(flowinburst[j])):  #traversal flow
            #print("burst ",j,"flow ",i,"is ",len(ret[j][i]),(ret[j][i]))
            l=[]
            #print("i is ",i)    # every flow contains two parts in and com 
            for item in flowinburst[j][i]:  # incoming and coming  one item has 
                #print("item is:",item)
                #print("The len ",len(flowinburst[j][i]))
                tmp=[]
                for k in item:      # in  or com
                    tmp.append(float(k.length))
                l.append(tmp)       # a flow's all length
                
            if len(l[0])>6 or len(l[1])>6:  # 6 packets
                l.append(l[0]+l[1])    #l[2] is total
                #print("len l is :",len(l))
                length_.append(l)       # a burst's all length
                for flow_length in l:
                    flow_features.append(fe.features(flow_length))
        burst_features.append(flow_features)
    return length_,burst_features
def to_json(burst_features):
    of=open("feature.json","w")
    json.dump(burst_features,of)
    of.close()
