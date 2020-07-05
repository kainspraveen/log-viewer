import pyshark
import xml.etree.ElementTree as et
import pandas as pd
import os
import copy
import datetime
import json

class Parser:
    def __init__(self):
        """processes and events are lists, but stack is dictionary with PID
        as key"""
        self.procmon={"processes":{},"events":{}}
        self.win_ent_view=None
        self.wire_shark={}
        self.archive=None
        self.files=None

    def FileLookup(self):
        self.files=[f for f in os.listdir('.') if os.path.isfile(f)]


    def ProcmonParser(self):
        #Get list of Procmon files

        procmon=[]
        for f in self.files:
            if(f[len(f)-3:]=="XML"):
                procmon.append(f)
        print(procmon)

        for i in range(1):   #First for single file then loop over len(procmon)
            print(procmon[i])
            tree=et.parse(procmon[i])
            root=tree.getroot()

            #Parsing <ProcessList>
            process_list=root[0]
            count2=1
            for process in process_list:
                print("Parsing Process",count2," ",process[1].text,"....Done")
                proc={}
                det={}
                for details in process[:17]:
                    det[details.tag]=copy.deepcopy(details.text)
                module_list={}
                count=0
                time=0
                for modules in process[17]:
                    temp={}
                    for details in modules:
                        temp[details.tag]=copy.deepcopy(details.text)

                    module_list[count]=copy.deepcopy(temp)
                    if(time==0):
                        time=int(modules[0].text)

                    count+=1
                #print(module_list)

                proc.update(det)
                #print("After det")
                #print("\n\n\n",proc)
                proc.update({'modules':module_list})
                #print("after module\n\n\n",proc)
                #break
                self.procmon['processes'][time]=copy.deepcopy(proc)
                count2+=1
            #parsing <eventlist>
            event_list=root[1]

            for events in event_list:
                eve={}
                for details in events[:8]:
                    eve[details.tag]=copy.deepcopy(details.text)
                pid=eve['PID']
                self.procmon['events'][pid]=copy.deepcopy(eve)
                stack_list={}
                count=0
                for frame in events[8]:

                    f={}
                    for info in frame:
                        f[info.tag]=info.text
                    stack_list[count]=copy.deepcopy(f)
                    count+=1
                self.procmon['events'][pid]['stack']=copy.deepcopy(stack_list)



    def WireSharkParser(self):
        ws_f=[]
        for i in self.files:
            if(i[len(i)-6:]=="pcapng"):
                ws_f.append(i)
        count=0
        for i in range(len(ws_f)):
            cap=pyshark.FileCapture(ws_f[i])
            for packets in cap:
                print("Parsing packet ",count,"....",end="")
                pkt={}
                pkt['packet_length']=packets.captured_length
                pkt['sniff_time'] = packets.sniff_time
                pkt['time_stamp'] = datetime.datetime.fromtimestamp(int(float(packets.sniff_timestamp))).strftime("%Y-%m-%d %H:%M:%S")

                """Ethernet"""
                ts=packets.sniff_time.timestamp() #Saved Timestamp
                temp1={}
                ether=packets[0]
                temp1['destination']=packets[0].dst
                temp1['source'] = packets[0].src
                pkt['ethernet_layer']=copy.deepcopy(temp1)

                """IP Layer"""
                temp1={}
                ip=packets[1]
                try:
                    temp1['dsfield']=ip.dsfield
                    temp1['dsfield_dscp']=ip.dsfield_dscp
                    temp1['dsfield_ecn']=ip.dsfield_ecn
                    temp1['length']=ip.len
                    temp1['identification']=ip.id
                    temp1['flags']=ip.flags
                    temp1['fragment_offset']=ip.frag_offset
                    temp1['ttl']=ip.ttl
                    temp1['protocol']=ip.proto
                    temp1['check_sum']=ip.checksum
                    temp1['check_sum_status']=ip.checksum_status
                    temp1['source']=ip.src
                    temp1['destination']=ip.dst
                except:
                    pass
                pkt['ip_layer']=copy.deepcopy(temp1)

                """TCP Layer"""

                temp1={}
                try:
                    tcp=packets[2]

                    temp1['dst_port']=tcp.dstport
                    temp1['src_port']=tcp.srcport
                    temp1['stream']=tcp.stream

                    temp1['length']=tcp.len
                    temp1['raw_sequence _number']=tcp.seq_raw
                    temp1['raw_ack_number']=tcp.ack_raw
                    temp1['flags']=tcp.flags
                    temp1['checksum']=tcp.checksum
                    temp1['checksum_status']=tcp.checksum_status
                    temp1['urgent_pointer']=tcp.urgent_pointer
                    temp1['window_size']=tcp.window_size
                except:
                    pass
                pkt['tcp_layer']=copy.deepcopy(temp1)
                """TLS Layer"""

                try:
                    temp1={}
                    tls=packets[3]
                    temp1['content_type']=tls.record_content_type
                    temp1['lendth']=tls.record_length
                    temp1['version']=tls.record_version
                    temp1['overview']=tls.record
                    temp=tls.app_data[:64]
                    temp+='...'
                    temp1['data']=copy.deepcopy(temp)
                    pkt['tls_layer']=copy.deepcopy(temp1)
                except:
                    pass


                self.wire_shark[ts]=copy.deepcopy(pkt)
                """ The End"""
                print("...Done")
                count+=1
                if(count==100):
                    break



    def WindowsEventLogParser(self):
        w_f=[]
        for i in self.files:
            if(i[len(i)-3:]=="xml"):
                w_f.append(i)

        for i in range(len(w_f)):

            tree=et.parse(w_f[i])
            root=tree.getroot()





    def WriteToFile(self):
        f1=open("procmon.json", 'w')
        f2=open("wire_shark.json", "w")
        procmon=json.dump(self.procmon,f1, indent=4,default=str)
        json.dump(self.wire_shark,f2, indent=4,default=str)




    def SortDicts(self):
        #print("DFFA")
        """dict=sorted(self.procmon['processes'], key= lambda x: self.procmon['processes'][0]['modules'][0]['Timestamp'])
        print(type(dict[0]))
        for i in dict:
            print(dict[0]['modules'][0]['Timestamp'])"""
        #print(self.procmon['processes'])
        #print(type(self.procmon['processes']))
        dict=sorted(self.procmon['processes'])
        Sorted={}
        for i in dict:
            Sorted[i]=copy.deepcopy(self.procmon['processes'][i])
        #print(Sorted)
        self.procmon['processes']=copy.deepcopy(Sorted) #UPDATING list with sorted dictionary
        count=0
        print("Sorted Processes")
        """for i in self.procmon['processes']:
            print("{",i,": ",self.procmon['processes'][i],"}")
            print("\n\n\n")
            count+=1
            if(count==3):
                break"""
        """print("Sorted Events")
        count=0
        for i in self.procmon['events']:
            print("{",i," : ",self.procmon['events'][i],"}")
            print("\n\n\n")
            count+=1
            if(count==3):
                break"""

        dict=sorted(self.wire_shark)
        #print(dict)
        Sorted={}
        for i in dict:
            Sorted[i]=copy.deepcopy(self.wire_shark[i])
        self.wire_shark=copy.deepcopy(Sorted)
        #print(self.wire_shark)
        count=0
        """print("sorted wireshark events")
        for i in self.wire_shark:
            print("{ ",i,": ",self.wire_shark[i],"}")
            print("\n\n\n")
            count+=1
            if(count==3):
                break"""







def main():
    obj=Parser()
    obj.FileLookup()
    obj.ProcmonParser()
    obj.WireSharkParser()
    #obj.SortDicts()
    obj.WriteToFile()

if __name__ == '__main__':
    main()
