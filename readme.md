#### What is this for ####
This project allows to get web server performance metric from traffic TCPDump. 
This allows to measure up metric like **html delivery time** which are usually not available in runtime and have second opinion about other metrics like **server latency**.


#### Installation ####
This is not meant to be used directy on frontend, because it could consume lot of memory and CPU parsing pcap files.
Please install on development server or workstation

Before installation you need python (pypy is preferrable because it faster on task like this).
Only other dependance is dpkt (python tcpdump parsing library) see https://dpkt.readthedocs.org
If you use pip to install dpkt please say **pypy -m pip install dpkt** instead of **pip install dpkt**,
second spell installs dpkt for python not pypy.

#### How to get data ####

You should dump on frontend/reverse proxy/balancer i.e. something which holds tcp connections directly to users

Simple way:
   **sudo tcpdump -w data.pcap port 80**

Production way:
   * use nice -10 to give additional priority to tcpdump
   * use -B option for largest buffer available on your system. Sometimes tcpdump drop some packets because disk is busy
   * use -C option to split file by files of reasonable size (1-10Gb) this is easier for copying/etc
   * use -z to compress splitted files after writing, note: nice/ionice gzip to prevent it from preemping tcpdump 
   * dump only traffic you need, i.e. use filters "port 80 or port 8080"
   * if you debugging frontend itself consider dumping both traffic to user and backend. You may find something interesting comparing timings.


#### Parsing ####
```
   decode-pcap.py <outdir> (parse|split|sparse) <input files shoild have extensions .pcap or .pcap.gz> 

   outdir - directory where http.txt and debug.txt will be created.

   parse  - just parse files. will use lot of memory because every active session is kept in memory until closed. 
            and tcpdump has a lot of sessions which never ends. Session which crossed tcpdump files will be preserved.
            order of files is important, i.e. better to have timestamp or number inside file name.
   split  - extract tcp sessions from pcap files split it to several new files. Each session will be only in one file.
            order of packets will be changed. I.e. session 1 - packets 1..N, session 2 packets N+1..M, etc.
            timestamps will be preserved. 
   sparse - parse splited files. Actually it is same as just run programs on all files one by one.
            sessions across files will be separated. 
```

Examples: 

```
     decode-pcap.py out parse tcpdump.pcap.gz 
     (test example)

     decode-pcap.py splitted split 100Gb-dump/*.pcap.gz
     decode-pcap.py out sparse splitted/*.pcap.gz 

     (real world example. If you want to parse 100Gb of tcpdump you may need comparable amount of memory for split 
     operation. Comparable means 100Gb if all http sessions is keep-alive and not finished inside file. And small amount of memory if all sessions are short. 
     In real world you have mixed traffic so be ready to have 20Gb-30Gb of memory for average large service.
     If you need only some ports save memory by please patching string in decode-pcap.py 
        "ports = None #set([80,8080]) #uncomment this if yuo don't need all traffic "

     In yandex we have used map/reduce version of this program, it were using proprietary map/ruduce implementation, 
     so it useless outside. But I waht to port in to Hadoop, if you have lot of data and test stand ask me)
```

After parsing there will be files http.txt and debug.txt 

#### Output format ####


Columns of http.txt are the folowing:

```
server  
server_port     
client  
client_port     
request                 - GET/POST/HEAD
uri 
response                - HTTP
status                  - 200/301/500/etc
reqid                   - Yandex Specific request id. Will be None in your case. 

request_start_time      - timestamp, first packet of request
request_end_time        - timestamp, last packet of request, usually same as first, unless it is large POST request.

response_start_time     - timestamp, first packet of response
response_end_time       - timestamp, last packet of response   

request_start_acked     - time then your server acked request first packet
request_end_acked       - time then your server acked request last packet      

response_start_acked    - time then user acked delivery of start of data
response_end_acked      - time then user acked delivery of end of data

request_retr            - number of retransmission in request     
request_false_retr      - broken   
request_keepalive_retr  - always 0, we track keepalive retransmission but they are not a part of request 


response_retr           - number of retransmission in response
response_false_retr     - broken
response_keepalive_retr - always 0, we track keepalive retransmission but they are not a part of response



request_min_rtt         - different round trip time statistic by seq/ack
request_median_rtt      
request_max_rtt 
response_min_rtt        
response_median_rtt     
response_max_rtt        
req_avg_retr_time       
resp_avg_retr_time      


reqpackets              - number of packets in request. Usually 1.
reqlen                  - length of payload of request
reqreallen              - length of payload without retransmission.


resppackets             - number of packets in response.
resplen                 - length of payload of response
respreallen             - length of payload without retransmission.


req_user_agent          - user agent. Split by this to distinguish mobile/nonmobile traffic
req_host                - host from HTTP protocol


server_as               - broken
server_24mask           - broken
client_as               - broken 
client_24mask           - broken
```

#### Intersing thing to calculate yourself ####

``` 
   server_ack_delay = response_start_acked - request_start_time 
   #if server_ack_delay>0 you have network problems (in case of server side dump)

   server_latency = response_start_time - request_end_time
   #compare to your logs, you may be surprised

   request_traffic_waste = reqlen/reqreallen
   #should be 1. If not you network is broken.

   response_traffic_waste = resplen/respreallen
   #will be more than 1. This is packet loss to users. Monitor to measure you network connectivity effectiveness

   response_packets_waste = resppackets/(resplen/1450)
   #if more than 1 - your traffic is not ideally splitted by packets. Usually on the border of jumbo frame.

   response_pushthru = response_end_time - response_start_time
   #Time of delivering to user. Usually significally more than server_latency. If it very large you probably need CDN.
   #also could be optimized by decreasing html size, or increasing initial cwnd (don't do last one unless you really know what are you doing)

   total_user_wait_time = response_end_acked - request_start_time
   #real request start time is request_start_time-rtt, real last byte time is response_end_acked-rtt.
   #rtt is negate itself if it stable

   Also take note you could parse traffic to USER and to BACKEND and compare it. There is lot of intersting statistic here too. You just need to be able to glue request - yandex used reqid for it.
```


