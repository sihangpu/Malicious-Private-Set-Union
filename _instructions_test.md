java -Djava.library.path=/root/merpsu_malicious/mpc4j-native-tool/cmake-build-release:/root/merpsu_malicious/mpc4j-native-fhe/cmake-build-release -jar /root/merpsu_malicious/mpc4j-s2pc-pso/target/mpc4j-s2pc-pso-1.0.5-jar-with-dependencies.jar /root/merpsu_malicious/mpc4j-s2pc-pso/conf/psu/conf_psu_merpsu22_ot_server.txt &  disown

java -Djava.library.path=/root/merpsu_malicious/mpc4j-native-tool/cmake-build-release:/root/merpsu_malicious/mpc4j-native-fhe/cmake-build-release -jar /root/merpsu_malicious/mpc4j-s2pc-pso/target/mpc4j-s2pc-pso-1.0.5-jar-with-dependencies.jar /root/merpsu_malicious/mpc4j-s2pc-pso/conf/psu/conf_psu_merpsu22_ot_client.txt & disown

java -Djava.library.path=/root/merpsu_malicious/mpc4j-native-tool/cmake-build-release:/root/merpsu_malicious/mpc4j-native-fhe/cmake-build-release -jar /root/merpsu_malicious/mpc4j-s2pc-pso/target/mpc4j-s2pc-pso-1.0.5-jar-with-dependencies.jar /root/merpsu_malicious/mpc4j-s2pc-pso/conf/psu/conf_psu_zcl22_ske_server.txt &  disown

java -Djava.library.path=/root/merpsu_malicious/mpc4j-native-tool/cmake-build-release:/root/merpsu_malicious/mpc4j-native-fhe/cmake-build-release -jar /root/merpsu_malicious/mpc4j-s2pc-pso/target/mpc4j-s2pc-pso-1.0.5-jar-with-dependencies.jar /root/merpsu_malicious/mpc4j-s2pc-pso/conf/psu/conf_psu_zcl22_ske_client.txt & disown

# result
awk '{print $6 " " $10}' PSU_MERPSU22_OT_128_1
PSU_ZCL22_SKE_128_1_5.txt

# test epsu
./test_balanced_epsu -nn 14 -nt 1 -r 0 & ./test_balanced_epsu -nn 14 -nt 1 -r 1

# connect server
194-37-80-237.cloud-xip.com

--------------

# add
sudo tc qdisc del dev lo root
sudo tc qdisc add dev lo root handle 1: htb default 1
sudo tc class add dev lo parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit
sudo tc filter add dev lo protocol ip parent 1: prio 1 u32 \
    match ip dst 127.0.0.1/32 flowid 1:1

# show htb
tc -s qdisc show dev lo
tc -s class show dev lo

# Remove 
sudo tc qdisc del dev lo root



# env --------------------------------------------------------------------------
CPU: Intel Xeon Processor (4th Gen SapphireRapids) Golden Cove 8-core @2.0Ghz
24G RAM
---------------------------------------------------------------------------
Field → Montgomery: 226909 ops/sec; each 4.4 us
Montgomery → Field: 229846 ops/sec; each 4.4 us

Enumerate Representatives: 846361 ops/sec; each 1.2 us
Montgomery Scalar Mult: 20575 ops/sec; each 48.6 us
Edwards Scalar Mult: 54081 ops/sec; each 18.5 us
Edwards Fixed-Base Mult: 112736 ops/sec; each 8.9 us
Edwards Multi-Scalar Mult: 412912 ops/sec; each 2.2 us
Edwards Round-Trip Compression: 121246 ops/sec; each 8.2 us
AES Round-Trip Permutation: 17543859649 ops/sec; each 0.1 ns
Hash to Point Round-Trip: 21505 ops/sec; each 46.5 us
Hash to Point 9.2 us
# czz sh --------------------------------------------------------------------------
0.41 6.48 103.31 MB 
Semi-honest One-Sided-Output PSU, set size 4096, online time 476.074301ms, offline time 83.655µs
Semi-honest One-Sided-Output PSU, set size 16384, online time 1.666564821s, offline time 267.589µs
Semi-honest One-Sided-Output PSU, set size 65536, online time 6.735245349s, offline time 819.784µs
Semi-honest One-Sided-Output PSU, set size 1048576, online time 108.682434088s, offline time 24.526507ms


1gbps
Semi-honest One-Sided-Output PSU, set size 4096, online time 482.956209ms, offline time 90.632µs
Semi-honest One-Sided-Output PSU, set size 16384, online time 1.886896002s, offline time 251.501µs
Semi-honest One-Sided-Output PSU, set size 65536, online time 7.607475555s, offline time 824.957µs
Semi-honest One-Sided-Output PSU, set size 1048576, online time 114.681426204s, offline time 29.478714ms


500mbps
Semi-honest One-Sided-Output PSU, set size 4096, online time 493.296027ms, offline time 110.304µs
Semi-honest One-Sided-Output PSU, set size 16384, online time 1.96358736s, offline time 219.113µs
Semi-honest One-Sided-Output PSU, set size 65536, online time 7.973407422s, offline time 819.348µs
Semi-honest One-Sided-Output PSU, set size 1048576, online time 126.332251584s, offline time 30.912027ms

100mbps
Semi-honest One-Sided-Output PSU, set size 4096, online time 528.925412ms, offline time 100.566µs
Semi-honest One-Sided-Output PSU, set size 16384, online time 2.019624232s, offline time 301.534µs
Semi-honest One-Sided-Output PSU, set size 65536, online time 8.365531713s, offline time 808.314µs
Semi-honest One-Sided-Output PSU, set size 1048576, online time 141.87121723s, offline time 42.576044ms


# 1m --------------------------------------------------------------------------
Malicious (Sender) One-Sided-Output PSU, set size 4096, online time 672.837482ms, offline time 86.417µs
Malicious (Sender) One-Sided-Output PSU, set size 16384, online time 2.384242314s, offline time 223.159µs
Malicious (Sender) One-Sided-Output PSU, set size 65536, online time 8.850988812s, offline time 809.992µs
Malicious (Sender) One-Sided-Output PSU, set size 1048576, online time 137.200276809s, offline time 24.636771ms

7750  124934 KB
1gbps
Malicious (Sender) One-Sided-Output PSU, set size 4096, online time 693.978104ms, offline time 100.273µs
Malicious (Sender) One-Sided-Output PSU, set size 16384, online time 2.403840617s, offline time 244.506µs
Malicious (Sender) One-Sided-Output PSU, set size 65536, online time 9.149315241s, offline time 803.166µs
Malicious (Sender) One-Sided-Output PSU, set size 1048576, online time 146.158427199s, offline time 42.881586

500mbps
Malicious (Sender) One-Sided-Output PSU, set size 4096, online time 703.25961ms, offline time 166.506µs
Malicious (Sender) One-Sided-Output PSU, set size 16384, online time 2.455179806s, offline time 224.839µs
Malicious (Sender) One-Sided-Output PSU, set size 65536, online time 9.349708744s, offline time 848.33µs
Malicious (Sender) One-Sided-Output PSU, set size 1048576, online time 149.349487089s, offline time 33.420973ms

100mbps
Malicious (Sender) One-Sided-Output PSU, set size 4096, online time 757.359213ms, offline time 87.124µs
Malicious (Sender) One-Sided-Output PSU, set size 16384, online time 2.565550937s, offline time 262.155µs
Malicious (Sender) One-Sided-Output PSU, set size 65536, online time 10.278719227s, offline time 895.539µs
Malicious (Sender) One-Sided-Output PSU, set size 1048576, online time 165.975496801s, offline time 48.040213ms

# 2m --------------------------------------------------------------------------
Offline time takes ~4%
Malicious Two-Sided-Output PSU, set size 4096, online time 709.425 ms, offline time 28.562 ms
Malicious Two-Sided-Output PSU, set size 16384, online time 2.828609553s, offline time 113.20391ms
Malicious Two-Sided-Output PSU, set size 65536, online time 11.303698904s, offline time 447.458212ms
Malicious Two-Sided-Output PSU, set size 1048576, online time 184.421532094s, offline time 8.15559357s

1gbps
Malicious Two-Sided-Output PSU, set size 4096, online time 844.752752ms, offline time 30.361627ms
Malicious Two-Sided-Output PSU, set size 16384, online time 3.023075861s, offline time 117.368052ms
Malicious Two-Sided-Output PSU, set size 65536, online time 12.383105585s, offline time 636.504775ms
Malicious Two-Sided-Output PSU, set size 1048576, online time 200.508845004s, offline time 8.977204887s

500mbps
Malicious Two-Sided-Output PSU, set size 4096, online time 851.877209ms, offline time 29.5879ms
Malicious Two-Sided-Output PSU, set size 16384, online time 3.156189121s, offline time 113.275357ms
Malicious Two-Sided-Output PSU, set size 65536, online time 13.548888916s, offline time 528.160176ms
Malicious Two-Sided-Output PSU, set size 1048576, online time 207.20214016s, offline time 8.913023742s

100 mbps
Malicious Two-Sided-Output PSU, set size 4096, online time 867.871552ms, offline time 29.97609ms
Malicious Two-Sided-Output PSU, set size 16384, online time 3.500861627s, offline time 122.04013ms
Malicious Two-Sided-Output PSU, set size 65536, online time 14.20578272s, offline time 512.9297ms
Malicious Two-Sided-Output PSU, set size 1048576, online time 230.034012992s, offline time 9.091121984s

# merpus --------------------------------------------------------------------------
Mermpus_10G
ID      Set      InitTime(ms)   Init Send Bytes(B)      Time(ms)         Send Bytes(B)                
1       1048576    6162            4587                  310682            127041306
1       65536      6117            4587                  18353             7939866
1       16384      6155            4587                  4750              1984916
1       4096       6162            4587                  1192              496244


Mermpus_1G
6678 352524
6780 20646
6594 5294
6898 1438


Mermpus_500m
7183 378264
7051 22923
7236 5827
6970 1507


Mermpus_100m
6538 355151
6679 21657
6651 5469
6634 1533




# zcl-ske --------------------------------------------------------------------------
ZCL-SKE 10 Gbps
ID      Set      Init Time(ms)       Init Send(B)      Time(ms)   Pto Send(B)
1       1048576     2377272          40262843          76170      226,656,354         
1       65536       185509           5850935           4670       14,237,351
1       16384       58339            3592712           1427       3,572,091
1       4096        12828            2417743           313        899,641



ZCL-SKE 1 Gbps     init time           time
                3231356                  86260
                
                237239                   5172
                
                74065                     1290
                
                15818                     356
                

ZCL-SKE 500 Mbps

                   3170487              88546
                   227016               5419
                   74894                1428
                   14480                364 
               

ZCL-SKE 100 Mbps
1     1048576     3165434             108863  
1      65536      244081                6312     
1      16384      78039                 1537     
1      4096       16826                  411      



# epsu --------------------------------------------------------------------------
---------------------------------

Comm cost = 1.714 MB

Label    Time (ms)  diff (ms)
__________________________________
end         918.6    918.601  **********

Balanced_ePSU functionality test pass! And union size is: 4097

Comm cost = 4.760 MB
Label    Time (ms)  diff (ms)
__________________________________
end        2488.7   2488.703  **********
end        2868.6   2868.574  **********
Balanced_ePSU functionality test pass! And union size is: 16385


Comm cost = 16.751 MB
Label    Time (ms)  diff (ms)
__________________________________
end        8457.4   8457.373  **********

Balanced_ePSU functionality test pass! And union size is: 65537

Comm cost = 262.961 MB
Label    Time (ms)  diff (ms)
__________________________________
end      127739.2  127739.210  **********

Balanced_ePSU functionality test pass! And union size is: 1048577