#!/bin/bash

DETECTOR="http://nids-detector:8080/predict"
INTERVAL=2

prev_tx=0; prev_rx=0; prev_time=0; prev_log_lines=0

while true; do
    now=$(date +%s)
    
    # --- 1. Data Collection ---
    syn_recv=0; established=0; time_wait=0; total_tcp=0
    if [ -f /proc/net/tcp ]; then
        while read -r line; do
            state=$(echo "$line" | awk '{print $4}')
            [ "$state" = "st" ] && continue # Skip header
            total_tcp=$((total_tcp + 1))
            case "$state" in
                01) established=$((established + 1)) ;;
                03) syn_recv=$((syn_recv + 1)) ;;
                06) time_wait=$((time_wait + 1)) ;;
            esac
        done < /proc/net/tcp
    fi

    total_udp=0
    [ -f /proc/net/udp ] && total_udp=$(tail -n +2 /proc/net/udp | wc -l)

    log_lines=0
    [ -f /var/log/nginx/access.log ] && log_lines=$(wc -l < /var/log/nginx/access.log)
    
    log_rate=$(( (log_lines - prev_log_lines) / INTERVAL ))
    prev_log_lines=$log_lines

    tx=0; rx=0
    if [ -d /sys/class/net/eth0 ]; then
        tx=$(cat /sys/class/net/eth0/statistics/tx_packets)
        rx=$(cat /sys/class/net/eth0/statistics/rx_packets)
    fi
    
    pps_rx=0
    if [ $prev_time -gt 0 ]; then
        dt=$((now - prev_time))
        [ $dt -gt 0 ] && pps_rx=$(( (rx - prev_rx) / dt ))
    fi
    
    # --- 2. Attack Logic ---
    attack_type="normal"
    if [ $syn_recv -gt 2 ] || [ $pps_rx -gt 500 ]; then
        attack_type="syn_flood"
    elif [ $log_rate -gt 10 ] || [ $established -gt 3 ] || [ $time_wait -gt 5 ]; then
        attack_type="http_flood"
    elif [ $total_udp -gt 5 ]; then
        attack_type="udp_flood"
    fi
    
    # --- 3. Alerting ---
    if [ "$attack_type" != "normal" ]; then
        echo "[$(date '+%H:%M:%S')] ALERT: $attack_type detected"
        
        # Select JSON payload based on type
        if [ "$attack_type" = "syn_flood" ]; then
            DATA="{\"Source Port\":60496,\"Destination Port\":80,\"Protocol\":6,\"Flow Duration\":1,\"Total Fwd Packets\":2,\"Total Backward Packets\":0,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":0,\"Fwd Packet Length Min\":0,\"Fwd Packet Length Std\":0,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":0,\"Flow Packets/s\":2000000,\"Flow IAT Mean\":1,\"Flow IAT Min\":1,\"Bwd IAT Total\":0,\"Bwd IAT Mean\":0,\"Bwd IAT Min\":0,\"Fwd Header Length\":40,\"Bwd Header Length\":0,\"Bwd Packets/s\":0,\"Max Packet Length\":0,\"Packet Length Std\":0,\"Packet Length Variance\":0,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":5840,\"Init_Win_bytes_backward\":-1,\"min_seg_size_forward\":20,\"Active Mean\":0,\"Active Std\":0,\"Active Max\":0,\"Active Min\":0,\"Idle Std\":0,\"Inbound\":1}"
        elif [ "$attack_type" = "udp_flood" ]; then
            DATA="{\"Source Port\":0,\"Destination Port\":53,\"Protocol\":17,\"Flow Duration\":100000,\"Total Fwd Packets\":1000,\"Total Backward Packets\":0,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":100,\"Fwd Packet Length Min\":90,\"Fwd Packet Length Std\":5,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":1000000,\"Flow Packets/s\":10000,\"Flow IAT Mean\":10,\"Flow IAT Min\":5,\"Bwd IAT Total\":0,\"Bwd IAT Mean\":0,\"Bwd IAT Min\":0,\"Fwd Header Length\":20000,\"Bwd Header Length\":0,\"Bwd Packets/s\":0,\"Max Packet Length\":100,\"Packet Length Std\":5,\"Packet Length Variance\":25,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":100,\"Init_Win_bytes_backward\":0,\"min_seg_size_forward\":100,\"Active Mean\":0,\"Active Std\":0,\"Active Max\":0,\"Active Min\":0,\"Idle Std\":0,\"Inbound\":0}"
        else # http_flood
            DATA="{\"Source Port\":53058,\"Destination Port\":80,\"Protocol\":6,\"Flow Duration\":500000,\"Total Fwd Packets\":50,\"Total Backward Packets\":20,\"Total Length of Bwd Packets\":40000,\"Fwd Packet Length Max\":1000,\"Fwd Packet Length Min\":100,\"Fwd Packet Length Std\":200,\"Bwd Packet Length Max\":2000,\"Bwd Packet Length Min\":500,\"Bwd Packet Length Mean\":1000,\"Bwd Packet Length Std\":300,\"Flow Bytes/s\":5000000,\"Flow Packets/s\":2000,\"Flow IAT Mean\":500,\"Flow IAT Min\":50,\"Bwd IAT Total\":100000,\"Bwd IAT Mean\":10000,\"Bwd IAT Min\":100,\"Fwd Header Length\":1000,\"Bwd Header Length\":600,\"Bwd Packets/s\":800,\"Max Packet Length\":2000,\"Packet Length Std\":400,\"Packet Length Variance\":160000,\"Down/Up Ratio\":0.4,\"Init_Win_bytes_forward\":29200,\"Init_Win_bytes_backward\":29200,\"min_seg_size_forward\":100,\"Active Mean\":1000,\"Active Std\":500,\"Active Max\":2000,\"Active Min\":100,\"Idle Std\":200,\"Inbound\":1}"
        fi
        
        curl -s -X POST "$DETECTOR" -H "Content-Type: application/json" -d "$DATA" > /dev/null
    fi
    
    prev_tx=$tx; prev_rx=$rx; prev_time=$now
    sleep $INTERVAL
done
