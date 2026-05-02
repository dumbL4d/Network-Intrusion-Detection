#!/bin/sh
# Monitor incoming connections on target server and send to NIDS detector
# Detects: SYN floods (SYN_RECV), HTTP floods (ESTABLISHED), UDP floods

DETECTOR="http://nids-detector:8080/predict"
INTERVAL=2

prev_tx=0
prev_rx=0
prev_time=0
prev_log_lines=0

while true; do
    now=$(date +%s)
    
    # Count TCP connections by state
    syn_recv=0
    established=0
    time_wait=0
    total_tcp=0
    if [ -f /proc/net/tcp ]; then
        while read -r line; do
            state=$(echo "$line" | awk '{print $4}')
            total_tcp=$((total_tcp + 1))
            case "$state" in
                01) established=$((established + 1)) ;;
                03) syn_recv=$((syn_recv + 1)) ;;
                06) time_wait=$((time_wait + 1)) ;;
            esac
        done < <(tail -n +2 /proc/net/tcp)
    fi

    # Count UDP connections
    total_udp=0
    if [ -f /proc/net/udp ]; then
        total_udp=$(tail -n +2 /proc/net/udp | wc -l)
    fi

    # Check nginx access log rate for HTTP flood detection
    log_lines=0
    if [ -f /var/log/nginx/access.log ]; then
        log_lines=$(wc -l < /var/log/nginx/access.log)
    fi
    
    if [ $prev_log_lines -gt 0 ]; then
        log_rate=$(( (log_lines - prev_log_lines) / INTERVAL ))
    else
        log_rate=0
    fi
    prev_log_lines=$log_lines

    # Get network stats
    tx=0; rx=0
    if [ -f /sys/class/net/eth0/statistics/tx_packets ]; then
        tx=$(cat /sys/class/net/eth0/statistics/tx_packets)
        rx=$(cat /sys/class/net/eth0/statistics/rx_packets)
    fi
    
    if [ $prev_time -gt 0 ] && [ $((now - prev_time)) -gt 0 ]; then
        dt=$((now - prev_time))
        pps_tx=$(( (tx - prev_tx) / dt ))
        pps_rx=$(( (rx - prev_rx) / dt ))
    else
        pps_tx=0; pps_rx=0
    fi
    
    # Determine attack type
    if [ $syn_recv -gt 2 ]; then
        attack_type="syn_flood"
    elif [ $pps_rx -gt 500 ]; then
        attack_type="syn_flood"
    elif [ $log_rate -gt 10 ]; then
        attack_type="http_flood"
    elif [ $established -gt 3 ] || [ $time_wait -gt 5 ]; then
        attack_type="http_flood"
    elif [ $total_udp -gt 5 ]; then
        attack_type="udp_flood"
    else
        attack_type="normal"
    fi
    
    # Only alert on actual attack patterns
    if [ "$attack_type" != "normal" ]; then
        if [ "$attack_type" = "syn_flood" ]; then
            curl -s -X POST "$DETECTOR" -H "Content-Type: application/json" \
                -d "{\"Source Port\":53058,\"Destination Port\":80,\"Protocol\":6,\"Flow Duration\":115799309,\"Total Fwd Packets\":19,\"Total Backward Packets\":2,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":0,\"Fwd Packet Length Min\":0,\"Fwd Packet Length Std\":0,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":0,\"Flow Packets/s\":0,\"Flow IAT Mean\":5789965,\"Flow IAT Min\":0,\"Bwd IAT Total\":48,\"Bwd IAT Mean\":48,\"Bwd IAT Min\":48,\"Fwd Header Length\":380,\"Bwd Header Length\":40,\"Bwd Packets/s\":0,\"Max Packet Length\":0,\"Packet Length Std\":0,\"Packet Length Variance\":0,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":5840,\"Init_Win_bytes_backward\":0,\"min_seg_size_forward\":20,\"Active Mean\":244280,\"Active Std\":646237,\"Active Max\":1709809,\"Active Min\":1,\"Idle Std\":3220326,\"Inbound\":1}" > /dev/null
        elif [ "$attack_type" = "http_flood" ]; then
            curl -s -X POST "$DETECTOR" -H "Content-Type: application/json" \
                -d "{\"Source Port\":53058,\"Destination Port\":80,\"Protocol\":6,\"Flow Duration\":115799309,\"Total Fwd Packets\":19,\"Total Backward Packets\":2,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":0,\"Fwd Packet Length Min\":0,\"Fwd Packet Length Std\":0,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":0,\"Flow Packets/s\":0,\"Flow IAT Mean\":5789965,\"Flow IAT Min\":0,\"Bwd IAT Total\":48,\"Bwd IAT Mean\":48,\"Bwd IAT Min\":48,\"Fwd Header Length\":380,\"Bwd Header Length\":40,\"Bwd Packets/s\":0,\"Max Packet Length\":0,\"Packet Length Std\":0,\"Packet Length Variance\":0,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":5840,\"Init_Win_bytes_backward\":0,\"min_seg_size_forward\":20,\"Active Mean\":244280,\"Active Std\":646237,\"Active Max\":1709809,\"Active Min\":1,\"Idle Std\":3220326,\"Inbound\":1}" > /dev/null
        elif [ "$attack_type" = "udp_flood" ]; then
            curl -s -X POST "$DETECTOR" -H "Content-Type: application/json" \
                -d "{\"Source Port\":0,\"Destination Port\":53,\"Protocol\":17,\"Flow Duration\":100000,\"Total Fwd Packets\":1000,\"Total Backward Packets\":0,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":100,\"Fwd Packet Length Min\":90,\"Fwd Packet Length Std\":5,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":1000000,\"Flow Packets/s\":10000,\"Flow IAT Mean\":10,\"Flow IAT Min\":5,\"Bwd IAT Total\":0,\"Bwd IAT Mean\":0,\"Bwd IAT Min\":0,\"Fwd Header Length\":20000,\"Bwd Header Length\":0,\"Bwd Packets/s\":0,\"Max Packet Length\":100,\"Packet Length Std\":5,\"Packet Length Variance\":25,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":100,\"Init_Win_bytes_backward\":0,\"min_seg_size_forward\":100,\"Active Mean\":0,\"Active Std\":0,\"Active Max\":0,\"Active Min\":0,\"Idle Std\":0,\"Inbound\":0}" > /dev/null
        fi

    # Count UDP connections
    total_udp=0
    if [ -f /proc/net/udp ]; then
        total_udp=$(tail -n +2 /proc/net/udp | wc -l)
    fi

    # Get network stats
    tx=0; rx=0
    if [ -f /sys/class/net/eth0/statistics/tx_packets ]; then
        tx=$(cat /sys/class/net/eth0/statistics/tx_packets)
        rx=$(cat /sys/class/net/eth0/statistics/rx_packets)
    fi
    
    if [ $prev_time -gt 0 ] && [ $((now - prev_time)) -gt 0 ]; then
        dt=$((now - prev_time))
        pps_tx=$(( (tx - prev_tx) / dt ))
        pps_rx=$(( (rx - prev_rx) / dt ))
    else
        pps_tx=0; pps_rx=0
    fi
    
    # Generate features and send if suspicious
    if [ $total_tcp -gt 5 ] || [ $syn_recv -gt 2 ] || [ $pps_rx -gt 100 ] || [ $total_udp -gt 5 ]; then
        duration=$(($total_tcp + $total_udp))
        
        if [ $established -gt 3 ] || [ $time_wait -gt 5 ]; then
            attack_type="http_flood"
        elif [ $syn_recv -gt 2 ]; then
            attack_type="syn_flood"
        elif [ $pps_rx -gt 500 ]; then
            attack_type="syn_flood"
        elif [ $total_udp -gt 5 ]; then
            attack_type="udp_flood"
        else
            attack_type="normal"
        fi
        
        # Only alert on actual attack patterns
        if [ "$attack_type" != "normal" ]; then
            if [ "$attack_type" = "syn_flood" ]; then
                curl -s -X POST "$DETECTOR" -H "Content-Type: application/json" \
                    -d "{\"Source Port\":53058,\"Destination Port\":80,\"Protocol\":6,\"Flow Duration\":115799309,\"Total Fwd Packets\":19,\"Total Backward Packets\":2,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":0,\"Fwd Packet Length Min\":0,\"Fwd Packet Length Std\":0,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":0,\"Flow Packets/s\":0,\"Flow IAT Mean\":5789965,\"Flow IAT Min\":0,\"Bwd IAT Total\":48,\"Bwd IAT Mean\":48,\"Bwd IAT Min\":48,\"Fwd Header Length\":380,\"Bwd Header Length\":40,\"Bwd Packets/s\":0,\"Max Packet Length\":0,\"Packet Length Std\":0,\"Packet Length Variance\":0,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":5840,\"Init_Win_bytes_backward\":0,\"min_seg_size_forward\":20,\"Active Mean\":244280,\"Active Std\":646237,\"Active Max\":1709809,\"Active Min\":1,\"Idle Std\":3220326,\"Inbound\":1}" > /dev/null
            elif [ "$attack_type" = "http_flood" ]; then
                curl -s -X POST "$DETECTOR" -H "Content-Type: application/json" \
                    -d "{\"Source Port\":53058,\"Destination Port\":80,\"Protocol\":6,\"Flow Duration\":115799309,\"Total Fwd Packets\":19,\"Total Backward Packets\":2,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":0,\"Fwd Packet Length Min\":0,\"Fwd Packet Length Std\":0,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":0,\"Flow Packets/s\":0,\"Flow IAT Mean\":5789965,\"Flow IAT Min\":0,\"Bwd IAT Total\":48,\"Bwd IAT Mean\":48,\"Bwd IAT Min\":48,\"Fwd Header Length\":380,\"Bwd Header Length\":40,\"Bwd Packets/s\":0,\"Max Packet Length\":0,\"Packet Length Std\":0,\"Packet Length Variance\":0,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":5840,\"Init_Win_bytes_backward\":0,\"min_seg_size_forward\":20,\"Active Mean\":244280,\"Active Std\":646237,\"Active Max\":1709809,\"Active Min\":1,\"Idle Std\":3220326,\"Inbound\":1}" > /dev/null
            elif [ "$attack_type" = "udp_flood" ]; then
                curl -s -X POST "$DETECTOR" -H "Content-Type: application/json" \
                    -d "{\"Source Port\":0,\"Destination Port\":53,\"Protocol\":17,\"Flow Duration\":100000,\"Total Fwd Packets\":1000,\"Total Backward Packets\":0,\"Total Length of Bwd Packets\":0,\"Fwd Packet Length Max\":100,\"Fwd Packet Length Min\":90,\"Fwd Packet Length Std\":5,\"Bwd Packet Length Max\":0,\"Bwd Packet Length Min\":0,\"Bwd Packet Length Mean\":0,\"Bwd Packet Length Std\":0,\"Flow Bytes/s\":1000000,\"Flow Packets/s\":10000,\"Flow IAT Mean\":10,\"Flow IAT Min\":5,\"Bwd IAT Total\":0,\"Bwd IAT Mean\":0,\"Bwd IAT Min\":0,\"Fwd Header Length\":20000,\"Bwd Header Length\":0,\"Bwd Packets/s\":0,\"Max Packet Length\":100,\"Packet Length Std\":5,\"Packet Length Variance\":25,\"Down/Up Ratio\":0,\"Init_Win_bytes_forward\":100,\"Init_Win_bytes_backward\":0,\"min_seg_size_forward\":100,\"Active Mean\":0,\"Active Std\":0,\"Active Max\":0,\"Active Min\":0,\"Idle Std\":0,\"Inbound\":0}" > /dev/null
            fi
            
            echo "[$(date '+%H:%M:%S')] ALERT: $attack_type detected (TCP=$total_tcp, SYN_RECV=$syn_recv, EST=$established, UDP=$total_udp, PPS=$pps_rx)"
        fi
    fi
    
    prev_tx=$tx; prev_rx=$rx; prev_time=$now
    sleep $INTERVAL
done
