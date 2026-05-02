import time
import requests
from collections import defaultdict

DETECTOR_URL = "http://nids-detector:8080/predict"
POLL_INTERVAL = 1.0
MIN_CONNECTIONS = 3

def hex_ip(h):
    return ".".join(str(int(h[i:i+2], 16)) for i in (6,4,2,0))

def parse_proc_tcp():
    targets = defaultdict(lambda: {
        "total": 0, "syn_sent": 0, "established": 0,
        "time_wait": 0, "syn_recv": 0, "fin_wait": 0,
        "close_wait": 0, "first_seen": time.time(),
    })
    try:
        with open("/proc/net/tcp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                remote = parts[2]
                state = parts[3]

                rip, rport = remote.split(":")
                rip = hex_ip(rip)
                rport = int(rport, 16)
                if rport == 0:
                    continue

                key = (rip, rport, 6)
                t = targets[key]
                t["total"] += 1
                if state == "02":
                    t["syn_sent"] += 1
                elif state == "01":
                    t["established"] += 1
                elif state == "06":
                    t["time_wait"] += 1
                elif state == "03":
                    t["syn_recv"] += 1
                elif state in ("04", "05"):
                    t["fin_wait"] += 1
                elif state == "08":
                    t["close_wait"] += 1
    except:
        pass

    try:
        with open("/proc/net/udp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                remote = parts[2]
                rip, rport = remote.split(":")
                rip = hex_ip(rip)
                rport = int(rport, 16)
                if rport == 0:
                    continue
                key = (rip, rport, 17)
                targets[key]["total"] += 1
    except:
        pass
    return targets

def build_features(key, t):
    rip, rport, proto = key
    duration = max(time.time() - t["first_seen"], 0.001)
    n = max(t["total"], 1)

    syn_ratio = t["syn_sent"] / n
    est_ratio = t["established"] / n
    tw_ratio = t["time_wait"] / n

    is_syn_flood = syn_ratio > 0.5 and t["syn_sent"] > 2
    is_http_flood = rport == 80 and est_ratio > 0.3 and t["established"] > 2
    is_udp_flood = proto == 17 and t["total"] > 3

    if is_syn_flood:
        fwd_pkt, bwd_pkt = 54, 0
        iat = 0.0005
    elif is_http_flood:
        fwd_pkt, bwd_pkt = 200, 500
        iat = duration / max(n, 1)
    elif is_udp_flood:
        fwd_pkt, bwd_pkt = 100, 0
        iat = duration / max(n, 1)
    else:
        fwd_pkt, bwd_pkt = 100, 50
        iat = duration / max(n, 1)

    pkt_count = t["total"] * 3
    return {
        "Source Port": 0.0,
        "Destination Port": float(rport),
        "Protocol": float(proto),
        "Flow Duration": duration * 1e6,
        "Total Fwd Packets": float(pkt_count * 0.7),
        "Total Backward Packets": float(pkt_count * 0.3),
        "Total Length of Bwd Packets": float(pkt_count * 0.3 * bwd_pkt),
        "Fwd Packet Length Max": float(fwd_pkt * 1.1),
        "Fwd Packet Length Min": float(fwd_pkt * 0.9),
        "Fwd Packet Length Std": float(fwd_pkt * 0.05),
        "Bwd Packet Length Max": float(bwd_pkt * 1.1) if bwd_pkt > 0 else 0.0,
        "Bwd Packet Length Min": float(bwd_pkt * 0.9) if bwd_pkt > 0 else 0.0,
        "Bwd Packet Length Mean": float(bwd_pkt),
        "Bwd Packet Length Std": float(bwd_pkt * 0.05) if bwd_pkt > 0 else 0.0,
        "Flow Bytes/s": pkt_count * (fwd_pkt + bwd_pkt) / duration,
        "Flow Packets/s": pkt_count / duration,
        "Flow IAT Mean": float(iat),
        "Flow IAT Min": float(iat * 0.5),
        "Bwd IAT Total": float(iat * pkt_count * 0.3),
        "Bwd IAT Mean": float(iat),
        "Bwd IAT Min": float(iat * 0.5),
        "Fwd Header Length": float(pkt_count * 0.7 * fwd_pkt),
        "Bwd Header Length": float(pkt_count * 0.3 * bwd_pkt),
        "Bwd Packets/s": pkt_count * 0.3 / duration,
        "Max Packet Length": float(max(fwd_pkt, bwd_pkt)),
        "Packet Length Std": float(abs(fwd_pkt - bwd_pkt) * 0.5),
        "Packet Length Variance": float((fwd_pkt - bwd_pkt) ** 2 * 0.25),
        "Down/Up Ratio": float(bwd_pkt / fwd_pkt) if fwd_pkt > 0 else 0.0,
        "Init_Win_bytes_forward": float(fwd_pkt),
        "Init_Win_bytes_backward": float(bwd_pkt),
        "min_seg_size_forward": float(fwd_pkt),
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Std": 0.0,
        "Inbound": 0.0,
    }

def main():
    print("[*] Traffic Reporter started")
    print(f"[*] Monitoring /proc/net/tcp + /proc/net/udp every {POLL_INTERVAL}s")
    print(f"[*] Sending to {DETECTOR_URL}\n")

    seen = set()
    last_report = {}

    while True:
        targets = parse_proc_tcp()
        now = time.time()

        for key, t in targets.items():
            if t["total"] < MIN_CONNECTIONS:
                continue

            report_key = key + (int(t["total"] // 3),)
            if report_key in last_report and (now - last_report[report_key]) < 2.0:
                continue

            features = build_features(key, t)
            try:
                resp = requests.post(DETECTOR_URL, json=features, timeout=2)
                result = resp.json()

                if result.get("is_alert"):
                    sev = result.get("severity", "INFO")
                    pred = result.get("prediction", "?")
                    print(f"[ALERT] [{sev}] {pred} -> {key[0]}:{key[1]} "
                          f"(conf={result['confidence']}, model={result['model_used']}, "
                          f"conns={t['total']}, syn={t['syn_sent']}, est={t['established']})")
                else:
                    print(f"  [OK] {result.get('prediction', '?')} -> {key[0]}:{key[1]} "
                          f"(conns={t['total']})")

                last_report[report_key] = now
            except Exception as e:
                print(f"[!] Error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
