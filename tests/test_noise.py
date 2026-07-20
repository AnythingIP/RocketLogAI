"""False-positive / AP-flow noise classifiers."""

from logsentinel.noise import (
    is_ap_flow_log,
    should_skip_llm,
    is_likely_false_positive_threat,
    filter_threats,
)


def test_ap_flow_detected():
    msg = (
        "[1784439818.76] AP MAC=14:eb:b6:a6:d6:f8 MAC SRC=04:99:b9:9c:ac:91 "
        "IP SRC=192.168.20.39 IP DST=192.168.20.108 IP proto=6 SPT=49574 DPT=51980"
    )
    assert is_ap_flow_log(msg)
    assert should_skip_llm({"message": msg, "raw": msg})


def test_syn_flood_fp():
    t = {
        "severity": "high",
        "score": 8.5,
        "description": "Potential TCP SYN Flood attack from IP 192.168.20.39 to 192.168.20.108",
        "evidence": [
            "AP MAC=14:eb:b6:a6:d6:f8 MAC SRC=04:99:b9:9c:ac:91 "
            "IP SRC=192.168.20.39 IP DST=192.168.20.108 IP proto=6 SPT=49574 DPT=51980"
        ],
    }
    fp, reason = is_likely_false_positive_threat(t)
    assert fp
    assert reason == "unifi_ap_flow_accounting"


def test_icmp_lan_fp():
    t = {
        "description": "Potential ICMP echo request attack from IP 192.168.20.80 to 192.168.20.1",
        "evidence": [
            "AP MAC=9c:a2:f4:f0:2f:0a MAC SRC=70:c9:32:50:ea:a6 "
            "IP SRC=192.168.20.80 IP DST=192.168.20.1 IP proto=1"
        ],
    }
    fp, reason = is_likely_false_positive_threat(t)
    assert fp


def test_real_ssh_not_fp():
    t = {
        "description": "SSH brute force: 40 failed passwords for root from 203.0.113.50",
        "evidence": [
            "Failed password for root from 203.0.113.50 port 55822 ssh2",
            "Failed password for root from 203.0.113.50 port 55823 ssh2",
        ],
        "hostname": "server01",
        "appname": "sshd",
    }
    fp, _ = is_likely_false_positive_threat(t)
    assert not fp


def test_filter_threats_splits():
    kept, dropped = filter_threats(
        [
            {
                "description": "SYN flood",
                "evidence": ["AP MAC=aa:bb:cc:dd:ee:ff IP SRC=192.168.1.2 IP DST=192.168.1.3 IP proto=6"],
            },
            {
                "description": "Failed password for admin from 198.51.100.9",
                "evidence": ["Failed password for admin from 198.51.100.9 port 22"],
            },
        ]
    )
    assert len(dropped) == 1
    assert len(kept) == 1
