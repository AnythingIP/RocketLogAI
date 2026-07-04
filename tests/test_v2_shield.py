"""Tests for RocketShield."""

from logsentinel.shield.waf import WAFEngine
from logsentinel.shield.av_scanner import AVScanner


def test_waf_blocks_sqli():
    waf = WAFEngine(block_mode="block")
    result = waf.inspect({
        "url": "/api?id=1 UNION SELECT password FROM users",
        "body": "",
        "source_ip": "10.0.0.1",
    })
    assert result["allowed"] is False
    assert len(result["matches"]) >= 1


def test_av_detects_eicar():
    av = AVScanner()
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    result = av.scan_payload(eicar)
    assert result["clean"] is False
    assert any(t["signature"] == "eicar" for t in result["threats"])