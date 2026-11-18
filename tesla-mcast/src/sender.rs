// 发送端:组播行情 + TESLA 认证
// 每包只做 1 次 HMAC;每 ckpt_every 个槽做 1 次 Ed25519 签名(检查点,重复发 3 份抗丢包)

use crate::common::*;
use ed25519_dalek::{Signer, SigningKey};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let group: Ipv4Addr = opt(args, "--group", "239.255.42.99").parse()?;
    let port: u16 = opt(args, "--port", "5000").parse()?;
    let rate: f64 = opt(args, "--rate", "20000").parse()?;
    let interval_us: u64 = (opt(args, "--interval-ms", "100").parse::<f64>()? * 1000.0) as u64;
    let d: u64 = opt(args, "--delay", "2").parse()?;
    let chain_len: usize = opt(args, "--chain", "500000").parse()?;
    let ckpt_every: u64 = opt(args, "--ckpt-every", "20").parse()?;

    eprintln!(
        "[sender] group={group}:{port} rate={rate}/s interval={}us d={d} chain={chain_len} ckpt_every={ckpt_every}",
        interval_us
    );

    eprintln!("[sender] building hash chain ({chain_len} keys)...");
    let t = Instant::now();
    let chain = build_chain(chain_len);
    eprintln!("[sender] chain built in {:?}", t.elapsed());

    let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    std::fs::write("sender.pub", sk.verifying_key().to_bytes())?;
    eprintln!("[sender] wrote sender.pub (pinned verification key for receivers)");

    // 组播发送 socket,走 loopback 接口
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    sock.set_multicast_if_v4(&Ipv4Addr::LOCALHOST)?;
    sock.set_multicast_ttl_v4(1)?;
    let sock: UdpSocket = sock.into();
    let dest = SocketAddr::from((group, port));

    let t0_us = now_micros();
    let start = Instant::now();
    let period = Duration::from_secs_f64(1.0 / rate);
    let mut next = start;

    let mut seq: u64 = 0;
    let mut last_ckpt = u64::MAX;
    let mut ckpts: u64 = 0;
    let mut mac_ns: u128 = 0;
    let mut sig_ns: u128 = 0;
    let mut last_report = start;
    let mut sent_at_report: u64 = 0;

    loop {
        let now_us = now_micros();
        let interval = interval_of(t0_us, now_us, interval_us);
        if interval as usize >= chain_len {
            eprintln!("[sender] hash chain exhausted at interval {interval}, stopping");
            break;
        }

        // 检查点:对 (interval, K_interval, t0, 参数) 签名,重复 3 份
        if interval % ckpt_every == 0 && last_ckpt != interval {
            let mut body = [0u8; CKPT_BODY_LEN];
            body[0..8].copy_from_slice(&interval.to_le_bytes());
            body[8..40].copy_from_slice(&chain[interval as usize]);
            body[40..48].copy_from_slice(&t0_us.to_le_bytes());
            body[48..56].copy_from_slice(&interval_us.to_le_bytes());
            body[56..64].copy_from_slice(&d.to_le_bytes());
            let msg = ckpt_signing_msg(&body);
            let ts = Instant::now();
            let sig = sk.sign(&msg);
            sig_ns += ts.elapsed().as_nanos();
            let c = Ckpt {
                interval,
                key: chain[interval as usize],
                t0_us,
                interval_us,
                d,
                sig: sig.to_bytes(),
            };
            let pkt = encode_ckpt(&c);
            for _ in 0..3 {
                let _ = sock.send_to(&pkt, dest);
            }
            ckpts += 1;
            last_ckpt = interval;
        }

        let key = &chain[interval as usize];
        let disclosed = if interval >= d {
            chain[(interval - d) as usize]
        } else {
            ZERO_KEY
        };

        // 模拟行情 payload
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0..8].copy_from_slice(MAGIC_MKT);
        payload[8..16].copy_from_slice(&seq.to_le_bytes());
        payload[16..24].copy_from_slice(&now_us.to_le_bytes());
        let mut x = seq ^ 0x9e37_79b9_7f4a_7c15;
        for chunk in payload[24..].chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            chunk.copy_from_slice(&x.to_le_bytes());
        }

        let ts = Instant::now();
        let mac = mac_bytes(key, seq, interval, &payload);
        mac_ns += ts.elapsed().as_nanos();

        let pkt = encode_data(&DataPkt {
            seq,
            interval,
            disclosed,
            mac,
            payload,
        });
        sock.send_to(&pkt, dest)?;
        seq += 1;

        //  pacing:粗睡 + 自旋
        next += period;
        loop {
            let now = Instant::now();
            if now >= next {
                break;
            }
            let rem = next - now;
            if rem > Duration::from_micros(500) {
                std::thread::sleep(rem / 2);
            } else {
                std::hint::spin_loop();
            }
        }

        if last_report.elapsed() >= Duration::from_secs(2) {
            let dt = last_report.elapsed().as_secs_f64();
            let pps = (seq - sent_at_report) as f64 / dt;
            eprintln!(
                "[sender] sent={seq} pps={pps:.0} mac_avg={:.0}ns sig_avg={:.1}us ckpts={ckpts}",
                mac_ns as f64 / seq.max(1) as f64,
                sig_ns as f64 / ckpts.max(1) as f64 / 1000.0,
            );
            sent_at_report = seq;
            last_report = Instant::now();
            std::io::stderr().flush().ok();
        }
    }
    Ok(())
}
