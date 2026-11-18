// 攻击端:位于同一局域网,加入组播组嗅探流量,并向组里注入伪造包
// 四种攻击轮换:
//   1. garbage :随机 MAC 的伪造包(当前槽)——应被 mac-fail 拒绝
//   2. tamper  :篡改捕获的真实包 payload,保留原 MAC——应被 mac-fail 拒绝
//   3. old-key :用已披露的真实旧钥匙 K_j 伪造 j 槽的包(MAC 完全合法!)
//               ——应被时效检查(stale)拒绝,这是 TESLA 的核心防线
//   4. replay  :原样重放捕获的真实包——应被去重(duplicate)拒绝

use crate::common::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let group: Ipv4Addr = opt(args, "--group", "239.255.42.99").parse()?;
    let port: u16 = opt(args, "--port", "5000").parse()?;
    let rate: f64 = opt(args, "--rate", "2000").parse()?;
    let d: u64 = opt(args, "--delay", "2").parse()?; // 公开参数,攻击者可知

    // 嗅探 socket:加入组播组
    let sniff = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sniff.set_reuse_address(true)?;
    sniff.set_reuse_port(true)?;
    sniff.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    sniff.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST)?;
    let _ = sniff.set_recv_buffer_size(8 << 20);
    let sniff: UdpSocket = sniff.into();
    sniff.set_nonblocking(true)?;

    // 注入 socket(必须显式指定组播出接口,否则默认走 en0,环回接收端收不到)
    let inj = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    inj.set_multicast_if_v4(&Ipv4Addr::LOCALHOST)?;
    let inject: UdpSocket = inj.into();
    let dest = SocketAddr::from((group, port));

    eprintln!("[attacker] sniffing {group}:{port}, injecting at {rate}/s");

    let mut rng = XorShift(0xdead_beef_cafe_f00d);
    let mut latest_interval: u64 = 0;
    let mut latest_disclosed: Key = ZERO_KEY;
    let mut captured: VecDeque<[u8; DATA_LEN]> = VecDeque::with_capacity(128);

    let mut sniffed = 0u64;
    let mut sent = [0u64; 4]; // garbage, tamper, old-key, replay

    let period = Duration::from_secs_f64(1.0 / rate);
    let start = Instant::now();
    let mut next = start;
    let mut last_report = start;
    let mut round = 0usize;
    let mut buf = [0u8; 2048];

    loop {
        // 尽量排空嗅探队列
        loop {
            match sniff.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if n == DATA_LEN && buf[0] == MSG_DATA {
                        sniffed += 1;
                        if let Some(p) = decode_data(&buf[..n]) {
                            if p.interval >= latest_interval {
                                latest_interval = p.interval;
                                latest_disclosed = p.disclosed;
                            }
                            if captured.len() == 128 {
                                captured.pop_front();
                            }
                            let mut raw = [0u8; DATA_LEN];
                            raw.copy_from_slice(&buf[..n]);
                            captured.push_back(raw);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        if Instant::now() >= next && latest_interval > d {
            let attack = round % 4;
            round += 1;
            let pkt: Vec<u8> = match attack {
                0 => {
                    // garbage: 当前槽 + 随机钥匙 + 随机 MAC
                    let mut payload = [0u8; PAYLOAD_LEN];
                    payload[0..8].copy_from_slice(MAGIC_FORGED);
                    for c in payload[8..].chunks_mut(8) {
                        c.copy_from_slice(&rng.next().to_le_bytes());
                    }
                    encode_data(&DataPkt {
                        seq: ATTACK_SEQ_BASE | (rng.next() & 0xFFFF_FFFF),
                        interval: latest_interval,
                        disclosed: rand::random(),
                        mac: rand::random(),
                        payload,
                    })
                    .to_vec()
                }
                1 => {
                    // tamper: 真实包翻转 payload 一字节
                    match captured.back() {
                        Some(raw) => {
                            let mut p = *raw;
                            p[100] ^= 0x01;
                            p.to_vec()
                        }
                        None => continue,
                    }
                }
                2 => {
                    // old-key: 用已披露的真钥匙 K_j 造 j 槽的包,MAC 合法
                    let j = latest_interval - d;
                    let mut payload = [0u8; PAYLOAD_LEN];
                    payload[0..8].copy_from_slice(MAGIC_FORGED);
                    for c in payload[8..].chunks_mut(8) {
                        c.copy_from_slice(&rng.next().to_le_bytes());
                    }
                    let seq = ATTACK_SEQ_BASE | (rng.next() & 0xFFFF_FFFF);
                    let mac = mac_bytes(&latest_disclosed, seq, j, &payload);
                    encode_data(&DataPkt {
                        seq,
                        interval: j,
                        disclosed: ZERO_KEY,
                        mac,
                        payload,
                    })
                    .to_vec()
                }
                _ => {
                    // replay: 原样重放
                    match captured.back() {
                        Some(raw) => raw.to_vec(),
                        None => continue,
                    }
                }
            };
            let _ = inject.send_to(&pkt, dest);
            sent[attack] += 1;
            next += period;
        }

        if last_report.elapsed() >= Duration::from_secs(2) {
            eprintln!(
                "[attacker] sniffed={sniffed} injected: garbage={} tamper={} old-key={} replay={}",
                sent[0], sent[1], sent[2], sent[3]
            );
            last_report = Instant::now();
        }

        std::thread::sleep(Duration::from_micros(200));
    }
}
