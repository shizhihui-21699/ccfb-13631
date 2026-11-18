// 接收端:加入组播组,缓存数据包,用披露的链上钥匙验证后交付
//
// 安全不变式:
//  1. 时效检查:仅当 本地当前槽 < 包槽 + d 时才缓存(此后 K_包槽 才可能被披露,
//     攻击者拿到披露钥匙时对应窗口已关闭)
//  2. 钥匙认证:披露的 K_j 必须哈希 (j - 已认证槽) 次后等于已认证钥匙
//  3. MAC 验证:K_interval 派生后逐包验 HMAC,通过才交付

use crate::common::*;
use ed25519_dalek::{Signature, VerifyingKey};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAX_CHAIN_STEPS: u64 = 200_000; // 防 DoS:单包诱导的哈希次数上限
const MAX_PENDING: usize = 200_000; // 防 DoS:缓存包数上限

struct Pending {
    seq: u64,
    mac: [u8; 32],
    payload: [u8; PAYLOAD_LEN],
    at: Instant,
}

#[derive(Default)]
struct Stats {
    datagrams: u64,
    sim_dropped: u64,
    pre_bootstrap: u64,
    ckpt_ok: u64,
    ckpt_bad: u64,
    stale: u64,
    chain_fail: u64,
    mac_fail: u64,
    authenticated: u64,
    duplicate: u64,
    forged_accepted: u64,
    evicted: u64,
    lat_us_sum: u128,
    lat_us_max: u64,
    verify_ns: u128,
    verify_n: u64,
    auth_seq_min: u64,
    auth_seq_max: u64,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let group: Ipv4Addr = opt(args, "--group", "239.255.42.99").parse()?;
    let port: u16 = opt(args, "--port", "5000").parse()?;
    let drop_p: f64 = opt(args, "--drop", "0").parse()?;
    let duration_s: f64 = opt(args, "--duration", "30").parse()?;

    let pk_bytes: [u8; 32] = std::fs::read("sender.pub")?
        .try_into()
        .map_err(|_| "sender.pub must be 32 bytes")?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)?;

    // 组播接收 socket
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    sock.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST)?;
    let _ = sock.set_recv_buffer_size(8 << 20);
    let sock: UdpSocket = sock.into();
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;

    eprintln!("[receiver] joined {group}:{port}, drop={drop_p}, duration={duration_s}s");

    let mut st = Stats::default();
    let mut rng = XorShift(0x1234_5678_9abc_def0);

    // 协议参数(来自已验证的检查点)
    let mut booted = false;
    let mut t0_us = 0u64;
    let mut interval_us = 1u64;
    let mut d = 0u64;

    let mut verified: (u64, Key) = (0, ZERO_KEY); // 已认证的最高槽钥匙
    let mut buffer: BTreeMap<u64, Vec<Pending>> = BTreeMap::new();
    let mut pending_n: usize = 0;
    let mut delivered: HashSet<u64> = HashSet::new();

    let start = Instant::now();
    let mut last_report = start;
    let mut buf = [0u8; 2048];

    // 用已认证的最高钥匙验证并交付所有 interval <= top 的缓存包
    macro_rules! drain {
        () => {{
            let (top_idx, top_key) = verified;
            let ivs: Vec<u64> = buffer.range(..=top_idx).map(|(k, _)| *k).collect();
            for iv in ivs {
                // 从 K_top 派生 K_iv:哈希 (top - iv) 次
                let mut k = top_key;
                for _ in 0..(top_idx - iv) {
                    k = hash_key(&k);
                }
                let pendings = buffer.remove(&iv).unwrap();
                pending_n -= pendings.len();
                for p in pendings {
                    let t = Instant::now();
                    let ok = mac_bytes(&k, p.seq, iv, &p.payload) == p.mac;
                    st.verify_ns += t.elapsed().as_nanos();
                    st.verify_n += 1;
                    if !ok {
                        st.mac_fail += 1;
                        continue;
                    }
                    if p.payload[0..8] == *MAGIC_FORGED || p.seq >= ATTACK_SEQ_BASE {
                        st.forged_accepted += 1; // 永远不应发生
                    }
                    if !delivered.insert(p.seq) {
                        st.duplicate += 1;
                        continue;
                    }
                    let lat = p.at.elapsed();
                    st.lat_us_sum += lat.as_micros();
                    st.lat_us_max = st.lat_us_max.max(lat.as_micros() as u64);
                    st.authenticated += 1;
                    if st.authenticated == 1 {
                        st.auth_seq_min = p.seq;
                        st.auth_seq_max = p.seq;
                    } else if p.seq < ATTACK_SEQ_BASE {
                        st.auth_seq_min = st.auth_seq_min.min(p.seq);
                        st.auth_seq_max = st.auth_seq_max.max(p.seq);
                    }
                }
            }
        }};
    }

    while start.elapsed().as_secs_f64() < duration_s {
        match sock.recv_from(&mut buf) {
            Ok((n, _src)) => {
                st.datagrams += 1;
                // 模拟网络丢包:在处理前均匀丢弃
                if drop_p > 0.0 && rng.f64() < drop_p {
                    st.sim_dropped += 1;
                    continue;
                }
                let pkt = &buf[..n];
                match pkt[0] {
                    MSG_DATA => {
                        let Some(p) = decode_data(pkt) else { continue };
                        if !booted {
                            st.pre_bootstrap += 1;
                            continue;
                        }
                        let cur = interval_of(t0_us, now_micros(), interval_us);
                        // 时效检查:K_interval 是否可能已经披露
                        if p.interval + d <= cur {
                            st.stale += 1;
                            continue;
                        }
                        // 尝试认证披露的钥匙 K_j (j = interval - d)
                        if p.interval >= d && p.disclosed != ZERO_KEY {
                            let j = p.interval - d;
                            if j > verified.0 && j - verified.0 <= MAX_CHAIN_STEPS {
                                let mut k = p.disclosed;
                                for _ in 0..(j - verified.0) {
                                    k = hash_key(&k);
                                }
                                if k == verified.1 {
                                    verified = (j, p.disclosed);
                                    drain!();
                                } else {
                                    st.chain_fail += 1;
                                }
                            }
                        }
                        // 缓存当前包(它的钥匙要等 d 个槽后才披露)
                        if pending_n >= MAX_PENDING {
                            if let Some((&oldest, _)) = buffer.iter().next() {
                                if let Some(v) = buffer.remove(&oldest) {
                                    st.evicted += v.len() as u64;
                                    pending_n -= v.len();
                                }
                            }
                        }
                        pending_n += 1;
                        buffer.entry(p.interval).or_default().push(Pending {
                            seq: p.seq,
                            mac: p.mac,
                            payload: p.payload,
                            at: Instant::now(),
                        });
                    }
                    MSG_CHECKPOINT => {
                        let Some(c) = decode_ckpt(pkt) else { continue };
                        let mut body = [0u8; CKPT_BODY_LEN];
                        body[0..8].copy_from_slice(&c.interval.to_le_bytes());
                        body[8..40].copy_from_slice(&c.key);
                        body[40..48].copy_from_slice(&c.t0_us.to_le_bytes());
                        body[48..56].copy_from_slice(&c.interval_us.to_le_bytes());
                        body[56..64].copy_from_slice(&c.d.to_le_bytes());
                        let msg = ckpt_signing_msg(&body);
                        let sig = Signature::from_bytes(&c.sig);
                        if vk.verify_strict(&msg, &sig).is_err() {
                            st.ckpt_bad += 1;
                            continue;
                        }
                        if !booted || c.interval > verified.0 {
                            t0_us = c.t0_us;
                            interval_us = c.interval_us;
                            d = c.d;
                            booted = true;
                            verified = (c.interval, c.key);
                            st.ckpt_ok += 1;
                            drain!();
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => {}
        }

        if last_report.elapsed() >= Duration::from_secs(2) {
            eprintln!(
                "[receiver] dgrams={} auth={} stale={} mac_fail={} chain_fail={} dup={} forged_ok={} pend={}",
                st.datagrams, st.authenticated, st.stale, st.mac_fail, st.chain_fail,
                st.duplicate, st.forged_accepted, pending_n
            );
            last_report = Instant::now();
        }
    }

    // 汇总
    let elapsed = start.elapsed().as_secs_f64();
    let span = st.auth_seq_max.saturating_sub(st.auth_seq_min) + 1;
    let implied_loss = if span > 0 && st.authenticated > 0 {
        1.0 - (st.authenticated as f64 / span as f64)
    } else {
        0.0
    };
    println!("\n=== receiver summary ({elapsed:.1}s) ===");
    println!("datagrams received:      {}", st.datagrams);
    println!("simulated drops:         {} ({:.1}%)", st.sim_dropped,
        100.0 * st.sim_dropped as f64 / st.datagrams.max(1) as f64);
    println!("checkpoints ok/bad-sig:  {}/{}", st.ckpt_ok, st.ckpt_bad);
    println!("authenticated+delivered: {}", st.authenticated);
    println!("duplicates (replays):    {}", st.duplicate);
    println!("rejected stale (old-key attack window closed): {}", st.stale);
    println!("rejected mac-fail (forgery/tamper):            {}", st.mac_fail);
    println!("rejected chain-fail (bad disclosed key):       {}", st.chain_fail);
    println!("pre-bootstrap dropped:   {}", st.pre_bootstrap);
    println!("evicted (buffer cap):    {}", st.evicted);
    println!("FORGED ACCEPTED:         {}  <-- 必须为 0", st.forged_accepted);
    println!("sender seq span [{}..{}], implied loss (sim+real): {:.2}%",
        st.auth_seq_min, st.auth_seq_max, 100.0 * implied_loss);
    if st.authenticated > 0 {
        println!("auth latency (recv->verified): avg {:.1} ms, max {:.1} ms",
            st.lat_us_sum as f64 / st.authenticated as f64 / 1000.0,
            st.lat_us_max as f64 / 1000.0);
    }
    if st.verify_n > 0 {
        println!("verify cpu: avg {:.2} us/pkt ({} pkts)",
            st.verify_ns as f64 / st.verify_n as f64 / 1000.0, st.verify_n);
    }
    println!("residual buffered (unverifiable, stream ended): {}", pending_n);
    Ok(())
}
