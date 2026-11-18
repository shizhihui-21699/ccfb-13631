// 公共部分:包格式、哈希链、MAC、检查点签名
//
// 认证结构(TESLA 变体):
//   密钥链: K_i = SHA256(K_{i+1}),发送端预生成,正向使用 K_0, K_1, ...
//   数据包: type | seq | interval | disclosed_key(K_{interval-d}) | mac | payload
//   mac = HMAC-SHA256(K_interval, seq || interval || payload)
//   检查点: type | interval | K_interval | t0_us | interval_us | d | Ed25519签名
//   签名消息 = b"TESLA-CKPT-v1" || 上述各字段

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub type Key = [u8; 32];
pub const ZERO_KEY: Key = [0u8; 32];

pub const MSG_DATA: u8 = 1;
pub const MSG_CHECKPOINT: u8 = 2;

pub const PAYLOAD_LEN: usize = 64;
// type(1) seq(8) interval(8) disclosed(32) mac(32) payload(64)
pub const DATA_LEN: usize = 1 + 8 + 8 + 32 + 32 + PAYLOAD_LEN;
// type(1) interval(8) key(32) t0(8) interval_us(8) d(8) sig(64)
pub const CKPT_BODY_LEN: usize = 8 + 32 + 8 + 8 + 8;
pub const CKPT_LEN: usize = 1 + CKPT_BODY_LEN + 64;

pub const MAGIC_MKT: &[u8; 8] = b"MKTDATA1";
pub const MAGIC_FORGED: &[u8; 8] = b"FORGED!!";
// 攻击端使用的 seq 命名空间,避免与发送端 seq 冲突干扰去重统计
pub const ATTACK_SEQ_BASE: u64 = 0xFFFF_0000_0000_0000;

pub fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

pub fn interval_of(t0_us: u64, now_us: u64, interval_us: u64) -> u64 {
    now_us.saturating_sub(t0_us) / interval_us
}

pub fn hash_key(k: &Key) -> Key {
    let mut h = Sha256::new();
    h.update(k);
    h.finalize().into()
}

/// 生成 len 把钥匙的链:chain[i] = K_i,K_i = H(K_{i+1}),链尾随机
pub fn build_chain(len: usize) -> Vec<Key> {
    let mut v = vec![[0u8; 32]; len];
    v[len - 1] = rand::random::<Key>();
    for i in (0..len - 1).rev() {
        v[i] = hash_key(&v[i + 1]);
    }
    v
}

pub fn mac_bytes(key: &Key, seq: u64, interval: u64, payload: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(&seq.to_le_bytes());
    m.update(&interval.to_le_bytes());
    m.update(payload);
    m.finalize().into_bytes().into()
}

#[derive(Clone)]
pub struct DataPkt {
    pub seq: u64,
    pub interval: u64,
    pub disclosed: Key,
    pub mac: [u8; 32],
    pub payload: [u8; PAYLOAD_LEN],
}

pub fn encode_data(p: &DataPkt) -> [u8; DATA_LEN] {
    let mut b = [0u8; DATA_LEN];
    b[0] = MSG_DATA;
    b[1..9].copy_from_slice(&p.seq.to_le_bytes());
    b[9..17].copy_from_slice(&p.interval.to_le_bytes());
    b[17..49].copy_from_slice(&p.disclosed);
    b[49..81].copy_from_slice(&p.mac);
    b[81..].copy_from_slice(&p.payload);
    b
}

pub fn decode_data(b: &[u8]) -> Option<DataPkt> {
    if b.len() != DATA_LEN || b[0] != MSG_DATA {
        return None;
    }
    let mut p = DataPkt {
        seq: u64::from_le_bytes(b[1..9].try_into().unwrap()),
        interval: u64::from_le_bytes(b[9..17].try_into().unwrap()),
        disclosed: [0; 32],
        mac: [0; 32],
        payload: [0; PAYLOAD_LEN],
    };
    p.disclosed.copy_from_slice(&b[17..49]);
    p.mac.copy_from_slice(&b[49..81]);
    p.payload.copy_from_slice(&b[81..]);
    Some(p)
}

pub struct Ckpt {
    pub interval: u64,
    pub key: Key,
    pub t0_us: u64,
    pub interval_us: u64,
    pub d: u64,
    pub sig: [u8; 64],
}

pub fn ckpt_signing_msg(body: &[u8; CKPT_BODY_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(13 + CKPT_BODY_LEN);
    v.extend_from_slice(b"TESLA-CKPT-v1");
    v.extend_from_slice(body);
    v
}

pub fn encode_ckpt(c: &Ckpt) -> [u8; CKPT_LEN] {
    let mut b = [0u8; CKPT_LEN];
    b[0] = MSG_CHECKPOINT;
    b[1..9].copy_from_slice(&c.interval.to_le_bytes());
    b[9..41].copy_from_slice(&c.key);
    b[41..49].copy_from_slice(&c.t0_us.to_le_bytes());
    b[49..57].copy_from_slice(&c.interval_us.to_le_bytes());
    b[57..65].copy_from_slice(&c.d.to_le_bytes());
    b[65..129].copy_from_slice(&c.sig);
    b
}

pub fn decode_ckpt(b: &[u8]) -> Option<Ckpt> {
    if b.len() != CKPT_LEN || b[0] != MSG_CHECKPOINT {
        return None;
    }
    let mut c = Ckpt {
        interval: u64::from_le_bytes(b[1..9].try_into().unwrap()),
        key: [0; 32],
        t0_us: u64::from_le_bytes(b[41..49].try_into().unwrap()),
        interval_us: u64::from_le_bytes(b[49..57].try_into().unwrap()),
        d: u64::from_le_bytes(b[57..65].try_into().unwrap()),
        sig: [0; 64],
    };
    c.key.copy_from_slice(&b[9..41]);
    c.sig.copy_from_slice(&b[65..129]);
    Some(c)
}

/// 简单 xorshift,用于接收端模拟丢包/攻击端随机化,避免每包走 rand
pub struct XorShift(pub u64);
impl XorShift {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

pub fn opt(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| default.to_string())
}
