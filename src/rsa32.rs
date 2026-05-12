//! 伺服器綑綁用的 RSA-32 金鑰生成
//!
//! 對齊 TGG EP6 server 端 Java 的小型 RSA：
//!   server 端 ClientThread 接受連線時 `random∈[255, 900000254]`，
//!   `authdata = random^E mod N`（4 bytes 小端送給客戶端）
//!   客戶端用 D 還原：`random = authdata^D mod N`
//!   取得 random 後 `xorByte = random%255 + 1`，後續封包 hi/lo bytes 用 xor 異或
//!
//! N 必須塞進 u32（Java `BigInteger.longValue()` 取低 64 位元，但範例值都 ≤ 2^31）。
//! 因此我們生成兩個 ~16-bit 質數 p, q，n = p*q ∈ [2^30, 2^32)。
//! 中間運算用 u128 避免溢位（n*n < 2^64）。

use std::time::{SystemTime, UNIX_EPOCH};

/// RSA-32 金鑰三元組
#[derive(Debug, Clone, Copy)]
pub struct Rsa32 {
    /// 公開加密指數（伺服器端使用）
    pub e: u32,
    /// 私密解密指數（客戶端使用）
    pub d: u32,
    /// 模數 N = p*q
    pub n: u32,
}

/// (a * b) mod m，避免 u64 溢位
fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128) * (b as u128) % (m as u128)) as u64
}

/// (base^exp) mod m
pub fn modpow(mut base: u64, mut exp: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
    let mut result = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mulmod(result, base, m);
        }
        exp >>= 1;
        base = mulmod(base, base, m);
    }
    result
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// 擴展歐幾里得：gcd(a,b) + (x,y) 使 a*x + b*y = g
fn ext_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, x1, y1) = ext_gcd(b, a % b);
        (g, y1, x1 - (a / b) * y1)
    }
}

/// 模反元素：a^-1 mod m，若 gcd(a,m)≠1 回 None
fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    let (g, x, _) = ext_gcd(a as i64, m as i64);
    if g != 1 {
        None
    } else {
        let m_i = m as i64;
        Some(((x % m_i + m_i) % m_i) as u64)
    }
}

/// 確定性 Miller-Rabin（n < 2^64 只需 12 個見證者即可正確判斷）
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for &p in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }
    let mut d = n - 1;
    let mut r = 0u32;
    while d & 1 == 0 {
        d >>= 1;
        r += 1;
    }
    'witness: for &a in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = modpow(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..r - 1 {
            x = mulmod(x, x, n);
            if x == n - 1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// 簡易 LCG 偽亂數（種子用 nanos + 自增，不需密碼學等級）
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x12345678);
        Self {
            state: nanos.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1),
        }
    }

    fn next(&mut self) -> u64 {
        // SplitMix64
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

/// 在 [40000, 65535] 範圍找一個 ~16-bit 質數（保證 p*q ≥ 2^30）
fn random_prime_16bit(rng: &mut Lcg) -> u64 {
    loop {
        let mut n = rng.range(40000, 65536);
        n |= 1;
        if is_prime(n) {
            return n;
        }
    }
}

/// 產生 RSA-32 金鑰：N ∈ [2^30, 2^32)，E、D 也 < N
pub fn generate() -> Rsa32 {
    let mut rng = Lcg::new();
    loop {
        let p = random_prime_16bit(&mut rng);
        let q = loop {
            let qq = random_prime_16bit(&mut rng);
            if qq != p {
                break qq;
            }
        };
        let n = p * q;
        if n > u32::MAX as u64 {
            continue;
        }
        if n < (1u64 << 30) {
            continue;
        }
        let phi = (p - 1) * (q - 1);
        // 隨機挑 d，gcd(d, phi) = 1，並且 1 < d < phi
        for _ in 0..1024 {
            let d = rng.range(3, phi);
            if d & 1 == 0 {
                continue;
            }
            if gcd(d, phi) != 1 {
                continue;
            }
            let e = match mod_inverse(d, phi) {
                Some(x) if x > 1 && x < phi => x,
                _ => continue,
            };
            // 自我驗證：random^E^D mod N == random
            let probe = (n / 7).max(2);
            let cipher = modpow(probe, e, n);
            let plain = modpow(cipher, d, n);
            if plain == probe {
                return Rsa32 {
                    e: e as u32,
                    d: d as u32,
                    n: n as u32,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miller_rabin_basic() {
        assert!(is_prime(2));
        assert!(is_prime(65537));
        assert!(is_prime(2_001_201_551 / 41953)); // example N's q-prime guess
        assert!(!is_prime(1));
        assert!(!is_prime(100));
        assert!(!is_prime(65536));
    }

    /// 例子：E=628624543, N=2001201551, D=1424206015
    /// 驗證 random^E mod N → cipher → cipher^D mod N == random
    #[test]
    fn example_rsa_roundtrip() {
        let e: u64 = 628_624_543;
        let d: u64 = 1_424_206_015;
        let n: u64 = 2_001_201_551;
        for &r in &[255u64, 12345, 0x1234567, 900_000_254] {
            let c = modpow(r, e, n);
            let p = modpow(c, d, n);
            assert_eq!(p, r, "RSA roundtrip 失敗 r={r}");
        }
    }

    #[test]
    fn generated_keys_roundtrip() {
        for _ in 0..5 {
            let k = generate();
            let n_u = k.n as u64;
            assert!(n_u >= (1u64 << 30));
            assert!(n_u <= u32::MAX as u64);
            for &r in &[255u64, 0xABCD1234u64 % (n_u - 1), n_u / 2, n_u - 2] {
                let c = modpow(r, k.e as u64, n_u);
                let p = modpow(c, k.d as u64, n_u);
                assert_eq!(p, r, "k={k:?} r={r}");
            }
        }
    }
}
