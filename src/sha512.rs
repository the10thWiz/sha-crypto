use digest::{Digest, FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update};

struct Sha512 {
    h: [u64; 8],
    buffer: [u8; 128],
    filled: u8,
    length: u128,
}

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

impl Sha512 {
    /// update state (self.h) using self.buffer.
    ///
    /// Assumes self.buffer is full
    fn run_round(&mut self) {
        //create a 64-entry message schedule array w[0..79] of 64-bit words
        let mut w = [0u64; 80];
        //(The initial values in w[0..79] don't matter, so many implementations zero them here)
        //copy chunk into first 16 words w[0..15] of the message schedule array
        self.buffer
            .chunks(8)
            .zip(w.iter_mut())
            .for_each(|(buf, w)| {
                *w = u64::from_be_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ])
            });

        //Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array:
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            //println!("s0 = {:032b}", s0);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            //println!("s1 = {:032b}", s1);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            //println!("w[16] = {:032b}", w[16]);
            //panic!();
        }
        //for i from 16 to 63
        //s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
        //s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        //w[i] := w[i-16] + s0 + w[i-7] + s1

        //Initialize working variables to current hash value:
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h.clone();
        //a := h0
        //b := h1
        //c := h2
        //d := h3
        //e := h4
        //f := h5
        //g := h6
        //h := h7

        //Compression function main loop:
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        //for i from 0 to 63
        //S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        //ch := (e and f) xor ((not e) and g)
        //temp1 := h + S1 + ch + k[i] + w[i]
        //S0 := (d rightrotdte 2) xor (d rightrotdte 13) xor (d rightrotdte 22)
        //maj := (a and b) xor (a and c) xor (b and c)
        //temp2 := S0 + maj

        //h := g
        //g := f
        //f := e
        //e := d + temp1
        //d := c
        //c := b
        //b := a
        //a := temp1 + temp2

        //Add the compressed chunk to the current hash value:
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

impl Update for Sha512 {
    fn update(&mut self, mut data: &[u8]) {
        self.length += data.len() as u128;
        let empty = &mut self.buffer[self.filled as usize..];
        let len = data.len().min(empty.len());
        empty[..len].copy_from_slice(&data[..len]);
        if self.filled + len as u8 == 128 {
            self.run_round();
            data = &data[len..];
            while data.len() >= 128 {
                self.buffer.copy_from_slice(&data[..128]);
                self.run_round();
                data = &data[128..];
            }
            self.buffer[..data.len()].copy_from_slice(data);
            self.filled = data.len() as u8;
        } else {
            self.filled += data.len() as u8;
        }
    }
}


impl FixedOutput for Sha512 {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        // TODO: padding message with nessecary bits.
        // Calc padding
        let mut filled = self.filled as usize;
        let length = self.length * 8;
        Update::update(&mut self, &[0b10000000]);
        //println!("With 1bit: {:X?}", self.buffer);
        //dbg!(self.filled);

        if filled > 128 - std::mem::size_of::<u128>() {
            Update::update(&mut self, &ZERO_BYTES[filled..]);
            filled = 0;
        }
        Update::update(&mut self, &ZERO_BYTES[filled..(128 - std::mem::size_of::<u128>() - 1)]);
        //println!("With K0s: {:X?}", self.buffer);
        //dbg!(self.filled);
        Update::update(&mut self, &length.to_be_bytes());

        out.iter_mut()
            .zip(self.h.iter().flat_map(|&h| h.to_be_bytes()))
            .for_each(|(out, s)| *out = s);
    }
}


const ZERO_BYTES: [u8; 128] = [0u8; 128];

impl Digest for Sha512 {
    fn new() -> Self {
        Self {
            h: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0; 128],
            filled: 0,
            length: 0,
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        <Self as Update>::update(self, data.as_ref())
    }

    fn finalize_into(self, out: &mut digest::Output<Self>) {
        FixedOutput::finalize_into(self, out)
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        Self::new().chain_update(data)
    }

    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::update(&mut self, data.as_ref());
        self
    }

    fn finalize(self) -> digest::Output<Self> {
        let mut tmp = digest::Output::<Self>::default();
        <Self as FixedOutput>::finalize_into(self, &mut tmp);
        tmp
    }

    fn output_size() -> usize {
        <Self as OutputSizeUser>::output_size()
    }

    fn digest(data: impl AsRef<[u8]>) -> digest::Output<Self> {
        let mut s = Self::new();
        <Self as Update>::update(&mut s, data.as_ref());
        s.finalize()
    }

    fn finalize_reset(&mut self) -> digest::Output<Self>
    where
        Self: digest::FixedOutputReset,
    {
        std::mem::replace(self, Self::new()).finalize()
    }

    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>)
    where
        Self: digest::FixedOutputReset,
    {
        <Self as FixedOutputReset>::finalize_into_reset(self, out);
    }

    fn reset(&mut self)
    where
        Self: digest::Reset,
    {
        *self = Self::new();
    }
}

impl OutputSizeUser for Sha512 {
    type OutputSize = digest::consts::U64;
}

impl Reset for Sha512 {
    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl FixedOutputReset for Sha512 {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        FixedOutput::finalize_into(std::mem::replace(self, Self::new()), out)
    }
}

#[cfg(test)]
mod tests {
    use digest::*;
    use rand::Rng;

    macro_rules! sha_test {
        ($i:literal) => {
            let s = $i;
            let my_res = super::Sha512::new().chain_update(s.as_bytes()).finalize();
            let ex_res = sha2::Sha512::new().chain_update(s.as_bytes()).finalize();
            assert_eq!(
                ex_res, my_res,
                concat!("Failed to hash `", $i, "` correctly")
            );
        };
    }

    #[test]
    fn simple() {
        sha_test!("hello world");
        sha_test!("Hello World!");
        sha_test!("");
        sha_test!("helloworld");
        sha_test!("Some nice string");
        sha_test!("Some nice string");
        sha_test!("Some nice string");
    }

    #[test]
    fn rand() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let buffer: Vec<_> = (0..10).map(|_| rng.gen::<u8>()).collect();
            let my_res = super::Sha512::new().chain_update(&buffer).finalize();
            let ex_res = sha2::Sha512::new().chain_update(&buffer).finalize();
            assert_eq!(ex_res, my_res, "Failed on random test");
        }
    }
}
