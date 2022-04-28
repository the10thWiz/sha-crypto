use digest::{Digest, FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update};

/// The different SHA2 algorithms
mod sha224;
mod sha384;
mod sha512;

/// Struct for SHA256
struct Sha256 {
    h: [u32; 8],
    buffer: [u8; 64],
    filled: u8,
    length: u64,
}

/// Array of round constants. They are the first 32 bits of the cube roots of the first 64 primes in hex form
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    /// Update state (self.h) using self.buffer.
    ///
    /// Assumes self.buffer is full
    fn run_round(&mut self) {
        // Create a 64-entry message schedule array w[0..63] of 32-bit words
        let mut w = [0u32; 64];
        // The initial values in w[0..63] don't matter, so many implementations zero them here
        // Copy chunk into first 16 words w[0..15] of the message schedule array
        self.buffer
            .chunks(4)
            .zip(w.iter_mut())
            .for_each(|(buf, w)| *w = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);

            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables to current hash value:
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h.clone();

        // Compression function main loop:
        for i in 0..64 {
            // Perform linear manipulation to shuffle the data further
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            // Assign results to temp variables
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value:
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

/// Updates the struct variables for the SHA256 hash
/// Specifically, it calculates the length, buffer and filled variables
impl Update for Sha256 {
    fn update(&mut self, mut data: &[u8]) {
        // Define variables
        self.length += data.len() as u64;
        let empty = &mut self.buffer[self.filled as usize..];
        let len = data.len().min(empty.len());
        empty[..len].copy_from_slice(&data[..len]);

        // Make sure we have enough bits
        if self.filled + len as u8 == 64 {
            self.run_round();
            data = &data[len..];

            // Break up the data into 64 bit chunks if needed
            while data.len() >= 64 {
                self.buffer.copy_from_slice(&data[..64]);
                self.run_round();
                data = &data[64..];
            }
            self.buffer[..data.len()].copy_from_slice(data);
            self.filled = data.len() as u8;
        } else {
            self.filled += data.len() as u8;
        }
    }
}

// A list of zero bytes
const ZERO_BYTES: [u8; 64] = [0u8; 64];

/// Split up and pad the original message ahead of time for processing
impl FixedOutput for Sha256 {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        // Calculate padding
        let mut filled = self.filled as usize;
        let length = self.length * 8;
        Update::update(&mut self, &[0b10000000]);

        // Update the struct
        if filled > 64 - 8 {
            Update::update(&mut self, &ZERO_BYTES[filled..]);
            filled = 0;
        }

        Update::update(&mut self, &ZERO_BYTES[filled..(64 - 8 - 1)]);
        Update::update(&mut self, &length.to_be_bytes());

        out.iter_mut()
            .zip(self.h.iter().flat_map(|&h| h.to_be_bytes()))
            .for_each(|(out, s)| *out = s);
    }
}

/// Defines useful functions for our SHA256 struct
impl Digest for Sha256 {
    // Instantiate struct with the first 32 bits of the fractional parts of the square roots of the first 8 primes
    fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    // Helper methods to make our hash function simpler and more compact
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

/// Defines the output size
impl OutputSizeUser for Sha256 {
    type OutputSize = digest::consts::U32;
}

/// Reset function for our hash algorithm
impl Reset for Sha256 {
    fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Reset our algorithm's output
impl FixedOutputReset for Sha256 {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        FixedOutput::finalize_into(std::mem::replace(self, Self::new()), out)
    }
}

/// Main function, not used
fn main() {
    println!("Welcome to our SHA2 family implementation!");
}

/// Tests for our SHA256 implementation
#[cfg(test)]
mod tests {
    use digest::*;
    use rand::Rng;

    // Hash the given string with our algorithm and Rust's SHA256 algorithm
    // If they are equal then we successfully hashed the string
    macro_rules! sha_test {
        ($i:literal) => {
            let s = $i;
            let my_res = crate::Sha256::new().chain_update(s.as_bytes()).finalize();
            let ex_res = sha2::Sha256::new().chain_update(s.as_bytes()).finalize();
            assert_eq!(
                ex_res, my_res,
                concat!("Failed to hash `", $i, "` correctly")
            );
        };
    }

    // Simple string tests
    #[test]
    fn simple() {
        sha_test!("hello world");
        sha_test!("Hello World!");
        sha_test!("");
        sha_test!("helloworld");
        sha_test!("Some nice string");
        sha_test!("Trying some numbers: 1234");
        sha_test!("5678");
    }

    // Randomly generate a list of numbers, hash them and check for equality
    #[test]
    fn rand() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let buffer: Vec<_> = (0..10).map(|_| rng.gen::<u8>()).collect();
            let my_res = crate::Sha256::new().chain_update(&buffer).finalize();
            let ex_res = sha2::Sha256::new().chain_update(&buffer).finalize();
            assert_eq!(ex_res, my_res, "Failed on random test");
        }
    }
}
