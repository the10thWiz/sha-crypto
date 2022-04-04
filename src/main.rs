use digest::{Digest, FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update};

struct Sha256 {
    h: [u32; 8],
    buffer: [u8; 64],
    filled: u8,
    length: u64,
}

impl Sha256 {
    /// update state (self.h) using self.buffer.
    ///
    /// Assumes self.buffer is full
    fn run_round(&mut self) {}
}

impl Update for Sha256 {
    fn update(&mut self, mut data: &[u8]) {
        self.length += data.len() as u64;
        let empty = &mut self.buffer[self.filled as usize..];
        let len = data.len().min(empty.len());
        empty[..len].copy_from_slice(&data[..len]);
        if self.filled + len as u8 == 64 {
            self.run_round();
            data = &data[len..];
            while data.len() >= 64 {
                self.buffer.copy_from_slice(&data[..64]);
                self.run_round();
                data = &data[64..];
            }
        }
        self.buffer[..data.len()].copy_from_slice(data);
        self.filled = data.len() as u8;
    }
}

impl FixedOutput for Sha256 {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        // TODO: padding message with nessecary bits.
        for (out, s) in out
            .iter_mut()
            .zip(self.h.iter().flat_map(|&h| h.to_be_bytes()))
        {
            *out = s;
        }
    }
}

impl Digest for Sha256 {
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

impl OutputSizeUser for Sha256 {
    type OutputSize = digest::consts::U32;
}

impl Reset for Sha256 {
    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl FixedOutputReset for Sha256 {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        FixedOutput::finalize_into(std::mem::replace(self, Self::new()), out)
    }
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use digest::*;

    macro_rules! sha_test {
        ($i:literal) => {
            let s = $i;
            let my_res = crate::Sha256::new().chain_update(s.as_bytes()).finalize();
            let ex_res = sha2::Sha256::new().chain_update(s.as_bytes()).finalize();
            assert_eq!(ex_res, my_res, concat!("Failed to hash `", $i, "` correctly"));
        };
    }

    #[test]
    fn simple() {
        sha_test!("Hello World!");
        sha_test!("helloworld");
        sha_test!("Some nice string");
        sha_test!("Some nice string");
        sha_test!("Some nice string");
    }
}
