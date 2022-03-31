use digest::{Digest, FixedOutput, FixedOutputReset, OutputSizeUser, Reset, Update};

struct Sha256 {
    state: (),
}

impl OutputSizeUser for Sha256 {
    type OutputSize = digest::consts::U32;
}

impl Reset for Sha256 {
    fn reset(&mut self) {
        todo!()
    }
}
impl Update for Sha256 {
    fn update(&mut self, data: &[u8]) {
        todo!()
    }
}
impl FixedOutput for Sha256 {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        todo!()
    }
}
impl FixedOutputReset for Sha256 {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        todo!()
    }
}

impl Digest for Sha256 {
    fn new() -> Self {
        todo!()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        <Self as Update>::update(self, data.as_ref())
    }

    fn finalize_into(self, out: &mut digest::Output<Self>) {
        todo!()
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        let mut s = Self::new();
        s.chain_update(data)
    }

    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::update(&mut self, data);
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
        let output = self.finalize();
        *self = Self::new();
        output
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

fn main() {
    println!("Hello, world!");
}

#[test]
fn simple() {
    let s = "Some nice string";
}
