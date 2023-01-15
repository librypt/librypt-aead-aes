use std::ops::{Index, IndexMut};

use librypt_aead::{Aead};
use consts::{sbox_get, inv_sbox_get, rcon_get};

mod consts;

const Nb: usize = 4;
struct State([u8; Nb * Nb]);

type RoundKey = State;

impl Index<(usize, usize)> for State {
    type Output = u8;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        &self.0[Nb * index.0 + index.1]
    }
}

impl Index<usize> for State {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<(usize, usize)> for State {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        &mut self.0[Nb * index.0 + index.1]
    }
}

impl IndexMut<usize> for State {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

fn sub_bytes(state: &mut State) {
    for i in 0..state.0.len() {
        state[i] = sbox_get(state[i]);
    }
}

fn shift_rows(state: &mut State) {
    state.0[4..8].rotate_left(1);
    state.0[8..12].rotate_left(2);
    state.0[12..16].rotate_left(3);
}

const fn xtime(x: u8) -> u8 {
    (x<<1) ^ (((x>>7) & 1) * 0x1b)
}

fn mix_columns(state: &mut State) {
    for i in 0..4 {
        let t = state[(i, 0)];
        let tmp = state[(i, 0)] ^ state[(i, 1)] ^ state[(i, 2)] ^ state[(i, 3)];
        let mut tm = state[(i, 0)] ^ state[(i, 1)]; tm = xtime(tm); state[(i, 0)] ^= tm ^ tmp;
        tm = state[(i, 1)] ^ state[(i, 2)]; tm = xtime(tm); state[(i, 1)] ^= tm ^ tmp;
        tm = state[(i, 2)] ^ state[(i, 3)]; tm = xtime(tm); state[(i, 2)] ^= tm ^ tmp;
        tm = state[(i, 3)] ^ t; tm = xtime(tm); state[(i, 3)] ^= tm ^ tmp;
    }
}

fn add_round_key(state: &mut State, round: usize, round_key: RoundKey) {
    for i in 0..4 {
        for j in 0..4 {
            state[(i, j)] = round_key[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

const fn galois_mul(x: u8, y: u8) -> u8 {
    ((y & 1) * x) ^
    ((y>>1 & 1) * xtime(x)) ^
    ((y>>2 & 1) * xtime(xtime(x))) ^
    ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
    ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))
}

fn inv_mix_columns(state: &mut State) {
    for i in 0..4 {
        let a = state[(i, 0)];
        let b = state[(i, 1)];
        let c = state[(i, 2)];
        let d = state[(i, 3)];
        
        use crate::galois_mul as gm;

        state[(i, 0)] = gm(a, 0x0e) ^ gm(b, 0x0b) ^ gm(c, 0x0d) ^ gm(d, 0x09);
        state[(i, 1)] = gm(a, 0x09) ^ gm(b, 0x0e) ^ gm(c, 0x0b) ^ gm(d, 0x0d);
        state[(i, 2)] = gm(a, 0x0d) ^ gm(b, 0x09) ^ gm(c, 0x0e) ^ gm(d, 0x0b);
        state[(i, 3)] = gm(a, 0x0b) ^ gm(b, 0x0d) ^ gm(c, 0x09) ^ gm(d, 0x0e);
    }
}

fn inv_sub_bytes(state: &mut State) {
    for i in 0..state.0.len() {
        state[i] = inv_sbox_get(state[i]); 
    }
}

fn inv_shift_rows(state: &mut State) {
    state.0[4..8].rotate_right(1);
    state.0[8..12].rotate_right(2);
    state.0[12..16].rotate_right(3);
}

const fn sub_word(w: u32) -> u32 {
    ((sbox_get((0xFF & (w >> 24)) as u8) as u32) << 24)
        | ((sbox_get((0xFF & (w >> 16)) as u8) as u32) << 16)
        | ((sbox_get((0xFF & (w >> 8)) as u8) as u32) << 8)
        | (sbox_get((0xFF & w) as u8) as u32)
}

pub const K128: u32 = 4;
pub const K192: u32 = K128 + 2;
pub const K256: u32 = K192 + 2;

macro_rules! define_aes_impl {
    (
        $name:tt,
        $nk: expr,
        $nr: expr
    ) => {
        pub struct $name {
            state: State,
            keys: [u32; $nk * $nr],
        }

        impl $name {
            
            fn key_expansion(&mut self, k: &[u32; $nk]) {
                for i in 0..(Nb * $nr) {
                    if i < $nk {
                        self.keys[i] = k[i];
                    } else if i >= $nk && i % $nk == 0 {
                        self.keys[i] = self.keys[i - $nk] ^ sub_word(self.keys[i - 1].rotate_right(8)) ^ rcon_get(i / $nk);
                    } else if i >= $nk && $nk > 6 && i % $nk == 4 {
                        self.keys[i] = self.keys[i - $nk] ^ sub_word(self.keys[i - 1]);
                    } else {
                        self.keys[i] = self.keys[i - $nk] ^ self.keys[i - 1];
                    }
                }
            }

            fn cipher(input: [u8; 4 * Nb]) {

            }
        }
    };
}

define_aes_impl!(AES128Block, 4, 10);
define_aes_impl!(AES192Block, 6, 12);
define_aes_impl!(AES256Block, 8, 14);

#[cfg(test)]
mod tests {
    use super::*;

    
}
