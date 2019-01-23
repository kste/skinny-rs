//! Implementation of the SKINNY-64 block cipher.
static SKINNY64_SBOX: [u8; 16] = [
    0xc, 0x6, 0x9, 0x0, 0x1, 0xa, 0x2, 0xb, 0x3, 0x8, 0x5, 0xd, 0x4, 0xe, 0x7, 0xf,
];
static KEY_PERM: [u8; 16] = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7];

static CONSTANTS: [u8; 48] = [
    0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e, 0x3c, 0x39, 0x33, 0x27, 0x0e,
    0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38,
    0x31, 0x23, 0x06, 0x0d, 0x1b, 0x36, 0x2d, 0x1a, 0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04,
];

static SR_PERM: [u8; 16] = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];

pub enum TweakeyType {
    TK1,
    TK2,
    TK3,
}

pub fn key_schedule_64(tweakey: &[u8], rounds: u64, keytype: TweakeyType) -> Vec<u8> {
    let mut round_keys: Vec<u8> = vec![0; 16 * rounds as usize];
    let mut state: Vec<u8> = match keytype {
        TweakeyType::TK1 => vec![0; 16],
        TweakeyType::TK2 => vec![0; 32],
        TweakeyType::TK3 => vec![0; 48],
    };

    // Convert key to a state of 16 nibbles
    for nibble in 0..state.len() {
        state[nibble] = tweakey[(nibble / 2)] >> (4 * ((nibble + 1) % 2)) & 0xf;
    }

    for round in 0..rounds {
        for i in 0..8 {
            let key_idx = 16 * round + i;
            round_keys[key_idx as usize] = match keytype {
                TweakeyType::TK1 => state[i as usize],
                TweakeyType::TK2 => state[i as usize] ^ state[(i + 16) as usize],
                TweakeyType::TK3 => {
                    state[i as usize] ^ state[(i + 16) as usize] ^ state[(i + 32) as usize]
                }
            }
        }

        // Add constants
        round_keys[16 * round as usize] ^= CONSTANTS[round as usize] & 0xf;
        round_keys[16 * round as usize + 4] ^= CONSTANTS[round as usize] >> 4;
        round_keys[16 * round as usize + 8] ^= 0x2;

        // Apply permutation
        let mut tmp: Vec<u8> = vec![0; state.len()];
        for i in 0..state.len() {
            tmp[i] = state[16 * (i / 16) + KEY_PERM[i % 16] as usize];
        }
        state.clone_from_slice(&tmp);

        // LFSR
        match keytype {
            TweakeyType::TK2 => {
                for nibble in state.iter_mut().take(24).skip(16) {
                    *nibble =
                        ((*nibble << 1) & 0xE) ^ ((*nibble >> 3) & 0x1) ^ ((*nibble >> 2) & 0x1);
                }
            }
            TweakeyType::TK3 => {
                for nibble in state.iter_mut().take(24).skip(16) {
                    *nibble =
                        ((*nibble << 1) & 0xE) ^ ((*nibble >> 3) & 0x1) ^ ((*nibble >> 2) & 0x1);
                }
                for nibble in state.iter_mut().take(40).skip(32) {
                    *nibble = ((*nibble >> 1) & 0x7) ^ ((*nibble) & 0x8) ^ ((*nibble << 3) & 0x8);
                }
            }
            _ => (),
        }
    }

    round_keys
}

fn sub_bytes(state: &[u8; 16]) -> [u8; 16] {
    let mut tmp_state: [u8; 16] = [0; 16];

    for nibble in 0..16 {
        tmp_state[nibble] = SKINNY64_SBOX[state[nibble] as usize];
    }
    tmp_state
}

fn add_tweakey(state: &[u8; 16], tweakey: &[u8]) -> [u8; 16] {
    let mut tmp_state: [u8; 16] = [0; 16];

    for nibble in 0..16 {
        tmp_state[nibble] = state[nibble] ^ tweakey[nibble];
    }
    tmp_state
}

fn shift_rows(state: &[u8; 16]) -> [u8; 16] {
    let mut tmp_state: [u8; 16] = [0; 16];

    for nibble in 0..16 {
        tmp_state[nibble] = state[SR_PERM[nibble] as usize];
    }
    tmp_state
}

fn mix_columns(state: &[u8; 16]) -> [u8; 16] {
    let mut tmp_state: [u8; 16] = [0; 16];
    // MixColumns
    for col in 0..4 {
        let tmp = state[12 + col];
        tmp_state[12 + col] = state[col] ^ state[8 + col];
        tmp_state[8 + col] = state[4 + col] ^ state[8 + col];
        tmp_state[4 + col] = state[col];
        tmp_state[col] = tmp ^ tmp_state[12 + col];
    }
    tmp_state
}

pub fn skinny64(input: &[u8; 8], rounds: u64, round_keys: &[u8]) -> [u8; 8] {
    let mut state: [u8; 16] = [0; 16];
    let mut output: [u8; 8] = [0; 8];

    // Convert input to a state of 16 nibbles
    for nibble in 0..16 {
        state[nibble] = input[(nibble / 2)] >> (4 * ((nibble + 1) % 2)) & 0xf;
    }

    for rnd in 0..rounds {
        // S-box layer
        state = sub_bytes(&state);
        state = add_tweakey(
            &state,
            &round_keys[16 * rnd as usize..16 * (rnd as usize + 1)],
        );
        state = shift_rows(&state);
        state = mix_columns(&state);
    }

    // Convert state to byte array
    for nibble in 0..16 {
        let val = state[nibble] << (4 * ((nibble + 1) % 2));
        output[nibble / 2] |= val;
    }
    output
}
