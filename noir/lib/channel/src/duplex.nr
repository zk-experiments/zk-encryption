//! The envelope cipher: eid_envelope's Poseidon2 duplex (width 4, rate 3),
//! keyed with (key, a, b, CIPHER) and bound to ctx. Each ciphertext field is
//! the plaintext field plus a state element and replaces it; one permutation
//! per block of three, the last block possibly partial (the ciphertext has
//! exactly as many fields as the plaintext).

/// "eid-envelope/cipher/v1" as a big-endian integer (as eid_envelope).
pub global CIPHER_DOMAIN: Field = 0x6569642d656e76656c6f70652f6369706865722f7631;

/// The duplex keyed with (key, a, b, CIPHER).
pub fn duplex<let N: u32>(
    key: Field,
    a: Field,
    b: Field,
    context: Field,
    plaintext: [Field; N],
) -> [Field; N] {
    let mut state: [Field; 4] = std::hash::poseidon2_permutation([key, a, b, CIPHER_DOMAIN]);
    state[0] += context;
    state = std::hash::poseidon2_permutation(state);
    let mut ciphertext: [Field; N] = [0; N];
    for block in 0..(N + 2) / 3 {
        for j in 0..3 {
            let i = 3 * block + j;
            if i < N {
                let c = plaintext[i] + state[j];
                ciphertext[i] = c;
                state[j] = c;
            }
        }
        state = std::hash::poseidon2_permutation(state);
    }
    ciphertext
}
