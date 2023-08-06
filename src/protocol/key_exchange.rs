use nom::{number::complete::be_u8, IResult};

use crate::crypto::key_exchage::{Curve25519Sha256, Kex};

struct KeyExchange {}

fn parse_key_exchange(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, message_code) = be_u8(input)?;
    match message_code {
        0x1e => {
            Kex::<Curve25519Sha256> {
                method: Curve25519Sha256::new(),
                shared_secret_key: vec![],
                exchange_hash: vec![],
                session_id: vec![],
            };
        }
        _ => {}
    };
    Ok((input, vec![]))
}

fn generate_key_exchange() {}

/*
00000609  00 00 00 2c 06 1e 00 00  00 20 11 2e 9a 73 e2 53   ...,.... . ...s.S
00000619  7e 4e 71 dd 6e f7 fc ec  18 bb 3c 26 40 15 7e 3f   ~Nq.n... ..<&@.~?
00000629  80 7d de 27 f3 c8 f7 a0  59 12 00 00 00 00 00 00   .}.'.... Y.......
    000002E9  00 00 00 bc 08 1f 00 00  00 33 00 00 00 0b 73 73   ........ .3....ss
    000002F9  68 2d 65 64 32 35 35 31  39 00 00 00 20 e3 2a aa   h-ed2551 9... .*.
    00000309  79 15 ce b9 b4 49 d1 ba  50 ea 2a 28 bb 1a 6e 01   y....I.. P.*(..n.
    00000319  f9 0b da 24 5a 2d 1d 87  69 7d 18 a2 65 00 00 00   ...$Z-.. i}..e...
    00000329  20 8c 1b 73 02 25 bf 80  da 84 00 81 39 27 a5 7b    ..s.%.. ....9'.{
    00000339  52 ea db 1e 80 c2 24 42  fa 2c b0 56 3a c2 8f 3b   R.....$B .,.V:..;
    00000349  37 00 00 00 53 00 00 00  0b 73 73 68 2d 65 64 32   7...S... .ssh-ed2
    00000359  35 35 31 39 00 00 00 40  41 66 5f 8c 52 e5 82 88   5519...@ Af_.R...
    00000369  73 6b 1f b1 29 4b 0b dc  f8 b9 16 c6 cd 04 cd 4b   sk..)K.. .......K
    00000379  18 45 a0 95 4b b6 70 15  54 65 ef 67 5a 4c b3 99   .E..K.p. Te.gZL..
    00000389  ae 52 f0 c0 f3 19 96 64  ff a8 12 8a 4e cb 9d 2a   .R.....d ....N..*
    00000399  80 7a a0 4d 00 c3 93 09  00 00 00 00 00 00 00 00   .z.M.... ........
    000003A9  00 00 00 0c 0a 15 00 00  00 00 00 00 00 00 00 00   ........ ........
 */
