use nom::IResult;
use rand::Rng;

use crate::protocol::data::{DataType, NameList};
use crate::protocol::ssh2::message_code;

use super::data::Data;

#[derive(Debug)]
pub struct KexAlgorithms {
    pub cookie: [u8; 16],
    pub kex_algorithms: NameList,
    pub server_host_key_algorithms: NameList,
    pub encryption_algorithms_client_to_server: NameList,
    pub encryption_algorithms_server_to_client: NameList,
    pub mac_algorithms_client_to_server: NameList,
    pub mac_algorithms_server_to_client: NameList,
    pub compression_algorithms_client_to_server: NameList,
    pub compression_algorithms_server_to_client: NameList,
    pub languages_client_to_server: NameList,
    pub languages_server_to_client: NameList,
    pub first_kex_packet_follows: bool,
}

impl KexAlgorithms {
    pub fn parse_key_exchange_init(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, message_id) = u8::decode(input)?;
        assert!(message_id == message_code::SSH_MSG_KEXINIT);
        let (input, cookie) = <[u8; 16]>::decode(input)?;
        let (input, kex_algorithms) = NameList::decode(input)?;
        let (input, server_host_key_algorithms) = NameList::decode(input)?;
        let (input, encryption_algorithms_client_to_server) = NameList::decode(input)?;
        let (input, encryption_algorithms_server_to_client) = NameList::decode(input)?;
        let (input, mac_algorithms_client_to_server) = NameList::decode(input)?;
        let (input, mac_algorithms_server_to_client) = NameList::decode(input)?;
        let (input, compression_algorithms_client_to_server) = NameList::decode(input)?;
        let (input, compression_algorithms_server_to_client) = NameList::decode(input)?;
        let (input, languages_client_to_server) = NameList::decode(input)?;
        let (input, languages_server_to_client) = NameList::decode(input)?;
        let (input, first_kex_packet_follows) = bool::decode(input)?;
        let (input, _reserved) = u32::decode(input)?;

        Ok((
            input,
            KexAlgorithms {
                cookie,
                kex_algorithms,
                server_host_key_algorithms,
                encryption_algorithms_client_to_server,
                encryption_algorithms_server_to_client,
                mac_algorithms_client_to_server,
                mac_algorithms_server_to_client,
                compression_algorithms_client_to_server,
                compression_algorithms_server_to_client,
                languages_client_to_server,
                languages_server_to_client,
                first_kex_packet_follows,
            },
        ))
    }

    pub fn generate_key_exchange_init(&self) -> Data {
        let mut data = Data::new();
        data.put(&message_code::SSH_MSG_KEXINIT)
            .put(&self.cookie)
            .put(&self.kex_algorithms)
            .put(&self.server_host_key_algorithms)
            .put(&self.encryption_algorithms_client_to_server)
            .put(&self.encryption_algorithms_server_to_client)
            .put(&self.mac_algorithms_client_to_server)
            .put(&self.mac_algorithms_server_to_client)
            .put(&self.compression_algorithms_client_to_server)
            .put(&self.compression_algorithms_server_to_client)
            .put(&self.languages_client_to_server)
            .put(&self.languages_server_to_client)
            .put(&self.languages_server_to_client)
            .put(&self.first_kex_packet_follows);
        data
    }

    pub fn create_kex_from_kex(&self) -> Self {
        KexAlgorithms {
            cookie: rand::thread_rng().gen::<[u8; 16]>(),
            kex_algorithms: self.kex_algorithms.clone(),
            server_host_key_algorithms: vec!["rsa-sha2-256".to_string()],
            encryption_algorithms_client_to_server: vec![
                "chacha20-poly1305@openssh.com".to_string(),
                // "aes128-ctr".to_string(),
                // "aes256-gcm@openssh.com".to_string(),
            ],
            encryption_algorithms_server_to_client: vec![
                "chacha20-poly1305@openssh.com".to_string(),
                // "aes128-ctr".to_string(),
                // "aes256-gcm@openssh.com".to_string(),
            ],
            mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
            mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
            compression_algorithms_client_to_server: self
                .compression_algorithms_client_to_server
                .clone(),
            compression_algorithms_server_to_client: self
                .compression_algorithms_server_to_client
                .clone(),
            languages_client_to_server: self.languages_client_to_server.clone(),
            languages_server_to_client: self.languages_server_to_client.clone(),
            first_kex_packet_follows: self.first_kex_packet_follows.clone(),
        }
    }
}

// When acting as server: "ext-info-s"
// When acting as client: "ext-info-c"
#[test]
fn parse_test_key_exchange_init_packet() {
    // \x00\x00\x05\xdc\x04\x14
    let packet = b"\x14\x11\x58\xa5\x0f\xa6\x66\x70\x27\x00\x75\x6b\xd9\x62\xe5\xdc\xb2\
\x00\x00\x01\x14\
curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c\
\x00\x00\x01\xcf\
ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\
\x00\x00\x00\x6c\
chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\
\x00\x00\x00\x6c\
chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\
\x00\x00\x00\xd5\
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\
\x00\x00\x00\xd5\
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\
\x00\x00\x00\x1a\
none,zlib@openssh.com,zlib\
\x00\x00\x00\x1a\
none,zlib@openssh.com,zlib\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    //\x00\x00\x00\x00";
    let parsed = KexAlgorithms::parse_key_exchange_init(packet);
    assert!(parsed.is_ok());
    let (_, algo) = parsed.unwrap();
    let gen_packet = algo.generate_key_exchange_init();
    // hexdump(packet);
    // hexdump(&gen_packet);
    assert!(packet[..] == gen_packet.into_inner()[..]);
}

/*
    00000000  53 53 48 2d 32 2e 30 2d  62 61 62 65 6c 64 2d 64   SSH-2.0- babeld-d
    00000010  63 35 65 63 39 62 65 0d  0a 00 00 02 cc 06 14 0a   c5ec9be. ........
    00000020  7d 59 2f 1e 43 c2 26 f4  29 3e 51 e8 4a 8d 4d 00   }Y/.C.&. )>Q.J.M.
    00000030  00 00 8c 63 75 72 76 65  32 35 35 31 39 2d 73 68   ...curve 25519-sh
    00000040  61 32 35 36 2c 63 75 72  76 65 32 35 35 31 39 2d   a256,cur ve25519-
    00000050  73 68 61 32 35 36 40 6c  69 62 73 73 68 2e 6f 72   sha256@l ibssh.or
    00000060  67 2c 65 63 64 68 2d 73  68 61 32 2d 6e 69 73 74   g,ecdh-s ha2-nist
    00000070  70 32 35 36 2c 65 63 64  68 2d 73 68 61 32 2d 6e   p256,ecd h-sha2-n
    00000080  69 73 74 70 33 38 34 2c  65 63 64 68 2d 73 68 61   istp384, ecdh-sha
    00000090  32 2d 6e 69 73 74 70 35  32 31 2c 64 69 66 66 69   2-nistp5 21,diffi
    000000A0  65 2d 68 65 6c 6c 6d 61  6e 2d 67 72 6f 75 70 2d   e-hellma n-group-
    000000B0  65 78 63 68 61 6e 67 65  2d 73 68 61 32 35 36 00   exchange -sha256.
    000000C0  00 00 41 73 73 68 2d 65  64 32 35 35 31 39 2c 65   ..Assh-e d25519,e
    000000D0  63 64 73 61 2d 73 68 61  32 2d 6e 69 73 74 70 32   cdsa-sha 2-nistp2
    000000E0  35 36 2c 72 73 61 2d 73  68 61 32 2d 35 31 32 2c   56,rsa-s ha2-512,
    000000F0  72 73 61 2d 73 68 61 32  2d 32 35 36 2c 73 73 68   rsa-sha2 -256,ssh
    00000100  2d 72 73 61 00 00 00 6c  63 68 61 63 68 61 32 30   -rsa...l chacha20
    00000110  2d 70 6f 6c 79 31 33 30  35 40 6f 70 65 6e 73 73   -poly130 5@openss
    00000120  68 2e 63 6f 6d 2c 61 65  73 32 35 36 2d 67 63 6d   h.com,ae s256-gcm
    00000130  40 6f 70 65 6e 73 73 68  2e 63 6f 6d 2c 61 65 73   @openssh .com,aes
    00000140  31 32 38 2d 67 63 6d 40  6f 70 65 6e 73 73 68 2e   128-gcm@ openssh.
    00000150  63 6f 6d 2c 61 65 73 32  35 36 2d 63 74 72 2c 61   com,aes2 56-ctr,a
    00000160  65 73 31 39 32 2d 63 74  72 2c 61 65 73 31 32 38   es192-ct r,aes128
    00000170  2d 63 74 72 00 00 00 6c  63 68 61 63 68 61 32 30   -ctr...l chacha20
    00000180  2d 70 6f 6c 79 31 33 30  35 40 6f 70 65 6e 73 73   -poly130 5@openss
    00000190  68 2e 63 6f 6d 2c 61 65  73 32 35 36 2d 67 63 6d   h.com,ae s256-gcm
    000001A0  40 6f 70 65 6e 73 73 68  2e 63 6f 6d 2c 61 65 73   @openssh .com,aes
    000001B0  31 32 38 2d 67 63 6d 40  6f 70 65 6e 73 73 68 2e   128-gcm@ openssh.
    000001C0  63 6f 6d 2c 61 65 73 32  35 36 2d 63 74 72 2c 61   com,aes2 56-ctr,a
    000001D0  65 73 31 39 32 2d 63 74  72 2c 61 65 73 31 32 38   es192-ct r,aes128
    000001E0  2d 63 74 72 00 00 00 57  68 6d 61 63 2d 73 68 61   -ctr...W hmac-sha
    000001F0  32 2d 35 31 32 2d 65 74  6d 40 6f 70 65 6e 73 73   2-512-et m@openss
    00000200  68 2e 63 6f 6d 2c 68 6d  61 63 2d 73 68 61 32 2d   h.com,hm ac-sha2-
    00000210  32 35 36 2d 65 74 6d 40  6f 70 65 6e 73 73 68 2e   256-etm@ openssh.
    00000220  63 6f 6d 2c 68 6d 61 63  2d 73 68 61 32 2d 35 31   com,hmac -sha2-51
    00000230  32 2c 68 6d 61 63 2d 73  68 61 32 2d 32 35 36 00   2,hmac-s ha2-256.
    00000240  00 00 57 68 6d 61 63 2d  73 68 61 32 2d 35 31 32   ..Whmac- sha2-512
    00000250  2d 65 74 6d 40 6f 70 65  6e 73 73 68 2e 63 6f 6d   -etm@ope nssh.com
    00000260  2c 68 6d 61 63 2d 73 68  61 32 2d 32 35 36 2d 65   ,hmac-sh a2-256-e
    00000270  74 6d 40 6f 70 65 6e 73  73 68 2e 63 6f 6d 2c 68   tm@opens sh.com,h
    00000280  6d 61 63 2d 73 68 61 32  2d 35 31 32 2c 68 6d 61   mac-sha2 -512,hma
    00000290  63 2d 73 68 61 32 2d 32  35 36 00 00 00 1a 6e 6f   c-sha2-2 56....no
    000002A0  6e 65 2c 7a 6c 69 62 40  6f 70 65 6e 73 73 68 2e   ne,zlib@ openssh.
    000002B0  63 6f 6d 2c 7a 6c 69 62  00 00 00 1a 6e 6f 6e 65   com,zlib ....none
    000002C0  2c 7a 6c 69 62 40 6f 70  65 6e 73 73 68 2e 63 6f   ,zlib@op enssh.co
    000002D0  6d 2c 7a 6c 69 62 00 00  00 00 00 00 00 00 00 00   m,zlib.. ........
    000002E0  00 00 00 00 00 00 00 00  00                        ........ .
00000029  00 00 05 dc 04 14 11 58  a5 0f a6 66 70 27 00 75   .......X ...fp'.u
00000039  6b d9 62 e5 dc b2 00 00  01 14 63 75 72 76 65 32   k.b..... ..curve2
00000049  35 35 31 39 2d 73 68 61  32 35 36 2c 63 75 72 76   5519-sha 256,curv
00000059  65 32 35 35 31 39 2d 73  68 61 32 35 36 40 6c 69   e25519-s ha256@li
00000069  62 73 73 68 2e 6f 72 67  2c 65 63 64 68 2d 73 68   bssh.org ,ecdh-sh
00000079  61 32 2d 6e 69 73 74 70  32 35 36 2c 65 63 64 68   a2-nistp 256,ecdh
00000089  2d 73 68 61 32 2d 6e 69  73 74 70 33 38 34 2c 65   -sha2-ni stp384,e
00000099  63 64 68 2d 73 68 61 32  2d 6e 69 73 74 70 35 32   cdh-sha2 -nistp52
000000A9  31 2c 73 6e 74 72 75 70  37 36 31 78 32 35 35 31   1,sntrup 761x2551
000000B9  39 2d 73 68 61 35 31 32  40 6f 70 65 6e 73 73 68   9-sha512 @openssh
000000C9  2e 63 6f 6d 2c 64 69 66  66 69 65 2d 68 65 6c 6c   .com,dif fie-hell
000000D9  6d 61 6e 2d 67 72 6f 75  70 2d 65 78 63 68 61 6e   man-grou p-exchan
000000E9  67 65 2d 73 68 61 32 35  36 2c 64 69 66 66 69 65   ge-sha25 6,diffie
000000F9  2d 68 65 6c 6c 6d 61 6e  2d 67 72 6f 75 70 31 36   -hellman -group16
00000109  2d 73 68 61 35 31 32 2c  64 69 66 66 69 65 2d 68   -sha512, diffie-h
00000119  65 6c 6c 6d 61 6e 2d 67  72 6f 75 70 31 38 2d 73   ellman-g roup18-s
00000129  68 61 35 31 32 2c 64 69  66 66 69 65 2d 68 65 6c   ha512,di ffie-hel
00000139  6c 6d 61 6e 2d 67 72 6f  75 70 31 34 2d 73 68 61   lman-gro up14-sha
00000149  32 35 36 2c 65 78 74 2d  69 6e 66 6f 2d 63 00 00   256,ext- info-c..
00000159  01 cf 73 73 68 2d 65 64  32 35 35 31 39 2d 63 65   ..ssh-ed 25519-ce
00000169  72 74 2d 76 30 31 40 6f  70 65 6e 73 73 68 2e 63   rt-v01@o penssh.c
00000179  6f 6d 2c 65 63 64 73 61  2d 73 68 61 32 2d 6e 69   om,ecdsa -sha2-ni
00000189  73 74 70 32 35 36 2d 63  65 72 74 2d 76 30 31 40   stp256-c ert-v01@
00000199  6f 70 65 6e 73 73 68 2e  63 6f 6d 2c 65 63 64 73   openssh. com,ecds
000001A9  61 2d 73 68 61 32 2d 6e  69 73 74 70 33 38 34 2d   a-sha2-n istp384-
000001B9  63 65 72 74 2d 76 30 31  40 6f 70 65 6e 73 73 68   cert-v01 @openssh
000001C9  2e 63 6f 6d 2c 65 63 64  73 61 2d 73 68 61 32 2d   .com,ecd sa-sha2-
000001D9  6e 69 73 74 70 35 32 31  2d 63 65 72 74 2d 76 30   nistp521 -cert-v0
000001E9  31 40 6f 70 65 6e 73 73  68 2e 63 6f 6d 2c 73 6b   1@openss h.com,sk
000001F9  2d 73 73 68 2d 65 64 32  35 35 31 39 2d 63 65 72   -ssh-ed2 5519-cer
00000209  74 2d 76 30 31 40 6f 70  65 6e 73 73 68 2e 63 6f   t-v01@op enssh.co
00000219  6d 2c 73 6b 2d 65 63 64  73 61 2d 73 68 61 32 2d   m,sk-ecd sa-sha2-
00000229  6e 69 73 74 70 32 35 36  2d 63 65 72 74 2d 76 30   nistp256 -cert-v0
00000239  31 40 6f 70 65 6e 73 73  68 2e 63 6f 6d 2c 72 73   1@openss h.com,rs
00000249  61 2d 73 68 61 32 2d 35  31 32 2d 63 65 72 74 2d   a-sha2-5 12-cert-
00000259  76 30 31 40 6f 70 65 6e  73 73 68 2e 63 6f 6d 2c   v01@open ssh.com,
00000269  72 73 61 2d 73 68 61 32  2d 32 35 36 2d 63 65 72   rsa-sha2 -256-cer
00000279  74 2d 76 30 31 40 6f 70  65 6e 73 73 68 2e 63 6f   t-v01@op enssh.co
00000289  6d 2c 73 73 68 2d 65 64  32 35 35 31 39 2c 65 63   m,ssh-ed 25519,ec
00000299  64 73 61 2d 73 68 61 32  2d 6e 69 73 74 70 32 35   dsa-sha2 -nistp25
000002A9  36 2c 65 63 64 73 61 2d  73 68 61 32 2d 6e 69 73   6,ecdsa- sha2-nis
000002B9  74 70 33 38 34 2c 65 63  64 73 61 2d 73 68 61 32   tp384,ec dsa-sha2
000002C9  2d 6e 69 73 74 70 35 32  31 2c 73 6b 2d 73 73 68   -nistp52 1,sk-ssh
000002D9  2d 65 64 32 35 35 31 39  40 6f 70 65 6e 73 73 68   -ed25519 @openssh
000002E9  2e 63 6f 6d 2c 73 6b 2d  65 63 64 73 61 2d 73 68   .com,sk- ecdsa-sh
000002F9  61 32 2d 6e 69 73 74 70  32 35 36 40 6f 70 65 6e   a2-nistp 256@open
00000309  73 73 68 2e 63 6f 6d 2c  72 73 61 2d 73 68 61 32   ssh.com, rsa-sha2
00000319  2d 35 31 32 2c 72 73 61  2d 73 68 61 32 2d 32 35   -512,rsa -sha2-25
00000329  36 00 00 00 6c 63 68 61  63 68 61 32 30 2d 70 6f   6...lcha cha20-po
00000339  6c 79 31 33 30 35 40 6f  70 65 6e 73 73 68 2e 63   ly1305@o penssh.c
00000349  6f 6d 2c 61 65 73 31 32  38 2d 63 74 72 2c 61 65   om,aes12 8-ctr,ae
00000359  73 31 39 32 2d 63 74 72  2c 61 65 73 32 35 36 2d   s192-ctr ,aes256-
00000369  63 74 72 2c 61 65 73 31  32 38 2d 67 63 6d 40 6f   ctr,aes1 28-gcm@o
00000379  70 65 6e 73 73 68 2e 63  6f 6d 2c 61 65 73 32 35   penssh.c om,aes25
00000389  36 2d 67 63 6d 40 6f 70  65 6e 73 73 68 2e 63 6f   6-gcm@op enssh.co
00000399  6d 00 00 00 6c 63 68 61  63 68 61 32 30 2d 70 6f   m...lcha cha20-po
000003A9  6c 79 31 33 30 35 40 6f  70 65 6e 73 73 68 2e 63   ly1305@o penssh.c
000003B9  6f 6d 2c 61 65 73 31 32  38 2d 63 74 72 2c 61 65   om,aes12 8-ctr,ae
000003C9  73 31 39 32 2d 63 74 72  2c 61 65 73 32 35 36 2d   s192-ctr ,aes256-
000003D9  63 74 72 2c 61 65 73 31  32 38 2d 67 63 6d 40 6f   ctr,aes1 28-gcm@o
000003E9  70 65 6e 73 73 68 2e 63  6f 6d 2c 61 65 73 32 35   penssh.c om,aes25
000003F9  36 2d 67 63 6d 40 6f 70  65 6e 73 73 68 2e 63 6f   6-gcm@op enssh.co
00000409  6d 00 00 00 d5 75 6d 61  63 2d 36 34 2d 65 74 6d   m....uma c-64-etm
00000419  40 6f 70 65 6e 73 73 68  2e 63 6f 6d 2c 75 6d 61   @openssh .com,uma
00000429  63 2d 31 32 38 2d 65 74  6d 40 6f 70 65 6e 73 73   c-128-et m@openss
00000439  68 2e 63 6f 6d 2c 68 6d  61 63 2d 73 68 61 32 2d   h.com,hm ac-sha2-
00000449  32 35 36 2d 65 74 6d 40  6f 70 65 6e 73 73 68 2e   256-etm@ openssh.
00000459  63 6f 6d 2c 68 6d 61 63  2d 73 68 61 32 2d 35 31   com,hmac -sha2-51
00000469  32 2d 65 74 6d 40 6f 70  65 6e 73 73 68 2e 63 6f   2-etm@op enssh.co
00000479  6d 2c 68 6d 61 63 2d 73  68 61 31 2d 65 74 6d 40   m,hmac-s ha1-etm@
00000489  6f 70 65 6e 73 73 68 2e  63 6f 6d 2c 75 6d 61 63   openssh. com,umac
00000499  2d 36 34 40 6f 70 65 6e  73 73 68 2e 63 6f 6d 2c   -64@open ssh.com,
000004A9  75 6d 61 63 2d 31 32 38  40 6f 70 65 6e 73 73 68   umac-128 @openssh
000004B9  2e 63 6f 6d 2c 68 6d 61  63 2d 73 68 61 32 2d 32   .com,hma c-sha2-2
000004C9  35 36 2c 68 6d 61 63 2d  73 68 61 32 2d 35 31 32   56,hmac- sha2-512
000004D9  2c 68 6d 61 63 2d 73 68  61 31 00 00 00 d5 75 6d   ,hmac-sh a1....um
000004E9  61 63 2d 36 34 2d 65 74  6d 40 6f 70 65 6e 73 73   ac-64-et m@openss
000004F9  68 2e 63 6f 6d 2c 75 6d  61 63 2d 31 32 38 2d 65   h.com,um ac-128-e
00000509  74 6d 40 6f 70 65 6e 73  73 68 2e 63 6f 6d 2c 68   tm@opens sh.com,h
00000519  6d 61 63 2d 73 68 61 32  2d 32 35 36 2d 65 74 6d   mac-sha2 -256-etm
00000529  40 6f 70 65 6e 73 73 68  2e 63 6f 6d 2c 68 6d 61   @openssh .com,hma
00000539  63 2d 73 68 61 32 2d 35  31 32 2d 65 74 6d 40 6f   c-sha2-5 12-etm@o
00000549  70 65 6e 73 73 68 2e 63  6f 6d 2c 68 6d 61 63 2d   penssh.c om,hmac-
00000559  73 68 61 31 2d 65 74 6d  40 6f 70 65 6e 73 73 68   sha1-etm @openssh
00000569  2e 63 6f 6d 2c 75 6d 61  63 2d 36 34 40 6f 70 65   .com,uma c-64@ope
00000579  6e 73 73 68 2e 63 6f 6d  2c 75 6d 61 63 2d 31 32   nssh.com ,umac-12
00000589  38 40 6f 70 65 6e 73 73  68 2e 63 6f 6d 2c 68 6d   8@openss h.com,hm
00000599  61 63 2d 73 68 61 32 2d  32 35 36 2c 68 6d 61 63   ac-sha2- 256,hmac
000005A9  2d 73 68 61 32 2d 35 31  32 2c 68 6d 61 63 2d 73   -sha2-51 2,hmac-s
000005B9  68 61 31 00 00 00 1a 6e  6f 6e 65 2c 7a 6c 69 62   ha1....n one,zlib
000005C9  40 6f 70 65 6e 73 73 68  2e 63 6f 6d 2c 7a 6c 69   @openssh .com,zli
000005D9  62 00 00 00 1a 6e 6f 6e  65 2c 7a 6c 69 62 40 6f   b....non e,zlib@o
000005E9  70 65 6e 73 73 68 2e 63  6f 6d 2c 7a 6c 69 62 00   penssh.c om,zlib.
000005F9  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
*/
