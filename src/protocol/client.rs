use rand::prelude::*;
use std::io;
use std::net::SocketAddr;

use crate::crypto::compression::{Compress, NoneCompress};
use crate::crypto::encryption::{
    aes_ctr::aes128_ctr, aes_gcm::aes256_gcm, chachapoly::chacha20_poly1305, Encryption,
};
use crate::crypto::key_exchange::{curve::Curve25519Sha256, KexMethod};
use crate::crypto::mac::{HmacSha2_256, NoneMac, MAC};
use crate::network::tcp_client::TcpClient;
use crate::protocol::binary_packet::BinaryPacket;
use crate::protocol::key_exchange::{generate_key_exchange, parse_key_exchange};
use crate::protocol::key_exchange_init::KexAlgorithms;
use crate::protocol::ssh2::DisconnectCode;
use crate::protocol::version_exchange::Version;
use crate::utils::{hex, hexdump};

use super::authentification::Authentication;
use super::key_exchange::Kex;
use super::session::{NewKeys, SessionState};
use super::ssh2::MessageCode;

pub struct SshClient {
    address: SocketAddr,
    username: String,
    client: TcpClient,
}

impl SshClient {
    pub fn new(address: SocketAddr, username: String) -> io::Result<Self> {
        let client = TcpClient::new(address)?;
        Ok(SshClient {
            address,
            username,
            client,
        })
    }

    pub fn connection_setup(&mut self) -> Result<&[u8], DisconnectCode> {
        let session = SessionState::init_state();
        let (client_version, server_version) = self.version_exchange()?;
        let (client_kex_algorithms, server_kex_algorithms) = self.key_exchange_init(&session)?;
        let kex = self.key_exchange::<Curve25519Sha256>(
            &client_kex_algorithms.cookie,
            &client_version,
            &server_version,
            &client_kex_algorithms,
            &server_kex_algorithms,
            &session,
        )?;
        let mut session = SessionState::new(
            NewKeys::new(
                Box::new(aes128_ctr::new(
                    &kex.encryption_key_server_to_client(),
                    &kex.initial_iv_server_to_client(),
                )),
                Box::new(HmacSha2_256::new(kex.integrity_key_server_to_client())),
                Box::new(NoneCompress {}),
            ),
            NewKeys::new(
                Box::new(aes128_ctr::new(
                    &kex.encryption_key_server_to_client(),
                    &kex.initial_iv_server_to_client(),
                )),
                Box::new(HmacSha2_256::new(kex.integrity_key_server_to_client())),
                Box::new(NoneCompress {}),
            ),
            &client_version,
            &server_version,
            &client_kex_algorithms,
            &server_kex_algorithms,
        );
        // let user_auth = self.user_auth(&mut session)?;
        // Ok(user_auth)
        Ok(&[])
    }

    fn version_exchange(&mut self) -> Result<(Version, Version), DisconnectCode> {
        // send version
        let client_version = Version::new(
            "SSH-2.0-OpenSSH_8.9p1",
            Some("Ubuntu-3ubuntu0.1wooooooooooo"),
        );
        self.send(&client_version.to_bytes(true))?;

        // recv version
        let (_input, server_version) = Version::from_bytes(&self.recv()?)
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_KEY_EXCHANGE_FAILED)?;

        Ok((client_version, server_version))
    }

    fn key_exchange_init(
        &mut self,
        session: &SessionState,
    ) -> Result<(KexAlgorithms, KexAlgorithms), DisconnectCode> {
        // recv key algorithms
        let packet = self.recv()?;
        let (payload, _binary_packet) = BinaryPacket::from_bytes(&packet, &session)
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_KEY_EXCHANGE_FAILED)?;
        let (_input, server_kex_algorithms) = KexAlgorithms::parse_key_exchange_init(&payload)
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_KEY_EXCHANGE_FAILED)?;

        // send key algorithms
        let client_kex_algorithms = KexAlgorithms {
            cookie: rand::thread_rng().gen::<[u8; 16]>().to_vec(),
            kex_algorithms: server_kex_algorithms.kex_algorithms.clone(),
            server_host_key_algorithms: vec!["rsa-sha2-256".to_string()],
            encryption_algorithms_client_to_server: vec![
                "aes128-ctr".to_string(),
                // "aes256-gcm@openssh.com".to_string(),
            ],
            encryption_algorithms_server_to_client: vec![
                "aes128-ctr".to_string(),
                // "aes256-gcm@openssh.com".to_string(),
            ],
            mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
            mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
            compression_algorithms_client_to_server: server_kex_algorithms
                .compression_algorithms_client_to_server
                .clone(),
            compression_algorithms_server_to_client: server_kex_algorithms
                .compression_algorithms_server_to_client
                .clone(),
            languages_client_to_server: server_kex_algorithms.languages_client_to_server.clone(),
            languages_server_to_client: server_kex_algorithms.languages_server_to_client.clone(),
            first_kex_packet_follows: server_kex_algorithms.first_kex_packet_follows.clone(),
        };
        self.send(&BinaryPacket::new(&client_kex_algorithms.to_bytes()).to_bytes(session))?;

        Ok((client_kex_algorithms, server_kex_algorithms))
    }

    fn key_exchange<Method: KexMethod>(
        &mut self,
        session_id: &[u8],
        client_version: &Version,
        server_version: &Version,
        client_kex: &KexAlgorithms,
        server_kex: &KexAlgorithms,
        session: &SessionState,
    ) -> Result<Kex<Method>, DisconnectCode> {
        let mut method = Method::new();
        let payload = generate_key_exchange::<Method>(&method);
        let client_public_key = method.public_key();
        let packet = BinaryPacket::new(&payload).to_bytes(session);
        self.send(&packet)?;

        let key_exchange_packet = self.recv()?;
        let (payload, _binary_packet) = BinaryPacket::from_bytes(&key_exchange_packet, session)
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_KEY_EXCHANGE_FAILED)?;
        let (_input, (server_public_host_key, server_public_key)) = parse_key_exchange(payload)
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_KEY_EXCHANGE_FAILED)?;

        let shared_secret = method.shared_secret(&server_public_key);

        // New Keys
        let payload: Vec<u8> = vec![MessageCode::SSH_MSG_NEWKEYS.to_u8()];
        let packet = BinaryPacket::new(&payload).to_bytes(session);
        self.client
            .send(&packet)
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_KEY_EXCHANGE_FAILED)?;
        Ok(Kex::<Method>::new(
            method,
            session_id,
            &client_version,
            &server_version,
            client_kex,
            server_kex,
            &server_public_host_key,
            &client_public_key,
            &server_public_key,
            &shared_secret,
        ))
    }

    fn user_auth(&mut self, session: SessionState) -> Result<&[u8], DisconnectCode> {
        let auth = Authentication::new("anko", "test", "publickey");
        let packet = auth.to_bytes();
        // let packet = enc_server_to_client.generate_encrypted_packet(&packet);
        // let packet = enc_client_to_server.to_bytes(&packet);
        // self.client
        //     .send(&packet)
        //     .map_err(|_| DisconnectCode::SSH2_DISCONNECT_KEY_EXCHANGE_FAILED)?;

        Ok(&[])
    }

    pub fn send(&self, packet: &[u8]) -> Result<(), DisconnectCode> {
        self.client
            .send(packet)
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_CONNECTION_LOST)
    }

    pub fn recv(&mut self) -> Result<Vec<u8>, DisconnectCode> {
        self.client
            .recv()
            .map_err(|_| DisconnectCode::SSH2_DISCONNECT_CONNECTION_LOST)
    }
}

/*
00000639  00 00 00 0c 0a 15 00 00  00 00 00 00 00 00 00 00   ........ ........
00000649  bd dc f4 de 92 39 3e 83  d1 1a c5 70 4a c4 0b 7e   .....9>. ...pJ..~
00000659  a6 88 18 17 09 ad 4e b2  d8 cf f4 96 eb 80 41 c0   ......N. ......A.
00000669  cc d1 c5 24 df 6c ed 14  cc 6d b2 34               ...$.l.. .m.4
    000003B9  92 61 69 71 4a 66 80 93  be 23 0a 99 4d e9 75 c4   .aiqJf.. .#..M.u.
    000003C9  87 06 98 39 99 fb 85 04  ca cc 8d 69 54 45 52 fe   ...9.... ...iTER.
    000003D9  5e e4 b2 ab ec 3f da b9  4f 37 8d d4 d4 23 9b 7f   ^....?.. O7...#..
    000003E9  8c b5 92 da b9 ac d0 c0  1d 4b ab 74 38 24 f2 33   ........ .K.t8$.3
    000003F9  ca 03 a9 a2 72 30 bc 21  a8 e1 cf 56 cc 3d 41 cc   ....r0.! ...V.=A.
    00000409  f3 29 95 f7 98 ac 34 ea  a8 84 e0 49 bc 0a 1a 84   .)....4. ...I....
    00000419  8d 8e c8 c9 c6 7b 5b 5f  e6 81 a3 99 a1 ba 15 d9   .....{[_ ........
    00000429  97 a3 0f 79 c9 d8 ab f5  f5 be 90 44 69 7b 90 8a   ...y.... ...Di{..
    00000439  fb 01 8e b4 93 44 3e 73  25 f5 3d d9 3e 53 76 43   .....D>s %.=.>SvC
    00000449  38 fe 7f 7e b6 61 05 b9  f8 90 b6 2c 4e f3 62 da   8..~.a.. ...,N.b.
    00000459  5a 56 24 99 00 4f e3 d1  cc 82 de c9 34 63 ee 51   ZV$..O.. ....4c.Q
    00000469  c2 5a d0 50 3d e1 58 9e  c0 74 bd a7 c7 f8 dc 53   .Z.P=.X. .t.....S
    00000479  69 3d b8 9d ed 6e c5 e4  c9 5d ce e4 ff 09 0d 3f   i=...n.. .].....?
    00000489  cb 8e 05 4c 61 c9 f7 55  5f d3 13 d0 9b 30 8d 35   ...La..U _....0.5
    00000499  dc 41 21 42 46 3c 42 b5  84 d7 d6 40 66 2e ee 2a   .A!BF<B. ...@f..*
    000004A9  4f 30 72 bf e4 e1 ed 2a  9b ac b0 21 8f 14 4d 76   O0r....* ...!..Mv
    000004B9  66 d5 93 7f e3 05 ab 93  8c 28 de 73 ce c7 ea d9   f....... .(.s....
    000004C9  24 f6 fb c6 44 fe 5c 35  7d 76 4e e8 c3 82 d0 94   $...D.\5 }vN.....
    000004D9  50 3b e8 ad af 06 d0 5e  99 61 35 e5 52 a0 0d 1b   P;.....^ .a5.R...
    000004E9  fc 71 e2 e2 f5 bf ec 3c  4b 3e 21 d0 d4 c0 e0 97   .q.....< K>!.....
    000004F9  3b 4d 1a d1 c6 2f 56 a1  4c 5e 3f 9c d3 ba 8b 0e   ;M.../V. L^?.....
    00000509  7b 25 c7 c8 65 ae 63 4b  f2 49 73 6d b8 5a 44 7f   {%..e.cK .Ism.ZD.
    00000519  a2 ab dd 4d f3 bc 49 d2  3c a4 ca ab 4c e9 ba cb   ...M..I. <...L...
    00000529  c2 15 3f 21 34 b7 ee 68  10 f1 af 2e 6e b5 21 20   ..?!4..h ....n.!
    00000539  40 de b7 d1 31 ee 47 c6  61 a8 69 bb 47 18 45 af   @...1.G. a.i.G.E.
    00000549  0c 53 bc ee ea b9 0b 6c  73 6d c2 89 95 77 ad 47   .S.....l sm...w.G
    00000559  eb a1 94 4b c7 43 4a fa  8b f5 8d 9a 53 e1 39 8c   ...K.CJ. ....S.9.
    00000569  7c 31 91 c2 88 dd 4a 45  b4 f4 cc 10 92 0b 67 70   |1....JE ......gp
    00000579  05 da 32 eb 2d b9 ed 5d  cc 27 3d e3 7f 9d 36 9c   ..2.-..] .'=...6.
    00000589  fb 27 bb 17 8d 33 cd 0d  99 e6 ad d3 ae 10 22 a0   .'...3.. ......".
    00000599  b8 12 be 78 dc 44 ac 79  b3 41 11 aa 7a 0e b4 af   ...x.D.y .A..z...
    000005A9  cc d7 97 10 74 58 03 62  f8 3e 28 be 68 96 c9 87   ....tX.b .>(.h...
    000005B9  22 bf 0f 2f 63 c0 c4 77  b0 4d af c0 34 0f e2 69   "../c..w .M..4..i
    000005C9  20 fc 5f 99 d8 3c 99 f4  f7 0c 5c be b1 da 22 61    ._..<.. ..\..."a
    000005D9  05 d5 12 9c ba b1 00 93  1b c6 22 f5               ........ ..".
    000005E5  dd 2f 74 ce 6c 8f d2 bd  aa d4 7e 9b f1 43 2a 6c   ./t.l... ..~..C*l
    000005F5  ca 5f 68 63 81 64 b4 50  6c 44 86 35 16 25 d1 78   ._hc.d.P lD.5.%.x
    00000605  1a c3 c4 68 c6 08 11 11  51 06 94 7d               ...h.... Q..}
00000675  b0 f3 f1 9d 47 53 b4 64  13 fd 78 ea 73 d6 94 3f   ....GS.d ..x.s..?
00000685  dc c6 5d 26 d7 15 ff a5  05 91 72 c0 3d 48 cb 83   ..]&.... ..r.=H..
00000695  87 f5 12 c5 4f 09 56 91  23 de f0 29 ab e4 50 1e   ....O.V. #..)..P.
000006A5  a4 74 ec 68 ff 22 67 20  dd 3d 22 55               .t.h."g  .="U
    00000611  ce 25 92 43 86 bc 6a 13  61 63 6a df d2 f9 f3 c4   .%.C..j. acj.....
    00000621  04 5f c5 1c 13 db 95 5f  04 dd 5e f7 8b 1a 0c 9f   ._....._ ..^.....
    00000631  af de 5e 3a 17 b6 9a ff  0f ff ea 54               ..^:.... ...T
000006B1  fa 55 8b 74 21 c3 d5 cb  97 89 f7 da 3a 18 83 78   .U.t!... ....:..x
000006C1  c6 21 f5 27 fc e1 59 3e  6e 8c 7a 79 5f df 76 6d   .!.'..Y> n.zy_.vm
000006D1  9e 31 50 a0 d0 67 5c 5d  fb 3f 82 c7 0f 16 ca 0d   .1P..g\] .?......
000006E1  4e b8 cc 41 f7 8f 42 d6  34 15 21 15 3c 2a 3a 7c   N..A..B. 4.!.<*:|
000006F1  b6 b2 d1 c7 23 7f 02 ac  19 5f f8 3d 47 1b 7b c2   ....#... ._.=G.{.
00000701  9e b1 32 37 ff 9e cb a6  32 74 ba b8 42 58 f7 1c   ..27.... 2t..BX..
00000711  cd 95 b8 cb d8 07 b6 c8  f1 3a 0a cc 7c cd 79 21   ........ .:..|.y!
00000721  5b f2 df 1b 3f d4 94 77  c7 93 6d a2 38 41 5c 82   [...?..w ..m.8A\.
00000731  db d2 84 5a 2f 6b 03 b4  b0 cb 82 6a d0 75 7e a0   ...Z/k.. ...j.u~.
00000741  3a 7d cb 17 94 cb da 5b  d1 84 f1 6f 32 ad 4d d0   :}.....[ ...o2.M.
00000751  a6 3a 41 73 39 58 f2 f7  cd c3 b3 17 2a 8d 3d 8c   .:As9X.. ....*.=.
00000761  52 b5 58 46 56 ce c2 85  3a 4c 73 fc 98 df 04 d7   R.XFV... :Ls.....
00000771  c0 c2 24 7b dd 05 72 c6  d6 1d ca f8 bb 42 11 af   ..${..r. .....B..
00000781  29 08 e2 48 26 23 4f 52  4f fc 7d fb 15 35 f2 43   )..H&#OR O.}..5.C
00000791  56 b0 89 99 2d 0f 76 b3  cf 02 56 94 07 73 42 55   V...-.v. ..V..sBU
000007A1  25 81 63 8a 82 3b 70 db  3a 05 56 82 7b c2 31 5d   %.c..;p. :.V.{.1]
000007B1  16 32 2f 90 e4 0a 56 86  1d 12 d8 77 31 35 65 66   .2/...V. ...w15ef
000007C1  14 42 1d 91 af e0 07 77  35 c0 15 df a7 f0 f9 35   .B.....w 5......5
000007D1  95 41 26 1e b3 33 f4 c4  cd e6 ba 2d 05 f1 14 38   .A&..3.. ...-...8
000007E1  9e e7 16 8a a3 0f e7 a3  fe 81 1e dc 7b 7e b5 6c   ........ ....{~.l
000007F1  be 6c a2 70 41 8b 34 2c  5e 87 95 11 e8 08 c6 f8   .l.pA.4, ^.......
00000801  8c 91 86 07 12 d5 78 93  ab f0 00 5b 3c 43 9c 44   ......x. ...[<C.D
00000811  bc 93 8e 3a 9e 71 00 8c  a6 d4 e4 0f 4d 83 45 92   ...:.q.. ....M.E.
00000821  cd e1 4d 24 61 1d 50 9c  69 b2 30 1f fc 0d e1 f0   ..M$a.P. i.0.....
00000831  d7 9d 01 6a 04 37 c4 8f  c8 b3 fa 81 cf 7a bb bc   ...j.7.. .....z..
00000841  74 b5 ce 81 ba 2e 05 ef  80 86 59 4e ba 85 7f 94   t....... ..YN....
00000851  52 26 49 ce 08 d7 3f c9  5c 33 f1 a9 8c 61 f2 49   R&I...?. \3...a.I
00000861  70 50 d7 c2 45 2b 4a 76  f3 83 dd 8a 39 4d b6 ab   pP..E+Jv ....9M..
00000871  c7 72 32 48 15 91 45 03  28 16 0a f3 d6 7d a3 67   .r2H..E. (....}.g
00000881  fe b1 53 69 98 4f b2 da  17 f9 54 47 85 5a 34 06   ..Si.O.. ..TG.Z4.
00000891  f5 9f 68 3e f5 c0 42 4a  7f 2d f2 1a               ..h>..BJ .-..
    0000063D  dc ea 5a 9e ac e7 60 87  4e ab b8 1f e6 04 b6 6a   ..Z...`. N......j
    0000064D  dc 20 b5 1c d7 5a 59 43  4b 2c 7a 22 78 91 9b 34   . ...ZYC K,z"x..4
    0000065D  cb 6d 4b fe 9b 1d b3 7d  ee 5d 8c 5c               .mK....} .].\
0000089D  ce e4 3f 96 28 46 a8 ff  ec 70 dd 96 73 a5 50 cb   ..?.(F.. .p..s.P.
000008AD  e8 5b 17 25 63 26 d8 a4  2e 08 1e 09 ec 1c c8 ea   .[.%c&.. ........
000008BD  fe fa d8 13 02 a5 a9 1c  1e 91 00 83 11 5a 4e 03   ........ .....ZN.
000008CD  08 0d a5 35 8f 75 a2 5b  5c a8 bc cb 02 5b 97 16   ...5.u.[ \....[..
000008DD  64 b3 79 68 3d 58 2d 75  12 1c 5e 74 cb a2 32 3d   d.yh=X-u ..^t..2=
000008ED  e1 97 d8 2d bd 63 bd 61  b7 0b d4 e8 b9 ee 00 7f   ...-.c.a ........
000008FD  27 af 50 51 fc 82 37 e7  51 aa 89 aa 0f 5e 5f 15   '.PQ..7. Q....^_.
0000090D  eb e8 d1 c1 af f4 f8 f2  39 fc d3 9b 2d 3b c0 cb   ........ 9...-;..
0000091D  bf 33 c7 2b 23 aa f7 22  54 af ac 0b               .3.+#.." T...
    00000669  9d 0c 28 9f 75 03 f4 80  d6 03 62 16 89 98 3a 27   ..(.u... ..b...:'
    00000679  28 64 54 24 6d 7d e5 6f  65 07 04 9c a9 64 22 cc   (dT$m}.o e....d".
    00000689  e2 fd a5 43 fd 64 ca 70  a8 99 89 b3 53 49 92 3b   ...C.d.p ....SI.;
    00000699  b3 86 b9 ba 47 66 45 0d  44 c8 dd d7 9f da e1 1d   ....GfE. D.......
    000006A9  cf ad 59 dc bc 08 f4 29  c4 30 34 c8 4c dd c5 8c   ..Y....) .04.L...
    000006B9  a0 d1 6f c3 f4 38 f3 87  18 0f d4 bd 09 50 39 a3   ..o..8.. .....P9.
    000006C9  1a e3 b7 ac                                        ....
00000929  df b6 de 1f c4 bb b7 58  1e ae 23 11 20 b4 4e 66   .......X ..#. .Nf
00000939  fd e7 e5 52 5c 96 ef d1  da 38 a0 f9 3a 13 49 c9   ...R\... .8..:.I.
00000949  f5 07 ee 4b 46 b8 9d fd  d3 fd 83 39 23 77 fe e3   ...KF... ...9#w..
00000959  75 c4 02 92 6e b6 dd e1  db 1a 01 c7 93 9d ee d0   u...n... ........
00000969  7a 16 22 7e 38 01 d9 ce  e3 0d 2b dc d9 e4 d3 bd   z."~8... ..+.....
00000979  55 2e e5 54 e1 18 01 67  f0 28 4c 2f e1 c6 ab 87   U..T...g .(L/....
00000989  69 0a e2 4d 3b 49 47 e3  07 99 6a 5a 20 f1 b4 2e   i..M;IG. ..jZ ...
00000999  91 86 50 7a 4c b3 51 02  43 05 0d 9e 4f 28 a8 23   ..PzL.Q. C...O(.#
000009A9  c6 2a cf 60 38 57 3d 31  9f 7f cc a5 c9 f3 1e e1   .*.`8W=1 ........
000009B9  da da 49 3f 52 e4 6f 00  c7 50 a3 34 a0 e2 f3 bb   ..I?R.o. .P.4....
000009C9  85 7e df f1 b4 4d 18 38  5b fa f1 6b 3f f1 e1 41   .~...M.8 [..k?..A
000009D9  7d 0e d1 b4 75 32 62 0d  19 59 c2 d9 fb 12 ee 18   }...u2b. .Y......
000009E9  42 48 a8 9b ea 74 62 02  89 30 8b 08 39 02 35 97   BH...tb. .0..9.5.
000009F9  62 5f ce 62 fa a6 c6 5e  02 2d e6 df 80 44 ef 92   b_.b...^ .-...D..
00000A09  52 61 c0 8c                                        Ra..
    000006CD  f9 8b a8 eb a4 82 ac fa  d7 32 6a e0 dd ce 12 ac   ........ .2j.....
    000006DD  f9 82 4c af aa e1 f9 d2  f3 00 ea 36               ..L..... ...6
    000006E9  b9 a0 89 f1 6a 92 e0 78  85 ab 83 a9 54 ae 27 14   ....j..x ....T.'.
    000006F9  e0 e1 db 87 fa c7 83 12  25 a4 cc 8c b4 d6 f8 6d   ........ %......m
    00000709  47 71 ea a4 81 29 58 61  4b f6 72 90 ea 4c 3c 57   Gq...)Xa K.r..L<W
    00000719  7c 74 16 0b 0d 3c f1 11  85 7b 4c 8a 01 3a 66 0d   |t...<.. .{L..:f.
    00000729  39 29 f2 02 a4 1a 49 d0  c3 27 22 35 06 c4 ea 18   9)....I. .'"5....
    00000739  21 1d 0d aa b1 1c 83 df  12 93 16 a7 c0 30 a7 f5   !....... .....0..
    00000749  95 83 75 d8 dd ce b2 12  30 14 c7 3e 12 0a ff 97   ..u..... 0..>....
    00000759  db a5 e2 95 56 f2 c5 ec  40 e4 1d e2 34 c1 44 45   ....V... @...4.DE
    00000769  bf 29 87 6f 9d 7b 4a 1c  02 59 01 17 b1 2e 38 08   .).o.{J. .Y....8.
    00000779  c7 6d 95 50 d4 fa 2c 00  b3 0d 66 d1 48 05 35 8e   .m.P..,. ..f.H.5.
    00000789  aa aa 12 1a c9 92 db 66  29 1f d0 8b 9d b1 b8 2f   .......f )....../
    00000799  ab ac 58 37 49 83 8c a4  8e c3 1b e9 ca bc a6 05   ..X7I... ........
    000007A9  21 0d fc 4f 27 4f 95 d0  41 07 79 48 bd af a2 21   !..O'O.. A.yH...!
    000007B9  71 0b 4f 65 ea 24 fc 23  50 34 f4 1c f5 c0 02 d2   q.Oe.$.# P4......
    000007C9  ec c9 e3 3f 1a ba 7c 29  58 28 20 8b 67 74 82 cf   ...?..|) X( .gt..
    000007D9  82 5d 1f a5 c2 4f 6d 86  2d 1f b6 1a 63 8b 8e 5a   .]...Om. -...c..Z
    000007E9  dc b7 7e 04 02 99 42 6e  04 4b b5 59 0e 77 f9 70   ..~...Bn .K.Y.w.p
    000007F9  7b f0 92 f3 5f fd 5a 6c  58 bc 08 43 89 07 c0 c2   {..._.Zl X..C....
    00000809  7f 9a e5 7f 2c 28 26 ae  37 6d 09 b7 de c9 2c 94   ....,(&. 7m....,.
    00000819  cc 73 12 0d fe 64 fc 0d  a2 5c 09 08 1e a8 d5 53   .s...d.. .\.....S
    00000829  5b 42 3e 11 0b 9b 06 fa  f8 0e ee 58 5e 50 51 c7   [B>..... ...X^PQ.
    00000839  d0 fb 2f 36 f3 17 3b e3  9e d0 35 68 e8 40 8a 86   ../6..;. ..5h.@..
    00000849  53 12 5b 83 9c b9 1f 1a  e2 23 87 e3 ee 70 ee 96   S.[..... .#...p..
    00000859  27 40 91 9b 26 21 1b c6  49 bb 7e aa 10 82 14 50   '@..&!.. I.~....P
    00000869  37 97 03 8d e1 e3 d1 22  ba d5 be 73 9b 39 60 19   7......" ...s.9`.
    00000879  6e fb 11 1a 57 06 e7 4d  64 ab 22 fe e0 f1 a4 73   n...W..M d."....s
    00000889  d6 7c c1 ea 84 9b 6e 1c  2e 50 27 60 f8 4c a9 d3   .|....n. .P'`.L..
    00000899  5b 83 f3 37 55 1b f1 b2  7b 53 2c d9 49 c0 87 d7   [..7U... {S,.I...
    000008A9  7b b4 69 83 be 31 f7 08  64 ce 38 74 3f 06 2a 76   {.i..1.. d.8t?.*v
    000008B9  81 d3 c8 0b 8d 65 35 6c  98 61 6c a1 25 2b 01 03   .....e5l .al.%+..
    000008C9  eb 15 2f c4 82 8b e1 12  f3 c7 05 b7 29 4c a0 af   ../..... ....)L..
    000008D9  05 83 dd 89 e0 8c 9a 8b  5a fc 96 a3 8c 74 f0 39   ........ Z....t.9
    000008E9  23 8b 88 9c 84 d6 00 d5  b2 cb 4c 73 6e 32 e4 a6   #....... ..Lsn2..
    000008F9  32 6a ce 2d 86 5c c6 d9  aa 81 7c b0 d5 03 47 00   2j.-.\.. ..|...G.
    00000909  59 d9 46 c5 83 cf 83 d7  0f 3e d3 46 5e 87 9e 7b   Y.F..... .>.F^..{
    00000919  b6 63 43 ba 60 80 53 f7  83 96 43 a7 2f fe 3b f6   .cC.`.S. ..C./.;.
    00000929  3b fd 59 3d 5b d7 29 55  8b d7 fe 37 4f 6c 9d 1b   ;.Y=[.)U ...7Ol..
    00000939  15 bd 28 bc 44 f2 71 c3  d9 7f 5e 50 35 ba 95 9c   ..(.D.q. ..^P5...
    00000949  95 93 e3 a7 ce 3e 9a cd  9a ff b4 79 71 c0 63 48   .....>.. ...yq.cH
    00000959  1f c2 b4 8a                                        ....
00000A0D  f7 d8 e4 62 29 9f 17 e6  2f fd 5a 34 c6 48 d5 98   ...b)... /.Z4.H..
00000A1D  43 4e 14 70 be 87 a2 0e  82 39 4d e7 4c b6 86 de   CN.p.... .9M.L...
00000A2D  5a d3 78 b4 ce 9f 0a c8  c9 65 c9 b6 68 85 79 c6   Z.x..... .e..h.y.
00000A3D  0d 52 da 43                                        .R.C
    0000095D  73 b5 ea a5 97 b7 bc 6e  08 82 6e d7 5b c2 46 cd   s......n ..n.[.F.
    0000096D  6c 44 8f 23 7a cc 86 98  97 09 6f ca bd 44 64 04   lD.#z... ..o..Dd.
    0000097D  19 01 53 fc c0 a2 4b 2e  1c 7d bf 67               ..S...K. .}.g
00000A41  0c ff 8d 2b f2 7a ef 38  70 ef bc 8b 63 36 1a c0   ...+.z.8 p...c6..
00000A51  e7 29 9f 49 71 f8 58 83  41 16 fb 3d a9 fe 2d dc   .).Iq.X. A..=..-.
00000A61  0c 6d e4 6d c7 9a ee 77  dd 23 53 62 f9 8d 76 3b   .m.m...w .#Sb..v;
00000A71  38 a3 34 50 b7 f2 8f c8  0a 92 f9 76 6b de b1 e1   8.4P.... ...vk...
00000A81  90 b2 26 2b 15 30 b3 f9  3e e5 5d f9 e3 71 44 0d   ..&+.0.. >.]..qD.
00000A91  e8 1c fe 5c 77 39 e3 f2  1c 52 b4 99 ae d3 9f e1   ...\w9.. .R......
00000AA1  5f 25 71 36 53 9f 07 7d                            _%q6S..}
    00000989  39 d2 f7 66 71 9c 32 22  4f 19 a7 a3 14 08 07 50   9..fq.2" O......P
    00000999  fa 81 4a cb f5 94 21 c5  ab 90 17 dc 2e 7a cd a0   ..J...!. .....z..
    000009A9  2d 0b 76 21                                        -.v!
    000009AD  5d 25 bd d0 36 0c d3 49  ba 36 13 1a f3 b0 e8 a1   ]%..6..I .6......
    000009BD  6e 59 fd 22 0c 22 46 8c  a7 7b 7d 99 54 35 1c 05   nY."."F. .{}.T5..
    000009CD  65 6c d0 3f d6 51 c3 99  8e 95 54 df e1 7b dc ba   el.?.Q.. ..T..{..
    000009DD  85 7c 3e 77 89 25 71 b0  fa d9 a8 67 b0 b9 75 1a   .|>w.%q. ...g..u.
    000009ED  d3 ba 49 ae 61 ca 94 db  75 a1 83 fc 3b 5f 1a 7e   ..I.a... u...;_.~
    000009FD  24 1d 65 17 26 cb 5e 5c  cb 16 6f eb 14 1f dd 9f   $.e.&.^\ ..o.....
    00000A0D  a7 6e 68 b1 76 ca 8e 06  7f c5 dc 46 c7 f8 c8 f7   .nh.v... ...F....
    00000A1D  a5 18 1e eb 76 8c 2f 10  a0 d8 35 30 bc ec cf 4a   ....v./. ..50...J
    00000A2D  73 ec 1e 7e 8d 93 26 e3  e2 63 3a 16 6e 27 0b c7   s..~..&. .c:.n'..
    00000A3D  5a 92 da 08 b6 ab ac 0d  57 7e 5c 33 7d f8 a9 91   Z....... W~\3}...
    00000A4D  d3 3c 16 ca e6 f5 e3 04  53 09 20 05 cf 1c e4 17   .<...... S. .....
    00000A5D  b6 6c ef ae ca 81 c0 cf  1e 8e 69 25 78 d9 8c 81   .l...... ..i%x...
    00000A6D  6d 23 20 d2 87 bc 80 61  50 b8 4c 5f c7 20 94 4d   m# ....a P.L_. .M
    00000A7D  2b 6e 96 94 05 91 62 25  b6 23 7a 0c d2 15 19 17   +n....b% .#z.....
    00000A8D  01 e9 7d 61 da 03 e3 3e  37 d9 89 96 5b 7f 94 6f   ..}a...> 7...[..o
    00000A9D  28 da e4 b6 b1 65 01 d9  66 7a d8 e8 72 82 77 b5   (....e.. fz..r.w.
    00000AAD  79 35 f4 63 16 20 42 f1  e3 b3 1a ea 42 a0 78 7d   y5.c. B. ....B.x}
    00000ABD  6c a8 0d 4d 36 15 22 9a  e1 5d a8 fe 8e c1 e2 86   l..M6.". .]......
    00000ACD  03 67 74 b2 46 88 4b c9  7c 7e e3 99               .gt.F.K. |~..
    00000AD9  ef 72 73 66 42 05 e6 87  f5 10 87 57 e8 3b 3a 38   .rsfB... ...W.;:8
    00000AE9  fa 05 38 ed be 56 d2 d0  ad 38 ce 9f 28 0a b1 64   ..8..V.. .8..(..d
    00000AF9  ee 15 e7 18 57 af 55 68  a0 02 8d ee b0 85 13 4c   ....W.Uh .......L
    00000B09  f2 38 b2 48                                        .8.H
    00000B0D  ae 6d 36 da 47 a8 e8 9e  f7 d6 20 f4 bf 0e ef aa   .m6.G... .. .....
    00000B1D  f2 a1 2e d9 f5 4c a6 9f  8e 65 6e 5c 5d 7d 32 fd   .....L.. .en\]}2.
    00000B2D  a5 5b 9c 9a cc e4 ca d2  63 22 48 18 df 07 05 0e   .[...... c"H.....
    00000B3D  6f 88 44 32 4c a6 76 7b  af d0 f1 5e bb e0 f4 65   o.D2L.v{ ...^...e
    00000B4D  76 be 3d 1b 75 f6 21 77                            v.=.u.!w
00000AA9  e7 42 fd 0c bc 7d 39 9b  b6 23 18 87 d0 8e 0a f0   .B...}9. .#......
00000AB9  9a 48 e7 55 da b0 64 70  aa ef 75 24 3b 15 c1 44   .H.U..dp ..u$;..D
00000AC9  20 b3 06 db                                         ...
00000ACD  5d 95 71 5a b1 ae 71 9d  81 80 f2 42 35 6f d1 fd   ].qZ..q. ...B5o..
00000ADD  b3 eb b8 01 e1 59 b2 26  2e 03 af 67 7d 4d 3b a7   .....Y.& ...g}M;.
00000AED  8f 89 ba 49 38 e0 10 55  1a 6a c6 85 9c 1c eb 50   ...I8..U .j.....P
00000AFD  10 a5 65 03 4f fd 91 06  6e 3e f3 f5               ..e.O... n>..
 */

// [hasshServerAlgorithms [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256;chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gc]
// [hasshServer: d5037e2b5d0a751478bc339d1cf024a8]

/*
- hmac-sha1 REQUIRED HMAC-SHA1 (digest length = key length = 20)
- hmac-sha1-96 RECOMMENDED first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
*/

/*
ssh-dss REQUIRED sign Raw DSS Key
ssh-rsa RECOMMENDED sign Raw RSA Key
 */
