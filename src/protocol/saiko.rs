// use crate::crypto::Kex;

// use super::data::NameList;

// macro_rules! create_wrapped_type {
//     ($name: ident, $value_type: ty) => {
//         #[derive(Clone, Default)]
//         pub(crate) struct $name(Vec<$value_type>);
//         impl Deref for $name {
//             type Target = Vec<$value_type>;
//             fn deref(&self) -> &Self::Target {
//                 &self.0
//             }
//         }

//         impl DerefMut for $name {
//             fn deref_mut(&mut self) -> &mut Self::Target {
//                 &mut self.0
//             }
//         }

//         impl Display for $name {
//             fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//                 write!(
//                     f,
//                     "{}",
//                     self.iter()
//                         .map(|&x| x.as_ref().to_owned())
//                         .collect::<Vec<String>>()
//                         .join(",")
//                 )
//             }
//         }

//         impl TryFrom<Vec<String>> for $name {
//             type Error = SshError;
//             fn try_from(v: Vec<String>) -> Result<Self, Self::Error> {
//                 let v = v
//                     .iter()
//                     .filter_map(|x| <$value_type>::from_str(x.as_str()).ok())
//                     .collect::<Vec<$value_type>>();
//                 Ok(Self(v))
//             }
//         }

//         impl From<Vec<$value_type>> for $name {
//             fn from(v: Vec<$value_type>) -> Self {
//                 Self(v)
//             }
//         }
//     };
// }

// create_wrapped_type!(Kexs, Kex);
// #[derive(Debug, Clone)]
// pub struct KexAlgorithms {
//     pub cookie: [u8; 16],
//     pub kex_algorithms: Kexs,
//     pub server_host_key_algorithms: NameList,
//     pub encryption_algorithms_client_to_server: NameList,
//     pub encryption_algorithms_server_to_client: NameList,
//     pub mac_algorithms_client_to_server: NameList,
//     pub mac_algorithms_server_to_client: NameList,
//     pub compression_algorithms_client_to_server: NameList,
//     pub compression_algorithms_server_to_client: NameList,
//     pub languages_client_to_server: NameList,
//     pub languages_server_to_client: NameList,
//     pub first_kex_packet_follows: bool,
//     pub reserved: u32,
// }
