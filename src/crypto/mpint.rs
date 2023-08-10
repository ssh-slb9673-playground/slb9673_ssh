pub fn to_mpint(input: &[u8]) -> Vec<u8> {
    let mut input = input.to_vec();
    if input[0] >= 0x80 {
        input.insert(0, 0x0);
    }
    input
}
