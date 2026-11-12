#[no_mangle]
pub unsafe extern "C" fn iced_trace(input:*const u8, length:usize, ip:u64, output:*mut u8)->usize {
    let bytes = std::slice::from_raw_parts(input,length);
    let out = std::slice::from_raw_parts_mut(output,length);
    let mut decoder=Decoder::with_ip(64,bytes,ip,DecoderOptions::NONE);
    let mut instruction=Instruction::default();
    let mut count=0;
    while decoder.can_decode() {
        let offset=decoder.position();
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            out[count]=0;
            decoder.set_position(offset+1).unwrap();
            decoder.set_ip(ip+offset as u64+1);
        } else { out[count]=instruction.len() as u8; }
        count+=1;
    }
    count
}
