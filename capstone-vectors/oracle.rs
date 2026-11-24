use iced_x86::{Decoder,DecoderOptions,OpKind};
use std::io::{self,BufRead,BufWriter,Write};
fn main(){
    let mut out=BufWriter::new(io::stdout().lock());
    for row in io::stdin().lock().lines(){
        let row=row.unwrap();
        let (bits,code)=row.split_once(' ').unwrap();
        let raw=if code=="-"{""}else{code};
        let bytes:Vec<_>=(0..raw.len()).step_by(2).map(|i|u8::from_str_radix(&raw[i..i+2],16).unwrap()).collect();
        let i=Decoder::with_ip(bits.parse().unwrap(),&bytes,0x1000,DecoderOptions::NONE).decode();
        if i.is_invalid(){writeln!(out,"-").unwrap();continue}
        write!(out,"{} {}",i.len(),format!("{:?}",i.mnemonic()).to_lowercase()).unwrap();
        for n in 0..i.op_count(){
            // Capstone publishes the memory destination of MASKMOVDQU implicitly.
            if i.mnemonic() == iced_x86::Mnemonic::Maskmovdqu && n == 0 {
                assert!(matches!(i.op_kind(n), OpKind::MemorySegDI | OpKind::MemorySegEDI | OpKind::MemorySegRDI));
                continue;
            }
            let k=match i.op_kind(n){OpKind::Register=>format!("r{:?}",i.op_register(n)).to_lowercase(),OpKind::Memory=>format!("m{}",i.memory_size().size()),_=>"i".to_string()};
            write!(out," {}",k).unwrap();
        }
        writeln!(out).unwrap();
    }
}
