extern "C" X86ScanBatchResult X86_scanBatch64(csh, const uint8_t *, size_t, uint64_t, uint32_t *, size_t) __attribute__((weak));
extern "C" X86ScanBatchResult X86_scanBatch32(csh, const uint8_t *, size_t, uint64_t, uint32_t *, size_t) __attribute__((weak));
template <bool Audit, auto Next = X86_scanBatch>
static Result batch_span(const uint8_t *bytes, size_t size, csh handle, cs_insn *insn, uint64_t start_ip) {
  Result out;
  size_t pos=0;
  while(pos<size) {
    uint32_t packed[64];
    const auto got=Next(handle,bytes+pos,size-pos,start_ip+pos,packed,64);
    if(got.count) {
      size_t initial=pos;
      if constexpr(Audit) if(got.count>64)throw std::runtime_error("batch capacity");
      for(size_t i=0;i<got.count;++i) {
        const unsigned n=packed[i]&255, id=packed[i]>>8;
        if constexpr(Audit) {
          const uint8_t *p=bytes+pos;size_t left=size-pos;uint64_t ip=start_ip+pos;
          if(!n || n>left || !cs_disasm_iter(handle,&p,&left,&ip,insn) || n!=insn->size ||
             id!=insn->id || p!=bytes+pos+n || left!=size-pos-n || ip!=start_ip+pos+n)
            throw std::runtime_error("batch/public record mismatch");
        }
        record(out,pos,n,true);out.values+=id;pos+=n;
      }
      if constexpr(Audit) if(pos-initial!=got.bytes)throw std::runtime_error("byte count");
      continue;
    }
    const uint8_t *p=bytes+pos;size_t left=size-pos;uint64_t ip=start_ip+pos;
    bool ok=cs_disasm_iter(handle,&p,&left,&ip,insn);
    unsigned n=ok?insn->size:1;
    record(out,pos,n,ok);
    if(ok)out.values+=insn->id;
    pos+=n;
  }
  return out;
}
