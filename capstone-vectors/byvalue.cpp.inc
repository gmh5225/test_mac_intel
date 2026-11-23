extern "C" bool X86_disasmOneText(csh,const uint8_t *,size_t,uint64_t,cs_insn *);
// The consumer keeps its own byte position and uses the returned record size.
template <bool One>
static inline bool consume_record(csh h,const uint8_t **p,size_t *n,uint64_t *address,cs_insn *record) {
    bool ok;
    if constexpr(One) {
        ok=X86_disasmOneText(h,*p,*n,*address,record);
    } else {
        const uint8_t *cursor=*p;
        size_t left=*n;
        uint64_t pc=*address;
        ok=X86_disasmIterText(h,&cursor,&left,&pc,record);
    }
    if (ok) {
        *p+=record->size;
        *n-=record->size;
        *address+=record->size;
    }
    return ok;
}
