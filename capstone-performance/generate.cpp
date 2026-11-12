// Exercise all encodings of each admitted /r form against the unmodified library.
#include <capstone/capstone.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

constexpr size_t detail_size = offsetof(cs_detail, x86) + sizeof(cs_x86);
struct Reg { unsigned id; char name[8]; };
struct Record {
	unsigned id;
	char mnemonic[CS_MNEMONIC_SIZE];
	std::array<unsigned char, detail_size> detail;
};
struct Decoder {
	csh handle = 0;
	cs_insn *insn;
	explicit Decoder(bool wide) {
		if (cs_open(CS_ARCH_X86, wide ? CS_MODE_64 : CS_MODE_32, &handle) ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) || !(insn = cs_malloc(handle)))
			throw std::runtime_error("init");
	}
	~Decoder() { cs_free(insn, 1); cs_close(&handle); }
	bool decode(unsigned prefix, unsigned opcode, unsigned modrm) {
		uint8_t storage[] = {static_cast<uint8_t>(prefix), static_cast<uint8_t>(opcode), static_cast<uint8_t>(modrm)};
		const uint8_t *p = storage + !prefix; size_t n = prefix ? 3 : 2;
		uint64_t va = UINT64_MAX - 1;
		return cs_disasm_iter(handle, &p, &n, &va, insn) && !n && insn->size == 2 + !!prefix;
	}
};
static void emit_bytes(const unsigned char *v, size_t n) {
	while (n > 1 && !v[n-1]) --n;
	putchar('{');
	for (size_t i=0;i<n;++i) std::printf("%s%u",i?",":"",v[i]);
	putchar('}');
}
static bool selected(unsigned op) {
	return (op < 0x40 && (op & 7) <= 3) || (op >= 0x84 && op <= 0x8b);
}
static unsigned form(unsigned op, unsigned prefix) {
	return (op & 1) ? ((prefix & 8) ? 3 : 2) : (prefix != 0);
}
static Record normalized(cs_insn *i) {
	Record out{};
	out.id=i->id; memcpy(out.mnemonic,i->mnemonic,sizeof(out.mnemonic));
	cs_detail copy=*i->detail;
	copy.x86.rex=0; copy.x86.modrm=0;
	copy.x86.operands[0].reg=X86_REG_INVALID;copy.x86.operands[1].reg=X86_REG_INVALID;
	memcpy(out.detail.data(), &copy, detail_size);
	return out;
}
int main() {
	Reg regs[4][16] = {};
	unsigned short plans[2][3][256] = {};
	std::vector<Record> rows(1);
	Decoder x64(true),x32(false);
	for(unsigned category=0;category<4;++category) {
		for(unsigned idx=0;idx<(category==0 ? 8u : 16u);++idx) {
			unsigned prefix=category==0 ? 0 : (0x40 | (idx>=8 ? 5:0) | (category==3?8:0));
			if(!x64.decode(prefix,category<2?0x88:0x89,0xc0|(idx&7)*9))return 2;
			auto &dst=x64.insn->detail->x86.operands[0];auto &src=x64.insn->detail->x86.operands[1];
			if(dst.type!=X86_OP_REG || src.type!=X86_OP_REG || dst.reg!=src.reg)return 3;
			Reg &v=regs[category][idx];v.id=dst.reg;
			const char *name=cs_reg_name(x64.handle,dst.reg);if(!name||strlen(name)>=sizeof(v.name))return 4;
			strcpy(v.name,name);
		}
	}
	unsigned comparisons=0,admitted=0,rejected=0;
	for (unsigned wide=0;wide<2;++wide) for(unsigned cls=0;cls<(wide?3u:1u);++cls) {
		Decoder &d=wide?x64:x32;
		unsigned first=cls==0?0:(cls==1?0x40:0x48),last=cls?first+7:first;
		for(unsigned op=0;op<256;++op) {
			if(!selected(op))continue;
			if(!d.decode(first,op,0xc1))return 5;
			unsigned cat=form(op,first);auto *ops=d.insn->detail->x86.operands;
			if(d.insn->detail->x86.op_count!=2 || ops[0].type!=X86_OP_REG || ops[1].type!=X86_OP_REG) { ++rejected;continue; }
			bool swapped=ops[0].reg==regs[cat][0].id;
			Record fixed=normalized(d.insn);bool ok=true;
			for(unsigned prefix=first;prefix<=last;++prefix)for(unsigned mr=0xc0;mr<256;++mr) {
				if(!d.decode(prefix,op,mr))return 6;
				unsigned reg=((prefix&4)<<1)|((mr>>3)&7),rm=((prefix&1)<<3)|(mr&7);
				const Reg &a=regs[cat][swapped?reg:rm], &b=regs[cat][swapped?rm:reg];
				char text[160]={};snprintf(text,sizeof(text),"%s, %s",a.name,b.name);
				Record raw=normalized(d.insn);const cs_x86 &x=d.insn->detail->x86;
				++comparisons;
				if(raw.id!=fixed.id || raw.detail!=fixed.detail || memcmp(raw.mnemonic,fixed.mnemonic,sizeof(fixed.mnemonic)) ||
				   memcmp(text,d.insn->op_str,sizeof(text)) || x.modrm!=mr || x.rex!=prefix ||
				   x.operands[0].reg!=a.id || x.operands[1].reg!=b.id)
					ok=false;
			}
			if(!ok){++rejected;continue;}
			size_t slot=1;for(;slot<rows.size();++slot) if(rows[slot].id==fixed.id&&rows[slot].detail==fixed.detail&&
			   memcmp(rows[slot].mnemonic,fixed.mnemonic,sizeof(fixed.mnemonic))==0)break;
			if(slot==rows.size())rows.push_back(fixed);
			plans[wide][cls][op]=static_cast<unsigned short>(slot*2+swapped);++admitted;
		}
	}
	if (!admitted || comparisons<40000)return 7;
	fprintf(stderr,"admitted=%u excluded=%u canonical_rows=%zu complete_encodings=%u\n",admitted,rejected,rows.size()-1,comparisons);
	puts("static const struct { unsigned id; unsigned char length; char name[8]; } pair_regs[4][16] = {");
	for(auto &category:regs){puts("{");for(auto &v:category)printf("{%u,%zu,\"%s\"},\n",v.id,strlen(v.name),v.name);puts("},");}puts("};");
	puts("static const unsigned short pair_plans[2][3][256] = {");
	for(auto &mode:plans){puts("{");for(auto &group:mode){putchar('{');for(unsigned v:group)printf("%u,",v);puts("},");}puts("},");}puts("};");
	printf("static const struct { unsigned id; char mnemonic[CS_MNEMONIC_SIZE]; unsigned char detail[%zu]; } pair_rows[] = {\n",detail_size);
	for(auto &row:rows){printf("{%u,",row.id);emit_bytes((const unsigned char*)row.mnemonic,sizeof(row.mnemonic));putchar(',');emit_bytes(row.detail.data(),detail_size);puts("},");}puts("};");
}
