#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>
#include "records.hfrag"

static bool fixed_opcode(unsigned op, bool wide) {
	if ((!wide && op >= 0x40 && op <= 0x4f) ||
	    (op >= 0x50 && op <= 0x5f) || (op >= 0x90 && op <= 0x99) ||
	    (op >= 0x9c && op <= 0x9f) || (op >= 0xf8 && op <= 0xfd)) return true;
	switch (op) {
	case 0xc3: case 0xc9: case 0xcb: case 0xcc: case 0xcf:
	case 0xd7: case 0xec: case 0xed: case 0xee: case 0xef:
	case 0xf4: case 0xf5: return true;
	default: return false;
	}
}

static bool describe(const cs_insn *insn, X86FixedOutput &row) {
	const cs_detail &d=*insn->detail;const cs_x86 &x=d.x86;
	if(strlen(insn->mnemonic)>=sizeof(row.mnemonic) || strlen(insn->op_str)>=sizeof(row.operands) ||
	   d.regs_read_count>4 || d.regs_write_count>4 || d.groups_count>4 || x.op_count>2) return false;
	row.id=insn->id;strcpy(row.mnemonic,insn->mnemonic);strcpy(row.operands,insn->op_str);
	if(strpbrk(row.mnemonic,"\n\\\"") ||strpbrk(row.operands,"\n\\\""))return false;
	row.flags=x.eflags;row.read_count=d.regs_read_count;row.write_count=d.regs_write_count;row.group_count=d.groups_count;
	row.operand_count=x.op_count;row.address_size=x.addr_size;
	memcpy(row.reads,d.regs_read,d.regs_read_count*sizeof(*d.regs_read));
	memcpy(row.writes,d.regs_write,d.regs_write_count*sizeof(*d.regs_write));memcpy(row.groups,d.groups,d.groups_count);
	for(unsigned i=0;i<x.op_count;++i) {
		if(x.operands[i].type!=X86_OP_REG)return false;
		row.ops[i]={static_cast<uint16_t>(x.operands[i].reg),x.operands[i].size,static_cast<uint8_t>(x.operands[i].access)};
	}
	cs_detail rebuilt;X86_writeFixedDetail(&rebuilt,&row,insn->bytes[0]);
	return !memcmp(&rebuilt,&d,offsetof(cs_detail,x86)+sizeof(cs_x86));
}
template<class T,size_t N> static void emit(const T(&xs)[N]) {
	putchar('{');for(size_t i=0;i<N;++i)printf("%s%u",i?", ":"",unsigned(xs[i]));putchar('}');
}
int main() {
	unsigned char indices[2][256] = {};std::vector<X86FixedOutput> records(1);
	unsigned observations=0,rejected=0;
	for(unsigned wide=0;wide<2;++wide) {
		csh h;if(cs_open(CS_ARCH_X86,wide?CS_MODE_64:CS_MODE_32,&h) || cs_option(h,CS_OPT_DETAIL,CS_OPT_ON))return 1;
		// This name is never printed in the fixed set and forces the ordinary mapping and printer.
		cs_opt_mnem normal={X86_INS_UD2,"ud2"};
		if(cs_option(h,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&normal)))return 2;
		cs_insn *insn=cs_malloc(h);if(!insn)return 3;
		for(unsigned op=0;op<256;++op) {
			if(!fixed_opcode(op,wide))continue;
			X86FixedOutput row{};bool eligible=true;
			for(unsigned tail=0;tail<=256;++tail) {
				uint8_t input[15];memset(input,tail,sizeof(input));input[0]=op;
				const uint8_t *p=input;size_t n=tail?sizeof(input):1;
				uint64_t va=tail?UINT64_MAX-uint64_t(tail):0;
				if(!cs_disasm_iter(h,&p,&n,&va,insn) || insn->size!=1 || p!=input+1)return 4;
				X86FixedOutput now{};++observations;
				if(!describe(insn,now)){eligible=false;break;}
				if(tail && memcmp(&now,&row,sizeof(row)))return 5;
				row=now;
			}
			if(!eligible){++rejected;continue;}
			size_t index=1;
			while(index<records.size() && memcmp(&row,&records[index],sizeof(row)))++index;
			if(index==records.size())records.push_back(row);
			if(index>255)return 6;
			indices[wide][op]=static_cast<unsigned char>(index);
		}
		cs_free(insn,1);cs_close(&h);
	}
	puts("static const uint8_t fixed_output_index[2][256] = {");
	for(auto &mode:indices){puts("\t{");for(unsigned start=0;start<256;start+=16){
		printf("\t\t");for(unsigned j=0;j<16;++j)printf("%u, ",mode[start+j]);puts("");}puts("\t},");}puts("};");
	puts("static const struct X86FixedOutput fixed_outputs[] = {");
	for(const auto &v:records) {
		printf("\t{ %u, \"%s\", \"%s\", UINT64_C(%llu), ",v.id,v.mnemonic,v.operands,(unsigned long long)v.flags);
		emit(v.reads);printf(", ");emit(v.writes);printf(", ");emit(v.groups);
		printf(", %u, %u, %u, %u, %u, { { %u, %u, %u }, { %u, %u, %u } } },\n",v.read_count,v.write_count,v.group_count,v.operand_count,v.address_size,
		       v.ops[0].reg,v.ops[0].size,v.ops[0].access,v.ops[1].reg,v.ops[1].size,v.ops[1].access);
	}puts("};");
	fprintf(stderr,"unique=%zu excluded=%u full_comparisons=%u table_bytes=%zu\n",records.size()-1,rejected,observations,sizeof(indices)+records.size()*sizeof(X86FixedOutput));
	return records.size()<30;
}
