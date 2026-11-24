#define main batch_compare_main
#include "compare.cpp"
#undef main

int main(int argc,char **argv) {
	if (argc != 3) return 2;
	Api baseline(argv[1]), trial(argv[2]);
	uint64_t attempts = 0;
	for (cs_mode width : {CS_MODE_16,CS_MODE_32,CS_MODE_64}) {
		Session a(baseline,CS_ARCH_X86,width), b(trial,CS_ARCH_X86,width);
		for (unsigned detail : {0U,1U}) {
			for (Session *s : {&a,&b}) s->set(CS_OPT_DETAIL,detail ? CS_OPT_ON : CS_OPT_OFF);
			for (unsigned pp=0; pp<8; pp++) {
				for (unsigned predicate=0; predicate<256; predicate++) {
					for (uint8_t mr: {uint8_t(0xc1),uint8_t(0x07)}) {
						const uint8_t control = static_cast<uint8_t>(0x78|pp);
						const auto imm=static_cast<uint8_t>(predicate);
						for (const std::vector<uint8_t> code : {
							std::vector<uint8_t>{0xc5,control,0xc2,mr,imm},
							std::vector<uint8_t>{0xc4,0xe1,control,0xc2,mr,imm},
							std::vector<uint8_t>{0x62,0xf1,static_cast<uint8_t>(0x7c|(pp&3)),static_cast<uint8_t>(0x08|((pp&4)<<3)),0xc2,mr,imm}}) {
							compare(a,b,code.data(),code.size(),0xfffffff0,1);
							++attempts;
						}
					}
				}
			}
		}
	}
	check(total_records>20000,"vector predicate coverage");
	std::printf("{\"attempts\":%" PRIu64 ",\"records\":%" PRIu64 "}\n",attempts,total_records);
}
