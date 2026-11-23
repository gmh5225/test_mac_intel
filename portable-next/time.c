#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t now(clockid_t clock)
{
	struct timespec ts;
	if (clock_gettime(clock, &ts)) exit(2);
	return (uint64_t)ts.tv_sec*1000000000 + ts.tv_nsec;
}

static uint64_t fold(uint64_t hash, const cs_insn *insn)
{
	return (hash ^ insn->id ^ insn->address ^ insn->size ^
		(unsigned char)insn->mnemonic[0]) * UINT64_C(1099511628211);
}

int main(int argc, char **argv)
{
	if (argc!=6) return 2;
	FILE *f=fopen(argv[1],"rb");
	if (!f || fseek(f,0,SEEK_END)) return 3;
	long bytes=ftell(f);
	if(bytes<1||fseek(f,0,SEEK_SET))return 3;
	uint8_t *buffer=malloc((size_t)bytes);
	if(!buffer||fread(buffer,1,(size_t)bytes,f)!=(size_t)bytes)return 3;
	fclose(f);
	uint64_t start=strtoull(argv[2],NULL,0), count=0, digest=0;
	unsigned mode=(unsigned)strtoul(argv[3],NULL,0), passes=(unsigned)strtoul(argv[5],NULL,0);
	bool array=argv[4][0]=='a';
	csh h;
	if(cs_open(CS_ARCH_XCORE,CS_MODE_LITTLE_ENDIAN,&h) ||
	   cs_option(h,CS_OPT_TEXT,mode?CS_OPT_ON:CS_OPT_OFF) ||
	   cs_option(h,CS_OPT_DETAIL,mode==2?CS_OPT_ON:CS_OPT_OFF)) return 4;
	cs_insn *record=cs_malloc(h);if(!record)return 4;
	uint64_t wall=now(CLOCK_MONOTONIC),cpu=now(CLOCK_PROCESS_CPUTIME_ID);
	for(unsigned pass=0;pass<passes;++pass){
		const uint8_t *p=buffer;
		size_t left=(size_t)bytes;
		uint64_t ip=start;
		while(left){
			if(array){
				cs_insn *batch=NULL;
				size_t n=cs_disasm(h,p,left,ip,64,&batch);
				if(n){
					for(size_t i=0;i<n;++i)digest=fold(digest,&batch[i]);
					uint64_t next=batch[n-1].address+batch[n-1].size;
					if(next<=ip || next-ip>left)return 5;
					p+=next-ip;left-=(size_t)(next-ip);ip=next;count+=n;
					cs_free(batch,n);
					continue;
				}
			} else if(cs_disasm_iter(h,&p,&left,&ip,record)){
				++count;digest=fold(digest,record);continue;
			}
			size_t step=left>=2?2:1;left-=step;ip+=step;p+=step;
		}
	}
	cpu=now(CLOCK_PROCESS_CPUTIME_ID)-cpu;wall=now(CLOCK_MONOTONIC)-wall;
	printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",cpu,wall,count,digest);
	cs_free(record,1);cs_close(&h);free(buffer);return 0;
}
