#include "arch/X86/X86Mapping.h"
#include "cs_priv.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif

typedef cs_err (*open_fn)(cs_arch, cs_mode, csh *);
typedef cs_err (*close_fn)(csh *);
typedef cs_err (*option_fn)(csh, cs_opt_type, size_t);
static struct { char kind; size_t items, width; } events[64];
static unsigned event_count, fail, length;
static void *trace_malloc(size_t n)
{
	events[event_count].kind='m'; events[event_count++].width=n;
	return fail==1 && n==length*sizeof(uint32_t) ? NULL : malloc(n);
}
static void *trace_calloc(size_t n, size_t size)
{
	events[event_count].kind='c'; events[event_count].items=n; events[event_count++].width=size;
	return fail==2 && n==length && size==sizeof(uint32_t) ? NULL : calloc(n,size);
}
static void trace_free(void *p)
{
	events[event_count].kind='f'; events[event_count++].width=p!=NULL;
	free(p);
}
int main(int argc, char **argv)
{
	if(argc!=2) return 2;
	void *dll=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL|RTLD_FIRST);
	if(!dll) return 3;
	open_fn openers[] = {(open_fn)dlsym(dll,"cs_open"),cs_open};
	close_fn closers[] = {(close_fn)dlsym(dll,"cs_close"),cs_close};
	option_fn options[] = {(option_fn)dlsym(dll,"cs_option"),cs_option};
	if(!openers[0] || !closers[0] || !options[0]) return 4;
	cs_opt_mem hooks={trace_malloc,trace_calloc,realloc,trace_free,vsnprintf};
	const cs_mode modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
	unsigned checks=0;
	for(unsigned mode=0; mode<3; ++mode) for(fail=0;fail<=2;++fail) {
		csh handles[2]={0}; cs_struct *h[2];
		unsigned count=0; unsigned char saved[sizeof(events)];
		for(unsigned v=0;v<2;++v){
			if(options[v](0,CS_OPT_MEM,(size_t)&hooks)!=CS_ERR_OK) return 5;
			memset(events,0,sizeof(events)); event_count=0;
			if(openers[v](CS_ARCH_X86,modes[mode],&handles[v])!=CS_ERR_OK) return 6;
			if(v==0){count=event_count; memcpy(saved,events,sizeof(events));}
			else if(count!=event_count || memcmp(saved,events,sizeof(events))) return 7;
			h[v]=(cs_struct *)handles[v];
		}
		if(h[0]->x86_insn_lut_max!=h[1]->x86_insn_lut_max) return 8;
		length=h[0]->x86_insn_lut_max+1;
		if(!!h[0]->x86_insn_lut!=!!h[1]->x86_insn_lut ||
		   !!h[0]->x86_insn_reg_lut!=!!h[1]->x86_insn_reg_lut) return 9;
		if(h[0]->x86_insn_lut) {
			for(unsigned id=0;id<length;++id) {
				unsigned row=find_insn(id);
				uint32_t expected=row==(unsigned)-1 ? UINT32_MAX : ((uint32_t)insns[row].mapid<<16)|row;
				if(h[0]->x86_insn_lut[id]!=expected || h[1]->x86_insn_lut[id]!=expected) return 10;
				++checks;
			}
		}
		if(h[0]->x86_insn_reg_lut && memcmp(h[0]->x86_insn_reg_lut,h[1]->x86_insn_reg_lut,length*sizeof(uint32_t)))return 11;
		for(unsigned v=0;v<2;++v){
			memset(events,0,sizeof(events));event_count=0;
			if(closers[v](&handles[v])!=CS_ERR_OK || handles[v])return 12;
			if(v==0){count=event_count;memcpy(saved,events,sizeof(events));}
			else if(count!=event_count||memcmp(saved,events,sizeof(events)))return 13;
		}
	}
	printf("Verified %u packed words and nine allocation/free traces including both failure paths\n",checks);
	return 0;
}
