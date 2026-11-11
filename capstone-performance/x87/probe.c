#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*thunk)(void);
extern void probe_fx(void *, unsigned, const double *, thunk);
#define REF(P, I) extern void P##I(void);
#define EIGHT(M, P) M(P, 0) M(P, 1) M(P, 2) M(P, 3) M(P, 4) M(P, 5) M(P, 6) M(P, 7)
#define FUN(P, I) P##I,
EIGHT(REF, fxch) EIGHT(REF, fstp) EIGHT(REF, ddx) EIGHT(REF, dfx)
EIGHT(REF, dfd0) EIGHT(REF, dfd8)
static const thunk thunks[][8] = {
    {EIGHT(FUN, fxch)}, {EIGHT(FUN, fstp)}, {EIGHT(FUN, ddx)},
    {EIGHT(FUN, dfx)}, {EIGHT(FUN, dfd0)}, {EIGHT(FUN, dfd8)}
};
typedef struct { _Alignas(16) unsigned char b[512]; } snapshot;
static uint16_t u16(const unsigned char *b) { uint16_t n; memcpy(&n,b,2); return n; }
static int equal(const snapshot *x, const snapshot *y) {
    uint16_t sw=u16(x->b+2);
    if (u16(x->b)!=u16(y->b) || ((sw^u16(y->b+2))&0xbaff) || x->b[4]!=y->b[4]) return 0;
    for (unsigned i=0;i<8;i++) {
        unsigned phys=((sw>>11)+i)&7;
        if ((x->b[4]&(1u<<phys)) && memcmp(x->b+32+16*i,y->b+32+16*i,10)) return 0;
    }
    return 1;
}
int main(void) {
    static const double vals[][8]={{1,2,3,4,5,6,7,8},{-0.0,-1.25,10.75,5.5,7.25,-11.5,-23.125,63.875}};
    unsigned n=0, mismatches=0;
    for(unsigned f=2;f<6;f++) for(unsigned i=0;i<8;i++)
        for(unsigned j=0;j<2;j++) for(unsigned d=0;d<=8;d++){
            snapshot a,b;
            probe_fx(&a,d,vals[j],thunks[f<4?0:1][i]);
            probe_fx(&b,d,vals[j],thunks[f][i]);
            ++n;
            if(!equal(&a,&b)){++mismatches;printf("differ %u %u %u %u\n",f,i,j,d);}
        }
    printf("comparisons=%u mismatches=%u\n",n,mismatches);
    return mismatches!=0;
}
