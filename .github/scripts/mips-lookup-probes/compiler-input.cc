template<class T> T clamp(T v,T lo,T hi) { return v<lo?lo:(v>hi?hi:v); }
extern "C" unsigned combine(const unsigned* in,int n,unsigned seed) {
for (int i=0;i<n;++i) { unsigned x=in[i]; switch(x&3) {
 case 0: seed=(seed ^ x)*3; break; case 1: seed+=(x<<7)|(x>>25); break;
 case 2: seed=clamp(seed, x&0xffu, x|0xffu);break; default: seed=seed*33+x; }}
return seed; }
extern "C" void blend(const unsigned char* src,unsigned char* dest,unsigned n,unsigned alpha) {
for(unsigned i=0;i<n;++i) dest[i]=((src[i]*alpha+dest[i]*(256-alpha))>>8); }
