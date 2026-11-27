#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Isolate the exact published and candidate loops from fill_insn.
 * Place the input terminator at every physically possible SStream index. */
typedef struct Input { char buffer[512]; } Input;
static size_t split_original(cs_insn *insn,const Input *OS)
{
	size_t off = 0;
	while (off < sizeof(insn->mnemonic) - 1 && OS->buffer[off] &&
	       OS->buffer[off] != ' ' && OS->buffer[off] != '\t') {
		char c = OS->buffer[off];
		insn->mnemonic[off] = c == '|' ? ' ' : c;
		off++;
	}
	while (OS->buffer[off] && OS->buffer[off] != ' ' &&
	       OS->buffer[off] != '\t')
		off++;
	while (OS->buffer[off] == ' ' || OS->buffer[off] == '\t')
		off++;
	return off;
}
static size_t split_known(cs_insn *insn,const Input *OS)
{
	size_t off = 0;
	while (off < sizeof(insn->mnemonic) - 1 && OS->buffer[off] &&
	       OS->buffer[off] != ' ' && OS->buffer[off] != '\t') {
		char c = OS->buffer[off];
		insn->mnemonic[off] = c == '|' ? ' ' : c;
		off++;
	}
	/* Only a truncated mnemonic can still have name bytes to skip. */
	if (off == sizeof(insn->mnemonic) - 1) {
		while (OS->buffer[off] && OS->buffer[off] != ' ' &&
		       OS->buffer[off] != '\t')
			off++;
	}
	if (OS->buffer[off]) {
		do {
			off++;
		} while (OS->buffer[off] == ' ' || OS->buffer[off] == '\t');
	}
	return off;
}
static size_t split_printable(cs_insn *insn,const Input *OS)
{
	size_t off = 0;
	char c = OS->buffer[off];
	while (off < sizeof(insn->mnemonic) - 1 && (unsigned char)c > ' ') {
		insn->mnemonic[off] = c == '|' ? ' ' : c;
		c = OS->buffer[++off];
	}
	/* Controls other than NUL, space and tab are part of the name.
	 * Continue to the delimiter even when the public name is full. */
	while (c && c != ' ' && c != '\t') {
		if (off < sizeof(insn->mnemonic) - 1)
			insn->mnemonic[off] = c == '|' ? ' ' : c;
		c = OS->buffer[++off];
	}
	if (c) {
		do {
			c = OS->buffer[++off];
		} while (c == ' ' || c == '\t');
	}
	return off;
}

static int check(const Input *stream)
{
    cs_insn original, known, printable;
    memset(&original,0x56,sizeof(original));
    memset(original.mnemonic,0,sizeof(original.mnemonic));
    memcpy(&known,&original,sizeof(known));
    memcpy(&printable,&original,sizeof(printable));
    size_t end=split_original(&original,stream);
    if (split_known(&known,stream)!=end || split_printable(&printable,stream)!=end ||
        memcmp(&original,&known,sizeof(known)) || memcmp(&original,&printable,sizeof(known))) {
        fprintf(stderr,"name split differs at operand offset %zu\n",end);return 1;
    }
    return 0;
}
int main(void)
{
    Input stream;
    unsigned cases=0;
    for (unsigned length=0;length<sizeof(stream.buffer);length++)
    for (unsigned pattern=0;pattern<7;pattern++) {
        static const char separators[]={' ','\t','|','\0','\1','\r',(char)0xff};
        memset(stream.buffer,0xa5,sizeof(stream.buffer));
        memset(stream.buffer,'v',length);
        stream.buffer[length]=0;
        for (unsigned pos=0;pos<=length;pos++) {
            char before=stream.buffer[pos];
            if (pos<length) stream.buffer[pos]=separators[pattern];
            if (pos+2<length && pattern<2) {
                stream.buffer[pos+1]='\t';stream.buffer[pos+2]=' ';
            }
            if (check(&stream)) return 1;
            ++cases;
            stream.buffer[pos]=before;
            if (pos+2<length && pattern<2) {
                stream.buffer[pos+1]='v';stream.buffer[pos+2]='v';
            }
        }
    }
    for (unsigned byte=0;byte<256;byte++)
    for (unsigned pos=0;pos<65;pos++) {
        memset(stream.buffer,'|',sizeof(stream.buffer));
        stream.buffer[pos]=(char)byte;
        stream.buffer[pos+1]=' ';
        stream.buffer[pos+2]='\t';
        stream.buffer[pos+3]='x';
        stream.buffer[pos+4]=0;
        if (check(&stream)) return 1;
        ++cases;
    }
    printf("%u\n",cases);
    return 0;
}
