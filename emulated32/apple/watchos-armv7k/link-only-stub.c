void exit(int x) { (void)x; for (;;) {} }
void binder(void) __asm__("dyld_stub_binder");
void binder(void) { for (;;) {} }
