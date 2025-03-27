#ifndef __LWC_H__
#define __LWC_H__


static inline unsigned long long rdcycle(void);
static void delay_6000_cycles(void);

static inline unsigned long long rdcycle() {
  unsigned long long cycle;
  asm volatile ("rdcycle %0" : "=r"(cycle));
  return cycle;
}

static void delay_6000_cycles() {
  unsigned long long start, current;
  volatile unsigned long long dummy = 0; // prevent optimization

  start = rdcycle();
  do {
    current = rdcycle();
    dummy = current;  // Use value to avoid optimizing the loop away
  } while (current - start < 6000);
}

#endif
