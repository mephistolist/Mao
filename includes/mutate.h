#ifndef MUTATE_H
#define MUTATE_H

void mutate1(char *s);
void mutate2(char *s);
void mutate3(char *s);
void mutate4(char *s);
void mutate5(char *s);
void mutate6(char *s);
void mutate7(char *s);
void mutate8(char *s);
void junk_memory(void);
unsigned char internal_random_byte(void);
void shuffle(void (**funcs)(char *), int count);
void obfuscate_memory_presence(void);
void temporal_obfuscation(void);
void obscure_system_calls(void);
void init_entropy();

#endif
