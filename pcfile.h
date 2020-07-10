#ifndef PCFILE_H
#define PCFILE_H

#define PCMAGIC			0x19930613
typedef struct {
	unsigned magic;
	unsigned entry;
} pcfile_header;

#endif