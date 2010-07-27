#ifndef _OLSR_COMMON_H_
#define _OLSR_COMMON_H_

#define OLSR_PORT_NUMBER	698
#define OLSR_MULTICAST_GROUP	"ff02::1"

extern int olsr_sock;

extern FILE *errout;

int olsr_mpr_dump_timer (struct thread *);

#define VNL VTY_NEWLINE

#endif /* _OLSR_COMMON_H_ */
