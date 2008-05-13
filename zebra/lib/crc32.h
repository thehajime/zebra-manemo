/* 
 * Cyclic Redundancy Check routine
 * From RFC1952(GZIP File Format Specification)
 * http://www.ietf.org/rfc/rfc1952.txt
 *
 * $Id: crc32.h,v 7fcbfc13ab62 2008/05/13 01:36:32 tazaki $
 *
 * Copyright (c) 2007 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#ifndef __CRC32_H__
#define __CRC32_H__

unsigned long update_crc(unsigned long , unsigned char *, int);
unsigned long crc(unsigned char *, int);

#endif /* __CRC32_H__ */
