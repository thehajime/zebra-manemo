/* 
 * API interface for external application
 *
 * $Id: td_api.h,v 7fcbfc13ab62 2008/05/13 01:36:32 tazaki $
 *
 * Copyright (c) 2008 {TBD}
 *
 * Author: Hajime TAZAKI  (tazaki@sfc.wide.ad.jp)
 *
 */

#ifndef __API_H__
#define __API_H__

/* Path to access */
#define  MNDP_API_PATH   "/tmp/.mndp_api"

/* Command Definition */
#define  MNDP_API_TD_GET_MR_DEPTH       0
#define  MNDP_API_TD_SET_HOA            1

struct api_cmd
{
  u_int8_t cmd;
  u_int16_t len;
  u_int8_t rsv;
  /* followed by option data */
};

int api_notify_td_depth_all();
int api_init();
int api_term();

#endif  /* __API_H__ */
