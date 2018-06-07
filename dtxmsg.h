#ifndef DTXMSG_H
#define DTXMSG_H

#include "dtxmsg_common.h"
#include <pro.h>
#include <kernwin.hpp>

#define DTXMSG_NODE "$ dtxmsg" // stores internal plugin data
#define DTXMSG_ALT_VERSION  0  // supval: DTXConnectionServices library version
#define DTXMSG_ALT_BPTS    'B' // altval_ea: array of bpt eas for inspecting incoming packets

#define DTXMSG_DEB_PFX "DTXMSG: "

//-----------------------------------------------------------------------------
THREAD_SAFE AS_PRINTF(1, 0) void dtxmsg_vdeb(const char *format, va_list va)
{
  qstring buf(DTXMSG_DEB_PFX);
  buf.cat_vsprnt(format, va);
  msg("%s", buf.c_str());
}

//-----------------------------------------------------------------------------
THREAD_SAFE AS_PRINTF(1, 2) void dtxmsg_deb(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  dtxmsg_vdeb(format, va);
  va_end(va);
}

#endif // DTXMSG_H
