#ifndef DTXMSG_H
#define DTXMSG_H

#include "dtxmsg_common.h"
#include <pro.h>
#include <kernwin.hpp>

#define DTXMSG_NODE "$ dtxmsg"
#define DTXMSG_ALT_FOOTPRINT  0  // has this plugin already operated on the current database?
#define DTXMSG_ALT_PARSE      1  // ea of -[DTXMessageParser parseMessageWithExceptionHandler:]
#define DTXMSG_ALT_WAIT       2  // ea of -[DTXMessageParser waitForMoreData:incrementalBuffer:]
#define DTXMSG_ALT_UNCOMPRESS 3  // ea of -[DTXBlockCompressorLibCompression uncompressBuffer:ofLength:toBuffer:withKnownUncompressedLength:usingCompressionType:]
#define DTXMSG_ALT_TABLE      4  // ea of compression algorithm table
#define DTXMSG_ALT_BPTS      'B' // array of magic bpt eas - for inspecting incoming packets

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
