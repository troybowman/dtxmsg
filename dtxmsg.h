#ifndef DTXMSG_H
#define DTXMSG_H

#include "dtxmsg_common.h"
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>

#define DTXMSG_NODE "$ dtxmsg" // stores internal plugin data
#define DTXMSG_ALT_VERSION  0  // supval: DTXConnectionServices library version
#define DTXMSG_ALT_BPTS    'B' // altval_ea: array of bpt eas for inspecting incoming packets

#define DTXMSG_DEB_PFX "DTXMSG: "

struct dtxmsg_plugmod_t;

//--------------------------------------------------------------------------
DECLARE_LISTENER(idb_listener_t, struct dtxmsg_plugmod_t, dpm);
DECLARE_LISTENER(dbg_listener_t, struct dtxmsg_plugmod_t, dpm);
DECLARE_LISTENER(ui_listener_t,  struct dtxmsg_plugmod_t, dpm);

//--------------------------------------------------------------------------
struct dtxmsg_plugmod_t : public plugmod_t
{
  // processor info for the current idb
  processor_t &ph;

  // persist important configuration details in the database
  netnode dtxmsg_node;

  // directory where captured + decoded messages are stored
  char logdir[QMAXPATH] = { 0 };

  // log the header of each captured message in this file
  FILE *headers_fp = NULL;

  // print extra messages to the output window
  bool verbose = false;

  // pid of the debugged process (either DTServiceHub or Xcode)
  pid_t pid = 0;

  // event listeners
  idb_listener_t idb_listener = idb_listener_t(*this);
  dbg_listener_t dbg_listener = dbg_listener_t(*this);
  ui_listener_t  ui_listener  = ui_listener_t(*this);

  dtxmsg_plugmod_t(void);
  ~dtxmsg_plugmod_t(void);

  // attach to the target process and wait for breakpoint events
  virtual bool idaapi run(size_t code) override;

  // handle a breakpoint event
  bool handle_dtxmsg_bpt(void) const;

  // set a breakpoint in the target process
  void set_dtxmsg_bpt(ea_t ea);

  // detect breakpoint locations
  void set_dtxmsg_bpts_xcode8(void);
  void set_dtxmsg_bpts_xcode9(void);

  // print plugin configuration to output window
  void print_node_info(const char *pfx) const;

  // parse a message in memory
  bool parse_message(ea_t buf, const DTXMessageHeader &mheader) const;

  // deserialize the payload stored at the given path
  bool deserialize_payload(const char *path, uint32 id) const;

  // try to parse a serialized object and print it to a file in plain text
  bool deserialize_component(
          const char *label,
          uint32 identifier,
          FILE *payload_fp,
          uint64 off,
          uint64 length,
          bool is_array) const;
};

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
