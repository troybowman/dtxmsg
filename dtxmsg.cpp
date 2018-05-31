#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <expr.hpp>
#include <err.h>
#include <moves.hpp>
#include <hexrays.hpp>
#include "dtxmsg.h"

static FILE *headers_fp = NULL;
static char logdir[QMAXPATH];
static bool verbose = false;
hexdsp_t *hexdsp = NULL;

//-----------------------------------------------------------------------------
// try to parse a serialized object and print it to a file in plain text
static bool deserialize_component(
        const char *label,
        uint32 identifier,
        FILE *payload_fp,
        uint64 off,
        uint64 length,
        bool is_array)
{
  qstring base;
  char binpath[QMAXPATH];

  // save the raw data to a file for reference
  base.sprnt("%s_%d.bin", label, identifier);
  qmakepath(binpath, sizeof(binpath), logdir, base.c_str(), NULL);

  FILE *binfp = qfopen(binpath, "wb");
  if ( binfp == NULL )
  {
    dtxmsg_deb("Error: failed to open %s: %s\n", binpath, winerr(errno));
    return false;
  }
  file_janitor_t bj(binfp);

  bytevec_t bytes;
  bytes.resize(length);

  // read the component from the complete payload,
  // and write it out to a separate file.
  if ( qfseek(payload_fp, off, SEEK_SET) != 0
    || qfread(payload_fp, bytes.begin(), length) != length
    || qfwrite(binfp, bytes.begin(), length) != length )
  {
    dtxmsg_deb("Error: failed to create %s: %s\n", binpath, winerr(errno));
    return false;
  }

  dtxmsg_deb("%s: %s\n", label, binpath);

  char txtpath[QMAXPATH];
  set_file_ext(txtpath, sizeof(txtpath), binpath, "txt");

  // try to deserialize the component and save it in plain text
  FILE *txtfp = qfopen(txtpath, "w");
  if ( txtfp == NULL )
  {
    dtxmsg_deb("Error: failed to create %s: %s\n", txtpath, winerr(errno));
    return false;
  }
  file_janitor_t tj(txtfp);

  if ( length != 0 )
  {
    CFTypeRef obj = NULL;
    qstring errbuf = "unarchive() failed";

    if ( is_array )
      obj = deserialize(bytes.begin(), length, &errbuf);
    else
      obj = unarchive(bytes.begin(), length);

    if ( obj == NULL )
    {
      dtxmsg_deb("Error: failed to deserialize %s: %s\n", binpath, errbuf.c_str());
      return false;
    }

    qfprintf(txtfp, "%s\n", get_description(obj).c_str());
    CFRelease(obj);
  }

  dtxmsg_deb("%s: %s\n", label, txtpath);
  return true;
}

//-----------------------------------------------------------------------------
static bool deserialize_payload(const char *path, uint32 id)
{
  FILE *payload_fp = qfopen(path, "rb");
  if ( payload_fp == NULL )
  {
    dtxmsg_deb("Error: failed to open payload file %s for reading: %s\n", path, winerr(errno));
    return false;
  }
  file_janitor_t pj(payload_fp);

  DTXMessagePayloadHeader pheader;
  if ( qfread(payload_fp, &pheader, sizeof(pheader)) != sizeof(pheader) )
  {
    dtxmsg_deb("Error: failed to read payload header from %s: %s\n", path, winerr(errno));
    return false;
  }

  uint8 message_type = pheader.flags & 0xFF;
  uint8 compression_type = pheader.flags & 0xFF000 >> 12;
  uint32 algorithm = 0;

  if ( message_type == 6 )
  {
    dtxmsg_deb("Error: message payload is a serialized dictionary. we only know how to deserialize arrays.\n");
    return false;
  }

  // it seems Xcode does not normally use compression when sending messages to the instruments server.
  // for now we will assume that it doesn't, and throw an error if compression is detected.
  if ( message_type == 7 && compression_type > 3 )
  {
    dtxmsg_deb("Error: message is compressed (compression_type=%x). We must uncompress it before we read it!\n", compression_type);
    return false;
  }

  asize_t auxlen = pheader.auxiliaryLength;
  asize_t objlen = pheader.totalLength - auxlen;

  // the payload is broken up into two components:
  // 1. the payload object (a single archived NSObject)
  // 2. auxiliary data (a serialized array of archived NSObjects)
  return deserialize_component("auxiliary", id, payload_fp, sizeof(pheader),          auxlen, true)
      && deserialize_component("object",    id, payload_fp, sizeof(pheader) + auxlen, objlen, false);
}

//-----------------------------------------------------------------------------
static bool format_header(qstring *out, ea_t ea, const tinfo_t &tif)
{
  format_data_info_t fdi;
  fdi.ptvf = PTV_SPACE|PTV_QUEST|PTV_CSTR|PTV_DEBUG|PTV_DEREF;
  fdi.radix = 16;
  fdi.margin = 0;
  fdi.max_length = MAXSTR;

  argloc_t loc;
  loc.set_ea(ea);

  idc_value_t idcv;
  idcv.vtype = VT_PVOID;
  idcv.pvoid = &loc;

  qstrvec_t outvec;
  if ( !format_cdata(&outvec, idcv, &tif, NULL, &fdi) )
    return false;

  *out = outvec[0];
  return true;
}

//-----------------------------------------------------------------------------
static bool handle_message_fragment(ea_t buf, const DTXMessageHeader &mheader)
{
  ea_t fptr = buf + sizeof(mheader);
  ea_t flen = mheader.length;

  // the first message fragment contains the payload header
  if ( mheader.fragmentId <= 1 )
  {
    tinfo_t tif;
    if ( !tif.get_named_type(NULL, "DTXMessagePayloadHeader") )
    {
      dtxmsg_deb("Error: failed to retrieve tinfo for DTXMessagePayloadHeader\n");
      return false;
    }

    qstring hstr;
    if ( !format_header(&hstr, fptr, tif) )
    {
      dtxmsg_deb("Error: failed to format DTXMessagePayloadHeader at %a\n", fptr);
      return false;
    }

    qfprintf(headers_fp, "\t- DTXMessagePayloadHeader: %s\n", hstr.c_str());
    qflush(headers_fp);
  }

  bytevec_t fbytes;
  fbytes.resize(flen);
  if ( flen != 0 && read_dbg_memory(fptr, fbytes.begin(), flen) != flen )
  {
    dtxmsg_deb("Error: failed to read message fragment at %a, size = %a\n", fptr, flen);
    return false;
  }

  char path[MAXSTR];

  qstring fname;
  fname.sprnt("payload_%d.bin", mheader.identifier);
  qmakepath(path, sizeof(path), logdir, fname.c_str(), NULL);

  // append this fragment to the incremental payload file
  FILE *payload_fp = qfopen(path, "a");
  if ( payload_fp == NULL )
  {
    dtxmsg_deb("Error: failed to open %s: %s\n", path, winerr(errno));
    return false;
  }

  qfwrite(payload_fp, fbytes.begin(), flen);
  qfclose(payload_fp);

  dtxmsg_deb("payload: %s\n", path);

  // after writing the last fragment, deserialize the complete payload
  if ( mheader.fragmentId == mheader.fragmentCount - 1 )
  {
    if ( !deserialize_payload(path, mheader.identifier) )
      return false;
  }

  return true;
}

//-----------------------------------------------------------------------------
static bool handle_magic_bpt(void)
{
  // read the return value register
  regval_t val;
  if ( !get_reg_val(ph.id == PLFM_ARM ? "X0" : "RAX", &val) )
  {
    dtxmsg_deb("Error: failed to read value from return register\n");
    return false;
  }

  ea_t buf = val.ival; // pointer to the message buffer

  tinfo_t tif;
  if ( !tif.get_named_type(NULL, "DTXMessageHeader") )
  {
    dtxmsg_deb("Error: failed to retrieve tinfo for DTXMessageHeader\n");
    return false;
  }

  qstring hstr;
  if ( !format_header(&hstr, buf, tif) )
  {
    dtxmsg_deb("Error: failed to format DTXMessageHeader at %a\n", buf);
    return false;
  }

  DTXMessageHeader mheader;
  if ( read_dbg_memory(buf, &mheader, sizeof(mheader)) != sizeof(mheader) )
  {
    dtxmsg_deb("Error: failed to read DTXMessageHeader at %a\n", buf);
    return false;
  }

  qfprintf(headers_fp, "%d.%d: DTXMessageHeader: %s\n", mheader.identifier, mheader.fragmentId, hstr.c_str());
  qflush(headers_fp);

  asize_t size = sizeof(mheader) + mheader.length;

  bytevec_t dtxmsg;
  dtxmsg.resize(size);
  if ( read_dbg_memory(buf, dtxmsg.begin(), size) != size )
  {
    dtxmsg_deb("Error: failed to read %a bytes of DTXMessage data at %a\n", size, buf);
    return false;
  }

  char path[QMAXPATH];

  qstring fname;
  fname.sprnt("dtxmsg_%d_%d.bin", mheader.identifier, mheader.fragmentId);
  qmakepath(path, sizeof(path), logdir, fname.c_str(), NULL);

  FILE *message_fp = qfopen(path, "wb");
  if ( message_fp == NULL )
  {
    dtxmsg_deb("Error: failed to open %s: %s\n", path, winerr(errno));
    return false;
  }

  qfwrite(message_fp, dtxmsg.begin(), size);
  qfclose(message_fp);

  dtxmsg_deb("message: %s\n", path);

  // don't try to parse any of the message data unless instructed
  bool ok = true;
  if ( verbose )
    ok = handle_message_fragment(buf, mheader);

  qfprintf(headers_fp, "\n");
  qflush(headers_fp);

  return ok;
}

//-----------------------------------------------------------------------------
static ssize_t idaapi dbg_callback(void *, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case dbg_bpt:
      {
        thid_t tid = va_arg(va, thid_t);
        ea_t bpt   = va_arg(va, ea_t);

        netnode node;
        node.create(DTXMSG_NODE);

        if ( node.altval_ea(bpt, DTXMSG_ALT_BPTS) == 0 )
          break;

        if ( verbose )
          dtxmsg_deb("magic bpt: %a, tid=%d\n", bpt, tid);

        if ( !handle_magic_bpt() )
          break;

        // resume process
        request_continue_process();
        run_requests();
      }
      break;

    default:
      break;
  }

  return 0;
}

//-----------------------------------------------------------------------------
static void print_node_info(const char *pfx)
{
  netnode node;
  node.create(DTXMSG_NODE);

  dtxmsg_deb("node info: %s\n", pfx);
  dtxmsg_deb("  footprint:  %a\n", node.altval(DTXMSG_ALT_FOOTPRINT));
  dtxmsg_deb("  parse:      %a\n", node.altval(DTXMSG_ALT_PARSE));
  dtxmsg_deb("  wait:       %a\n", node.altval(DTXMSG_ALT_WAIT));

  for ( nodeidx_t idx = node.altfirst(DTXMSG_ALT_BPTS);
        idx != BADNODE;
        idx = node.altnext(idx, DTXMSG_ALT_BPTS) )
  {
    dtxmsg_deb("  magic bpt:  %a\n", node2ea(idx));
  }
}

//-----------------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    case idb_event::auto_empty_finally:
      {
        if ( hexdsp == NULL )
          break;

        netnode node;
        node.create(DTXMSG_NODE);

        ea_t ea = node.altval(DTXMSG_ALT_PARSE);
        func_t *pfn = get_func(ea);
        if ( pfn == NULL )
        {
          dtxmsg_deb("Error: no function found at %a\n", ea);
          break;
        }

        mba_ranges_t mbr(pfn);
        hexrays_failure_t hf;
        mbl_array_t *mba = gen_microcode(
                mbr,
                &hf,
                NULL,
                DECOMP_NO_WAIT,
                MMAT_GLBOPT1);

        if ( mba == NULL )
        {
          dtxmsg_deb("microcode failure at %a: %s\n", hf.errea, hf.desc().c_str());
          return false;
        }

        // add breakpoints after calls to -[DTXMessageParser waitForMoreData:incrementalBuffer:].
        // this function will return a pointer to the raw DTXMessage data.
        struct ida_local bpt_finder_t : public minsn_visitor_t
        {
          netnode node;
          bpt_finder_t(netnode _node) : node(_node) {}
          virtual int idaapi visit_minsn(void)
          {
            if ( curins->opcode == m_call )
            {
              const mfuncinfo_t *fi = curins->d.f;
              if ( fi->args.size() == 4 && fi->callee == get_name_ea(BADADDR, "_objc_msgSend") )
              {
                const mfuncarg_t &selarg = fi->args[1];
                if ( selarg.t == mop_a || selarg.a->t == mop_v )
                {
                  qstring sel;
                  ea_t selea = selarg.a->g;
                  if ( is_strlit(get_flags(selea))
                    && get_strlit_contents(&sel, selea, -1, STRTYPE_C) > 0
                    && sel == "waitForMoreData:incrementalBuffer:"
                    // we ignore calls with a constant for the length argument, since they are likely just
                    // reading the header block. we are only interested in calls that will ultimately return
                    // the full serialized DTXMessage payload.
                    && fi->args[2].t != mop_n )
                  {
                    ea_t bpt = get_item_end(curins->ea);
                    add_bpt(bpt, 1, BPT_DEFAULT);
                    node.altset_ea(bpt, 1, DTXMSG_ALT_BPTS);
                    dtxmsg_deb("magic bpt: %a\n", bpt);
                  }
                }
              }
            }
            return 0;
          }
        };

        bpt_finder_t bf(node);
        mba->for_all_insns(bf);

        delete mba;

        if ( node.altfirst(DTXMSG_ALT_BPTS) == BADNODE )
          warning(DTXMSG_DEB_PFX "failed to detect any critical breakpoints!");
      }
      break;

    case idb_event::allsegs_moved:
      {
        netnode node;
        node.create(DTXMSG_NODE);
        const segm_move_infos_t *smi = va_arg(va, segm_move_infos_t *);

        for ( segm_move_infos_t::const_iterator i = smi->begin(); i != smi->end(); ++i )
        {
          nodeidx_t n1 = ea2node(i->from);
          nodeidx_t n2 = ea2node(i->to);
          node.altshift(n1, n2, i->size, DTXMSG_ALT_BPTS);
        }

        for ( nodeidx_t idx = node.altfirst(); idx != BADNODE; idx = node.altnext(idx) )
        {
          if ( idx == DTXMSG_ALT_FOOTPRINT )
            continue;

          ea_t oldea = node.altval(idx);
          const segm_move_info_t *_smi = smi->find(oldea);
          if ( _smi != NULL )
          {
            asize_t slide = _smi->to - _smi->from;
            node.altset(idx, oldea + slide);
          }
        }

        print_node_info("rebased");
      }
      break;

    default:
      break;
  }

  return 0;
}

//-----------------------------------------------------------------------------
static int idaapi init(void)
{
  ea_t ea1 = get_name_ea(BADADDR, "-[DTXMessageParser parseMessageWithExceptionHandler:]");
  ea_t ea2 = get_name_ea(BADADDR, "-[DTXMessageParser waitForMoreData:incrementalBuffer:]");

  if ( ea1 == BADADDR || ea2 == BADADDR || !inf.is_64bit() )
  {
    dtxmsg_deb("input file does not look like the 64-bit DTXConnectionServices library, skipping\n");
    return PLUGIN_SKIP;
  }

  if ( !init_hexrays_plugin() )
  {
    warning("AUTOHIDE DATABASE\n"
            "The hexrays decompiler is not available. The dtxmsg plugin requires the decompiler to detect\n"
            "critical pieces of logic in -[DTXMessageParser parseMessageWithExceptionHandler:] and set\n"
            "the proper breakpoints. Without the decompiler, you will have to set these breakpoints manually.\n");
  }

  netnode node;
  node.create(DTXMSG_NODE);
  if ( node.altval(DTXMSG_ALT_FOOTPRINT) == 0 )
  {
    // working with a fresh database - must perform some setup
    const char *dbgname = NULL;
    const char *exe = NULL;
    const char *lib = NULL;
    int port = -1;

    switch ( ph.id )
    {
      case PLFM_ARM:
        dbgname = "ios";
        exe = "/Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub";
        lib = "/Developer/Library/PrivateFrameworks/DTXConnectionServices.framework/DTXConnectionServices";
        port = 4321; // use ios_deploy to relay connection to the debugserver. see 'ios_deploy usbproxy -h'.
        break;

      case PLFM_386:
        dbgname = "mac";
        exe = "/Applications/Xcode.app/Contents/MacOS/Xcode";
        lib = "/Applications/Xcode.app/Contents/SharedFrameworks/DTXConnectionServices.framework/Versions/A/DTXConnectionServices";
        port = 23946;
        break;

      default:
        dtxmsg_deb("Error: unsupported architecture: %d\n", ph.id);
        return PLUGIN_SKIP;
    }

    if ( !load_debugger(dbgname, true) )
    {
      dtxmsg_deb("Error: failed to load %s debugger module\n", dbgname);
      return PLUGIN_SKIP;
    }

    set_process_options(exe, NULL, NULL, "localhost", NULL, port);
    set_root_filename(lib);

    node.altset(DTXMSG_ALT_FOOTPRINT, 1);
    node.altset(DTXMSG_ALT_PARSE, ea1);
    node.altset(DTXMSG_ALT_WAIT, ea2);
  }
  else
  {
    // already configured the debugging environment
    print_node_info("saved");
  }

  static const char *decls =
    "struct DTXMessageHeader        \n"
    "{                              \n"
    "  uint32_t magic;              \n"
    "  uint32_t cb;                 \n"
    "  uint16_t fragmentId;         \n"
    "  uint16_t fragmentCount;      \n"
    "  uint32_t length;             \n"
    "  uint32_t identifier;         \n"
    "  uint32_t conversationIndex;  \n"
    "  uint32_t channelCode;        \n"
    "  uint32_t expectsReply;       \n"
    "};                             \n"
    "struct DTXMessagePayloadHeader \n"
    "{                              \n"
    "  uint32_t flags;              \n"
    "  uint32_t auxiliaryLength;    \n"
    "  uint64_t totalLength;        \n"
    "};                             \n";

  if ( parse_decls(NULL, decls, NULL, HTI_DCL) != 0
    || import_type(NULL, -1, "DTXMessageHeader") == BADNODE
    || import_type(NULL, -1, "DTXMessagePayloadHeader") == BADNODE )
  {
    dtxmsg_deb("Error: failed to import DTXMessage helper types\n");
    return PLUGIN_SKIP;
  }

  qtmpnam(logdir, sizeof(logdir));
  if ( qmkdir(logdir, 0755) != 0 )
  {
    dtxmsg_deb("Error: failed to mkdir %s: %s\n", logdir, winerr(errno));
    return PLUGIN_SKIP;
  }

  char path[QMAXPATH];
  qmakepath(path, sizeof(path), logdir, "headers.log", NULL);

  headers_fp = qfopen(path, "w");
  if ( headers_fp == NULL )
  {
    dtxmsg_deb("Error: failed to open %s: %s\n", path, winerr(errno));
    return PLUGIN_SKIP;
  }

  dtxmsg_deb("logging header info to: %s\n", path);

  // parse command line arguments
  qstring cmdline = get_plugin_options("dtxmsg");
  if ( !cmdline.empty() )
  {
    char *ctx = NULL;
    for ( char *tok = qstrtok(cmdline.begin(), ":", &ctx);
          tok != NULL;
          tok = qstrtok(NULL, ":", &ctx) )
    {
      if ( qstrlen(tok) == 1 )
      {
        switch ( tok[0] )
        {
          case 'v':
          case 'V':
            verbose = true;
            continue;
          default:
            break;
        }
      }
      dtxmsg_deb("Warning: bad command line arg: %s\n", tok);
    }
  }

  hook_to_notification_point(HT_DBG, dbg_callback);
  hook_to_notification_point(HT_IDB, idb_callback);

  return PLUGIN_KEEP;
}

//-----------------------------------------------------------------------------
static void idaapi term(void)
{
  unhook_from_notification_point(HT_DBG, dbg_callback);
  unhook_from_notification_point(HT_IDB, idb_callback);

  if ( headers_fp != NULL )
  {
    qfclose(headers_fp);
    headers_fp = NULL;
  }

  if ( hexdsp != NULL )
  {
    term_hexrays_plugin();
    hexdsp = NULL;
  }
}

//-----------------------------------------------------------------------------
static bool idaapi run(size_t)
{
  return false;
}

//-----------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                     // plugin flags
  init,                  // initialize
  term,                  // terminate. this pointer may be NULL.
  run,                   // invoke plugin
  NULL,                  // long comment about the plugin
  NULL,                  // multiline help about the plugin
  "",                    // the preferred short name of the plugin
  NULL                   // the preferred hotkey to run the plugin
};
