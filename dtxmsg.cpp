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

static FILE *logfp = NULL;
static char logdir[QMAXPATH];
hexdsp_t *hexdsp = NULL;

//-----------------------------------------------------------------------------
// this is the crux of the plugin. here we try to deserialize a packet of data
// sent between Xcode and the iOS instruments server and print it to a file
// in plain text.
static bool parse_payload_component(
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

    if ( obj != NULL )
    {
      qfprintf(txtfp, "%s\n", get_description(obj).c_str());
      CFRelease(obj);
    }
    else
    {
      dtxmsg_deb("Error: failed to deserialize %s: %s\n", binpath, errbuf.c_str());
    }
  }

  dtxmsg_deb("%s: %s\n", label, txtpath);
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

  format_data_info_t fdi;
  fdi.ptvf = PTV_SPACE|PTV_QUEST|PTV_CSTR|PTV_DEBUG|PTV_DEREF;
  fdi.radix = 16;
  fdi.margin = 0;
  fdi.max_length = MAXSTR;

  argloc_t loc;
  loc.set_ea(buf);

  idc_value_t idcv;
  idcv.vtype = VT_PVOID;
  idcv.pvoid = &loc;

  qstrvec_t outvec;
  if ( !format_cdata(&outvec, idcv, &tif, NULL, &fdi) )
  {
    dtxmsg_deb("Error: format_cdata() failed for data at %a\n", buf);
    return false;
  }

  DTXMessageHeader mheader;
  if ( read_dbg_memory(buf, &mheader, sizeof(mheader)) != sizeof(mheader) )
  {
    dtxmsg_deb("Error: failed to read DTXMessageHeader at %a\n", buf);
    return false;
  }

  qfprintf(logfp, "%d.%d: DTXMessageHeader: %s\n", mheader.identifier, mheader.fragmentId, outvec[0].c_str());
  qflush(logfp);

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

  FILE *fp = qfopen(path, "wb");
  if ( fp == NULL )
  {
    dtxmsg_deb("Error: failed to open %s: %s\n", path, winerr(errno));
    return false;
  }

  qfwrite(fp, dtxmsg.begin(), size);
  qfclose(fp);

  dtxmsg_deb("message: %s\n", path);

  // payload data
  ea_t pbuf = buf + sizeof(mheader);
  ea_t plen = mheader.length;

  if ( mheader.fragmentId <= 1 )
  {
    // payload header
    if ( !tif.get_named_type(NULL, "DTXMessagePayloadHeader") )
    {
      dtxmsg_deb("Error: failed to retrieve tinfo for DTXMessagePayloadHeader\n");
      return false;
    }

    loc.set_ea(pbuf);
    outvec.clear();

    if ( !format_cdata(&outvec, idcv, &tif, NULL, &fdi) )
    {
      dtxmsg_deb("Error: format_cdata() failed for data at %a\n", pbuf);
      return false;
    }

    qfprintf(logfp, "\t- DTXMessagePayloadHeader: %s\n", outvec[0].c_str());
    qflush(logfp);
  }

  bytevec_t payload;
  payload.resize(plen);
  if ( plen != 0 && read_dbg_memory(pbuf, payload.begin(), plen) != plen )
  {
    dtxmsg_deb("Error: failed to read %a bytes of payload at %a\n", plen, pbuf);
    return false;
  }

  fname.sprnt("payload_%d.bin", mheader.identifier);
  qmakepath(path, sizeof(path), logdir, fname.c_str(), NULL);

  fp = qfopen(path, "a");
  if ( fp == NULL )
  {
    dtxmsg_deb("Error: failed to open %s: %s\n", path, winerr(errno));
    return false;
  }

  qfwrite(fp, payload.begin(), plen);
  qfclose(fp);

  dtxmsg_deb("payload: %s\n", path);

  // after writing the last fragment, deserialize the complete payload
  if ( mheader.fragmentId == mheader.fragmentCount - 1 )
  {
    fp = qfopen(path, "rb");
    if ( fp == NULL )
    {
      dtxmsg_deb("Error: failed to open payload file %s for reading: %s\n", path, winerr(errno));
      return false;
    }
    file_janitor_t j(fp);

    DTXMessagePayloadHeader pheader;
    if ( qfread(fp, &pheader, sizeof(pheader)) != sizeof(pheader) )
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

    // the complete payload is broken up into two components:
    // 1. the payload object (a single archived NSObject)
    // 2. auxiliary data (a serialized array of archived NSObjects)
    if ( !parse_payload_component("auxiliary", mheader.identifier, fp, sizeof(pheader), auxlen, true)
      || !parse_payload_component("object",    mheader.identifier, fp, sizeof(pheader) + auxlen, objlen, false) )
    {
      return false;
    }
  }

  qfprintf(logfp, "\n");
  qflush(logfp);

  return true;
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

        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(pfn, &hf);
        if ( cfunc == NULL )
        {
          dtxmsg_deb("Error: decompilation failed. code=%d, addr=%a, err=%s\n", hf.code, hf.errea, hf.str.c_str());
          break;
        }

        // add breakpoints after calls to -[DTXMessageParser waitForMoreData:incrementalBuffer:].
        // this function will return a pointer to the raw DTXMessage data.
        struct ida_local bpt_finder_t : public ctree_visitor_t
        {
          netnode &node;
          bpt_finder_t(netnode &_node) : ctree_visitor_t(CV_FAST), node(_node) {}

          virtual int idaapi visit_expr(cexpr_t *e)
          {
            if ( e->op == cot_call )
            {
              ea_t callee = e->x->obj_ea;
              if ( callee == node.altval(DTXMSG_ALT_WAIT) // objc plugin might have set this
                || callee == get_name_ea(BADADDR, "_objc_msgSend") )
              {
                const carglist_t &args = *e->a;

                if ( args.size() == 4 && args[1].op == cot_obj )
                {
                  ea_t selea = args[1].obj_ea;
                  qstring sel;

                  if ( is_strlit(get_flags(selea))
                    && get_strlit_contents(&sel, selea, -1, STRTYPE_C)
                    && sel == "waitForMoreData:incrementalBuffer:"
                    // we ignore calls with a constant for the length argument, since they are likely just
                    // reading the header block. we are only interested in calls that will ultimately return
                    // the full serialized DTXMessage payload.
                    && args[2].op != cot_num )
                  {
                    ea_t bpt = get_item_end(e->ea);
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
        bf.apply_to_exprs(&cfunc->body, NULL);
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

  if ( ea1 == BADADDR || ea2 == BADADDR )
  {
    dtxmsg_deb("input file does not look like the DTXConnectionServices library, skipping\n");
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
  const char *fname = ph.id == PLFM_ARM ? "requests.log" : "responses.log";
  qmakepath(path, sizeof(path), logdir, fname, NULL);

  logfp = qfopen(path, "w");
  if ( logfp == NULL )
  {
    dtxmsg_deb("Error: failed to open %s: %s\n", path, winerr(errno));
    return PLUGIN_SKIP;
  }

  dtxmsg_deb("logging to: %s\n", path);

  hook_to_notification_point(HT_DBG, dbg_callback);
  hook_to_notification_point(HT_IDB, idb_callback);

  return PLUGIN_KEEP;
}

//-----------------------------------------------------------------------------
static void idaapi term(void)
{
  unhook_from_notification_point(HT_DBG, dbg_callback);
  unhook_from_notification_point(HT_IDB, idb_callback);

  if ( logfp != NULL )
  {
    qfclose(logfp);
    logfp = NULL;
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
