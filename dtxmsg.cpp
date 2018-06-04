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
static bool parse_message(ea_t buf, const DTXMessageHeader &mheader)
{
  // it is possible that this message is just one of many "fragments".
  // this happens when an object is too big to be transmitted in a single message
  // and is therefore split up across multiple messages. so, we always append the
  // current fragment to an incremental payload file and deserialize the data only
  // after all fragments have been read.
  ea_t fptr = buf + sizeof(mheader);
  ea_t flen = mheader.length;

  // the first fragment contains the payload header.
  // note that if a payload does not require multiple fragments, the fragmentId is 0.
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

  // append this fragment to the incremental payload file.
  // also note that different fragments for the same payload will
  // have the same message identifier.
  qstring fname;
  fname.sprnt("payload_%d.bin", mheader.identifier);

  char path[MAXSTR];
  qmakepath(path, sizeof(path), logdir, fname.c_str(), NULL);

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
static bool handle_dtxmsg_bpt(void)
{
  // read the return register
  regval_t val;
  const char *reg = ph.id == PLFM_ARM ? "X0" : "RAX";
  if ( !get_reg_val(reg, &val) )
  {
    dtxmsg_deb("Error: failed to get value of register %s\n", reg);
    return false;
  }

  // pointer to the message buffer
  ea_t buf = val.ival;

  // if buffer is NULL, just ignore it
  if ( buf == 0 )
    return true;

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

  // don't try to parse the message payload, unless instructed
  bool ok = true;
  if ( verbose )
    ok = parse_message(buf, mheader);

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

        if ( !handle_dtxmsg_bpt() )
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
static void set_dtxmsg_bpt(netnode &node, ea_t ea)
{
  if ( !add_bpt(ea, 1, BPT_DEFAULT) )
  {
    dtxmsg_deb("Error: failed to add breakpoint at %a\n", ea);
    return;
  }
  node.altset_ea(ea, 1, DTXMSG_ALT_BPTS);
  dtxmsg_deb("magic bpt: %a\n", ea);
}

//-----------------------------------------------------------------------------
static void set_dtxmsg_bpts_xcode8(netnode &node)
{
  const char *method = "-[DTXMessageParser parseMessageWithExceptionHandler:]";
  ea_t ea = get_name_ea(BADADDR, method);
  if ( ea == BADADDR )
  {
    dtxmsg_deb("failed to find %s in the database\n", method);
    return;
  }

  func_t *pfn = get_func(ea);
  if ( pfn == NULL )
  {
    dtxmsg_deb("Error: no function found at %a\n", ea);
    return;
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
    return;
  }

  // add breakpoints after calls to -[DTXMessageParser waitForMoreData:incrementalBuffer:].
  // this function returns a pointer to the raw DTXMessage data.
  struct ida_local bpt_finder_t : public minsn_visitor_t
  {
    netnode &node;
    bpt_finder_t(netnode &_node) : node(_node) {}
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
              // ignore calls with a constant as the length argument. they are likely just
              // reading the message header. we are only interested in calls that will return
              // a pointer to the full serialized message.
              && fi->args[2].t != mop_n )
            {
              set_dtxmsg_bpt(node, get_item_end(curins->ea));
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
}

//-----------------------------------------------------------------------------
static const lvar_t *find_retained_block(mbl_array_t *mba)
{
  ea_t retain_block = get_name_ea(BADADDR, "_objc_retainBlock");
  if ( retain_block == BADADDR )
    return NULL;

  // find a variable that is initialized like: v1 = objc_retainBlock(&block);
  for ( mblock_t *b = mba->blocks; b != NULL; b = b->nextb )
  {
    for ( minsn_t *m = b->head; m != NULL; m = m->next )
    {
      if ( m->opcode == m_mov && m->d.t == mop_l && m->l.t == mop_d )
      {
        const minsn_t *d = m->l.d;
        if ( d->opcode == m_call )
        {
          const mfuncinfo_t *fi = d->d.f;
          if ( fi->callee == retain_block )
          {
            // found a retained block
            const lvar_t *v = &m->d.l->var();
            // if the code later assigns this variable to another one,
            // the new variable takes priority
            for ( minsn_t *n = m->next; n != NULL; n = n->next )
            {
              if ( n->opcode == m_mov
                && n->d.t == mop_l
                && n->l.t == mop_l
                && n->l.l->var() == *v )
              {
                v = &n->d.l->var();
              }
            }
            return v;
          }
        }
      }
    }
  }

  return NULL;
}

//-----------------------------------------------------------------------------
static void set_dtxmsg_bpts_xcode9(netnode &node)
{
  const char *method = "-[DTXMessageParser parseIncomingBytes:length:]";
  ea_t ea = get_name_ea(BADADDR, method);
  if ( ea == BADADDR )
  {
    dtxmsg_deb("Error: failed to find %s in the database\n", method);
    return;
  }

  func_t *pfn = get_func(ea);
  if ( pfn == NULL )
  {
    dtxmsg_deb("Error: no function found at %a\n", ea);
    return;
  }

  // in Xcode 9, -[DTXMessageParser parseMessageWithExceptionHandler:] was replaced
  // with a block function.
  func_t *parser_block = NULL;

  func_item_iterator_t fii;
  for ( bool ok = fii.set(pfn); ok; ok = fii.next_addr() )
  {
    ea_t xref = get_first_dref_from(fii.current());
    if ( xref != BADADDR )
    {
      func_t *_pfn = get_func(xref);
      if ( _pfn != NULL && get_name(xref).find("block_invoke") != qstring::npos )
      {
        parser_block = _pfn;
        break;
      }
    }
  }

  if ( parser_block == NULL )
  {
    dtxmsg_deb("Error: expected a block function in %s\n", method);
    return;
  }

  mba_ranges_t mbr(parser_block);
  hexrays_failure_t hf;
  mbl_array_t *mba = gen_microcode(
          mbr,
          &hf,
          NULL,
          DECOMP_NO_WAIT,
          MMAT_LVARS);

  if ( mba == NULL )
  {
    dtxmsg_deb("microcode failure at %a: %s\n", hf.errea, hf.desc().c_str());
    return;
  }

  // Xcode 9 also replaced -[DTXMessageParser waitForMoreData:incrementalBuffer:]
  // with a block function. the return value of this block function will be
  // a pointer to the serialized message data. we must find all instances where
  // it is invoked.
  const lvar_t *bvar = find_retained_block(mba);
  if ( bvar == NULL )
  {
    dtxmsg_deb("Error: expected to find objc_retainBlock() in function %a\n", parser_block->start_ea);
    return;
  }

  struct ida_local bpt_finder_t : public minsn_visitor_t
  {
    netnode &node;
    const lvar_t &bvar;

    bpt_finder_t(netnode &_node, const lvar_t &_bvar) : node(_node), bvar(_bvar) {}

    virtual int idaapi visit_minsn(void)
    {
      if ( curins->opcode == m_icall )
      {
        const mfuncinfo_t *fi = curins->d.f;
        // if the block variable is the first argument for an indirect call,
        // this is likely a call to the invoke function
        if ( fi->args.size() >= 2
          && fi->args[0].t == mop_l
          && fi->args[0].l->var() == bvar
          // ignore calls with a constant as the length argument. they are likely just
          // reading the message header. we are only interested in calls that will return
          // a pointer to the full serialized message
          && fi->args[1].t != mop_n )
        {
          set_dtxmsg_bpt(node, get_item_end(curins->ea));
        }
      }
      return 0;
    }
  };

  bpt_finder_t bf(node, *bvar);
  mba->for_all_insns(bf);

  delete mba;
}

//-----------------------------------------------------------------------------
static void print_node_info(const char *pfx)
{
  netnode node;
  node.create(DTXMSG_NODE);

  dtxmsg_deb("node info: %s\n", pfx);
  dtxmsg_deb("  dtx version: %a\n", node.altval(DTXMSG_ALT_VERSION));

  for ( nodeidx_t idx = node.altfirst(DTXMSG_ALT_BPTS);
        idx != BADNODE;
        idx = node.altnext(idx, DTXMSG_ALT_BPTS) )
  {
    dtxmsg_deb("  magic bpt:   %a\n", node2ea(idx));
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

        // sometime around Xcode 9, Apple decided to change everything
        uint64 version = node.altval(DTXMSG_ALT_VERSION);
        if ( version < 0x40EED00000000000LL )
          set_dtxmsg_bpts_xcode8(node);
        else
          set_dtxmsg_bpts_xcode9(node);

        if ( node.altfirst(DTXMSG_ALT_BPTS) == BADNODE )
          warning(DTXMSG_DEB_PFX " failed to detect any critical breakpoints!");
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

        print_node_info("rebased");
      }
      break;

    default:
      break;
  }

  return 0;
}

//-----------------------------------------------------------------------------
static ssize_t idaapi ui_callback(void *, int code, va_list)
{
  switch ( code )
  {
    case ui_ready_to_run:
      {
        // it is possible that struct DTXMessageHeader was encoded in the objc types.
        // we overwrite it with our own struct that has better member names.
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

        if ( h2ti(NULL, NULL, decls, HTI_DCL, NULL, NULL, msg) != 0
          || import_type(NULL, -1, "DTXMessageHeader") == BADNODE
          || import_type(NULL, -1, "DTXMessagePayloadHeader") == BADNODE )
        {
          dtxmsg_deb("Error: failed to import DTXMessage helper types\n");
        }
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
  ea_t version_ea = get_name_ea(BADADDR, "_DTXConnectionServicesVersionNumber");
  if ( version_ea == BADADDR )
  {
    dtxmsg_deb("input file does not look the DTXConnectionServices library, skipping\n");
    return PLUGIN_SKIP;
  }

  if ( !init_hexrays_plugin() )
  {
    dtxmsg_deb("Error: this plugin requires the hexrays decompiler!\n");
    return PLUGIN_SKIP;
  }

  netnode node;
  node.create(DTXMSG_NODE);
  if ( node.altval(DTXMSG_ALT_VERSION) == 0 )
  {
    // working with a fresh database - must perform some setup
    node.altset(DTXMSG_ALT_VERSION, get_qword(version_ea));

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
  }
  else
  {
    // already configured the debugging environment
    print_node_info("saved");
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

  hook_to_notification_point(HT_UI,  ui_callback);
  hook_to_notification_point(HT_IDB, idb_callback);
  hook_to_notification_point(HT_DBG, dbg_callback);

  return PLUGIN_KEEP;
}

//-----------------------------------------------------------------------------
static void idaapi term(void)
{
  unhook_from_notification_point(HT_UI,  ui_callback);
  unhook_from_notification_point(HT_IDB, idb_callback);
  unhook_from_notification_point(HT_DBG, dbg_callback);

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
  PLUGIN_HIDE,           // plugin flags
  init,                  // initialize
  term,                  // terminate. this pointer may be NULL.
  run,                   // invoke plugin
  NULL,                  // long comment about the plugin
  NULL,                  // multiline help about the plugin
  "",                    // the preferred short name of the plugin
  NULL                   // the preferred hotkey to run the plugin
};
