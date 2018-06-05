#include "dtxmsg_client.h"
#include <err.h>
#include <dlfcn.h>

static qstring device_id;               // user's preferred device (-d option)
static bool found_device = false;       // has the user's preferred device been detected?
static bool verbose = false;            // verbose mode (-v option)
static int cur_message = 0;             // current message id
static int cur_channel = 0;             // current channel id
static CFDictionaryRef channels = NULL; // list of available channels published by the instruments server
static int pid2kill = -1;               // process id to kill ("kill" option)
static const char *bid2launch = NULL;   // bundle id of app to launch ("launch" option)
static bool proclist = false;           // print the process list ("proclist" option)
static bool applist = false;            // print the application list ("applist" option)

//-----------------------------------------------------------------------------
// pointers to functions in MobileDevice.framework
static mach_error_t (*AMDeviceNotificationSubscribe)(am_device_notification_callback_t *, int, int, void *, am_device_notification **);
static mach_error_t (*AMDeviceNotificationUnsubscribe)(am_device_notification *);
static CFStringRef (*AMDeviceCopyDeviceIdentifier)(am_device *);
static mach_error_t (*AMDeviceConnect)(am_device *);
static int (*AMDeviceIsPaired)(am_device *);
static mach_error_t (*AMDeviceValidatePairing)(am_device *);
static mach_error_t (*AMDeviceStartSession)(am_device *);
static mach_error_t (*AMDeviceStopSession)(am_device *);
static mach_error_t (*AMDeviceDisconnect)(am_device *);
static mach_error_t (*AMDeviceSecureStartService)(am_device *, CFStringRef, int *, am_device_service_connection **);
static void (*AMDServiceConnectionInvalidate)(am_device_service_connection *);
static mach_error_t (*AMDServiceConnectionSend)(am_device_service_connection *, const void *, size_t);
static mach_error_t (*AMDServiceConnectionReceive)(am_device_service_connection *, void *, size_t);

//-----------------------------------------------------------------------------
static bool load_mobile_device(void)
{
  const char *path = "/System/Library/PrivateFrameworks/MobileDevice.framework/MobileDevice";
  void *handle = dlopen(path, RTLD_NOW);
  if ( handle == NULL )
  {
    qeprintf("dlopen() failed for %s: %s", path, dlerror());
    return false;
  }

#define BINDFUN(name, type)                                    \
  name = reinterpret_cast<type>(dlsym(handle, #name));         \
  if ( name == NULL )                                          \
  {                                                            \
    qeprintf("Could not find function " #name " in %s", path); \
    return false;                                              \
  }

  BINDFUN(AMDeviceNotificationSubscribe, mach_error_t (*)(am_device_notification_callback_t *, int, int, void *, am_device_notification **));
  BINDFUN(AMDeviceNotificationUnsubscribe, mach_error_t (*)(am_device_notification *));
  BINDFUN(AMDeviceCopyDeviceIdentifier, CFStringRef (*)(am_device *));
  BINDFUN(AMDeviceConnect, mach_error_t (*)(am_device *));
  BINDFUN(AMDeviceIsPaired, int (*)(am_device *));
  BINDFUN(AMDeviceValidatePairing, mach_error_t (*)(am_device *));
  BINDFUN(AMDeviceStartSession, mach_error_t (*)(am_device *));
  BINDFUN(AMDeviceStopSession, mach_error_t (*)(am_device *));
  BINDFUN(AMDeviceDisconnect, mach_error_t (*)(am_device *));
  BINDFUN(AMDeviceSecureStartService, mach_error_t (*)(am_device *, CFStringRef, int *, am_device_service_connection **));
  BINDFUN(AMDServiceConnectionInvalidate, void (*)(am_device_service_connection *));
  BINDFUN(AMDServiceConnectionSend, mach_error_t (*)(am_device_service_connection *, const void *, size_t));
  BINDFUN(AMDServiceConnectionReceive, mach_error_t (*)(am_device_service_connection *, void *, size_t));

#undef BINDFUN

  return true;
}

//-----------------------------------------------------------------------------
// callback that handles device notifications. called once for each connected device.
static void device_callback(am_device_notification_callback_info *cbi, void *arg)
{
  if ( cbi->code != ADNCI_MSG_CONNECTED )
    return;

  CFStringRef id = AMDeviceCopyDeviceIdentifier(cbi->dev);
  qstring _device_id = to_qstring(id);
  CFRelease(id);

  if ( !device_id.empty() && device_id != _device_id )
    return;

  found_device = true;

  if ( verbose )
    qprintf("found device: %s\n", _device_id.c_str());

  do
  {
    // start a session on the device
    if ( AMDeviceConnect(cbi->dev) != kAMDSuccess
      || AMDeviceIsPaired(cbi->dev) == 0
      || AMDeviceValidatePairing(cbi->dev) != kAMDSuccess
      || AMDeviceStartSession(cbi->dev) != kAMDSuccess )
    {
      qeprintf("Error: failed to start a session on the device\n");
      break;
    }

    am_device_service_connection **connptr = (am_device_service_connection **)arg;

    // launch the instruments server
    mach_error_t err = AMDeviceSecureStartService(
            cbi->dev,
            CFSTR("com.apple.instruments.remoteserver"),
            NULL,
            connptr);

    if ( err != kAMDSuccess )
    {
      qeprintf("Failed to start the instruments server (0x%x). "
               "Perhaps DeveloperDiskImage.dmg is not installed on the device?\n", err);
      break;
    }

    if ( verbose )
      qprintf("successfully launched instruments server\n");
  }
  while ( false );

  AMDeviceStopSession(cbi->dev);
  AMDeviceDisconnect(cbi->dev);

  CFRunLoopStop(CFRunLoopGetCurrent());
}

//-----------------------------------------------------------------------------
// launch the instruments server on the user's device.
// returns a handle that can be used to send/receive data to/from the server.
static am_device_service_connection *start_server(void)
{
  am_device_notification *notify_handle = NULL;
  am_device_service_connection *conn = NULL;

  mach_error_t err = AMDeviceNotificationSubscribe(
          device_callback,
          0,
          0,
          &conn,
          &notify_handle);

  if ( err != kAMDSuccess )
  {
    qeprintf("failed to register device notifier: 0x%x\n", err);
    return NULL;
  }

  // start a run loop, and wait for the device notifier to call our callback function.
  // if no device was detected within 3 seconds, we bail out.
  CFRunLoopRunInMode(kCFRunLoopDefaultMode, 3, false);

  AMDeviceNotificationUnsubscribe(notify_handle);

  if ( conn == NULL && !found_device )
  {
    if ( device_id.empty() )
      qeprintf("Failed to find a connected device\n");
    else
      qeprintf("Failed to find device with id = %s\n", device_id.c_str());
    return NULL;
  }

  return conn;
}

//-----------------------------------------------------------------------------
// "call" an Objective-C method in the instruments server process
//   conn           server handle
//   channel        determines the object that will receive the message,
//                  obtained by a previous call to make_channel()
//   selector       method name
//   args           serialized list of arguments for the method
//   expects_reply  do we expect a return value from the method?
//                  the return value can be obtained by a subsequent call to recv_message()
static bool send_message(
        am_device_service_connection *conn,
        int channel,
        CFStringRef selector,
        const message_aux_t *args,
        bool expects_reply = true)
{
  uint32 id = ++cur_message;

  bytevec_t aux;
  if ( args != NULL )
    args->get_bytes(&aux);

  bytevec_t sel;
  if ( selector != NULL )
    archive(&sel, selector);

  DTXMessagePayloadHeader pheader;
  // the low byte of the payload flags represents the message type.
  // so far it seems that all requests to the instruments server have message type 2.
  pheader.flags = 0x2 | (expects_reply ? 0x1000 : 0);
  pheader.auxiliaryLength = aux.size();
  pheader.totalLength = aux.size() + sel.size();

  DTXMessageHeader mheader;
  mheader.magic = 0x1F3D5B79;
  mheader.cb = sizeof(DTXMessageHeader);
  mheader.fragmentId = 0;
  mheader.fragmentCount = 1;
  mheader.length = sizeof(pheader) + pheader.totalLength;
  mheader.identifier = id;
  mheader.conversationIndex = 0;
  mheader.channelCode = channel;
  mheader.expectsReply = (expects_reply ? 1 : 0);

  bytevec_t msg;
  append_v(msg, &mheader, sizeof(mheader));
  append_v(msg, &pheader, sizeof(pheader));
  append_b(msg, aux);
  append_b(msg, sel);

  size_t msglen = msg.size();

  if ( AMDServiceConnectionSend(conn, msg.begin(), msglen) != msglen )
  {
    qeprintf("Failed to send 0x%x bytes of message: %s\n", msglen, winerr(errno));
    return false;
  }

  return true;
}

//-----------------------------------------------------------------------------
// handle a response from the server.
//   conn    server handle
//   retobj  contains the return value for the method invoked by send_message()
//   aux     usually empty, except in specific situations (see _notifyOfPublishedCapabilities)
static bool recv_message(
        am_device_service_connection *conn,
        CFTypeRef *retobj,
        CFArrayRef *aux)
{
  uint32 id = 0;
  bytevec_t payload;

  while ( true )
  {
    DTXMessageHeader mheader;
    ssize_t nrecv = AMDServiceConnectionReceive(conn, &mheader, sizeof(mheader));
    if ( nrecv != sizeof(mheader) )
    {
      qeprintf("failed to read message header: %s, nrecv = %lx", winerr(errno), nrecv);
      return false;
    }

    if ( mheader.magic != 0x1F3D5B79 )
    {
      qeprintf("bad header magic: %x", mheader.magic);
      return false;
    }

    if ( mheader.conversationIndex == 1 )
    {
      // the message is a response to a previous request, so it should have the same id as the request
      if ( mheader.identifier != cur_message )
      {
        qeprintf("expected response to message id=%d, got a new message with id=%d", cur_message, mheader.identifier);
        return false;
      }
    }
    else if ( mheader.conversationIndex == 0 )
    {
      // the message is not a response to a previous request. in this case, different iOS versions produce different results.
      // on iOS 9, the incoming message can have the same message ID has the previous message we sent to the server.
      // on later versions, the incoming message will have a new message ID. we must be aware of both situations.
      if ( mheader.identifier > cur_message )
      {
        // new message id, we must update the count on our side
        cur_message = mheader.identifier;
      }
      else if ( mheader.identifier < cur_message )
      {
        // the id must match the previous request, anything else doesn't really make sense
        qeprintf("unexpected message ID: %d", mheader.identifier);
        return false;
      }
    }
    else
    {
      qeprintf("invalid conversation index: %d", mheader.conversationIndex);
      return false;
    }

    if ( mheader.fragmentId == 0 )
    {
      id = mheader.identifier;
      // when reading multiple message fragments, the 0th fragment contains only a message header
      if ( mheader.fragmentCount > 1 )
        continue;
    }

    // read the entire payload in the current fragment
    bytevec_t frag;
    frag.append(&mheader, sizeof(mheader));
    frag.growfill(mheader.length);

    uchar *data = frag.begin() + sizeof(mheader);

    uint32 nbytes = 0;
    while ( nbytes < mheader.length )
    {
      nrecv = AMDServiceConnectionReceive(conn, data+nbytes, mheader.length-nbytes);
      if ( nrecv <= 0 )
      {
        qeprintf("failed reading from socket: %s", winerr(errno));
        return false;
      }
      nbytes += nrecv;
    }

    // append to the incremental payload
    payload.append(data, mheader.length);

    // done reading message fragments?
    if ( mheader.fragmentId == mheader.fragmentCount - 1 )
      break;
  }

  const DTXMessagePayloadHeader *pheader = (const DTXMessagePayloadHeader *)payload.begin();

  // we don't know how to decompress messages yet
  uint8 compression = (pheader->flags & 0xFF000) >> 12;
  if ( compression != 0 )
  {
    qeprintf("message is compressed (compression type %d)", compression);
    return false;
  }

  // serialized object array is located just after payload header
  const uchar *auxptr = payload.begin() + sizeof(DTXMessagePayloadHeader);
  uint32 auxlen = pheader->auxiliaryLength;

  // archived payload object appears after the auxiliary array
  const uchar *objptr = auxptr + auxlen;
  uint64 objlen = pheader->totalLength - auxlen;

  if ( auxlen != 0 && aux != NULL )
  {
    qstring errbuf;
    CFArrayRef _aux = deserialize(auxptr, auxlen, &errbuf);
    if ( _aux == NULL )
    {
      qeprintf("Error: %s\n", errbuf.c_str());
      return false;
    }
    *aux = _aux;
  }

  if ( objlen != 0 && retobj != NULL )
    *retobj = unarchive(objptr, objlen);

  return true;
}

//-----------------------------------------------------------------------------
// perform the initial client-server handshake.
// here we retrieve the list of available channels published by the instruments server.
// we can open a given channel with make_channel().
static bool perform_handshake(am_device_service_connection *conn)
{
  // I'm not sure if this argument is necessary - but Xcode uses it, so I'm using it too.
  CFMutableDictionaryRef capabilities = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);

  int64 _v1 = 1;
  int64 _v2 = 2;

  CFNumberRef v1 = CFNumberCreate(NULL, kCFNumberSInt64Type, &_v1);
  CFNumberRef v2 = CFNumberCreate(NULL, kCFNumberSInt64Type, &_v2);

  CFDictionaryAddValue(capabilities, CFSTR("com.apple.private.DTXBlockCompression"), v2);
  CFDictionaryAddValue(capabilities, CFSTR("com.apple.private.DTXConnection"), v1);

  // serialize the dictionary
  message_aux_t args;
  args.append_obj(capabilities);

  CFRelease(capabilities);
  CFRelease(v1);
  CFRelease(v2);

  if ( !send_message(conn, 0, CFSTR("_notifyOfPublishedCapabilities:"), &args, false) )
    return false;

  CFTypeRef obj = NULL;
  CFArrayRef aux = NULL;

  // we are now expecting the server to reply with the same message.
  // a description of all available channels will be provided in the arguments list.
  if ( !recv_message(conn, &obj, &aux) || obj == NULL || aux == NULL )
  {
    qeprintf("Error: failed to receive response from _notifyOfPublishedCapabilities:\n");
    return false;
  }

  bool ok = false;
  do
  {
    if ( CFGetTypeID(obj) != CFStringGetTypeID()
      || to_qstring((CFStringRef)obj) != "_notifyOfPublishedCapabilities:" )
    {
      qeprintf("Error: unexpected message selector: %s\n", get_description(obj).c_str());
      break;
    }

    CFDictionaryRef _channels;

    // extract the channel list from the arguments
    if ( CFArrayGetCount(aux) != 1
      || (_channels = (CFDictionaryRef)CFArrayGetValueAtIndex(aux, 0)) == NULL
      || CFGetTypeID(_channels) != CFDictionaryGetTypeID()
      || CFDictionaryGetCount(_channels) == 0 )
    {
      qeprintf("channel list has an unexpected format:\n%s\n", get_description(aux).c_str());
      break;
    }

    channels = (CFDictionaryRef)CFRetain(_channels);

    if ( verbose )
      qprintf("channel list:\n%s\n", get_description(channels).c_str());

    ok = true;
  }
  while ( false );

  CFRelease(obj);
  CFRelease(aux);

  return ok;
}

//-----------------------------------------------------------------------------
// establish a connection to a service in the instruments server process.
// the channel identifier should be in the list of channels returned by the server
// in perform_handshake(). after a channel is established, you can use send_message()
// to remotely invoke Objective-C methods.
static int make_channel(am_device_service_connection *conn, CFStringRef identifier)
{
  if ( !CFDictionaryContainsKey(channels, identifier) )
  {
    qeprintf("channel %s is not supported by the server", to_qstring(identifier).c_str());
    return -1;
  }

  int code = ++cur_channel;

  message_aux_t args;
  args.append_int(code);
  args.append_obj(identifier);

  CFTypeRef retobj = NULL;

  // request to open the channel, expect an empty reply
  if ( !send_message(conn, 0, CFSTR("_requestChannelWithCode:identifier:"), &args)
    || !recv_message(conn, &retobj, NULL) )
  {
    return -1;
  }

  if ( retobj != NULL )
  {
    qeprintf("Error: _requestChannelWithCode:identifier: returned %s", get_description(retobj).c_str());
    CFRelease(retobj);
    return -1;
  }

  return code;
}

//-----------------------------------------------------------------------------
// invoke method -[DTDeviceInfoService runningProcesses]
//   args:    none
//   returns: CFArrayRef procs
static bool print_proclist(am_device_service_connection *conn)
{
  int channel = make_channel(conn, CFSTR("com.apple.instruments.server.services.deviceinfo"));
  if ( channel < 0 )
    return false;

  CFTypeRef retobj = NULL;

  if ( !send_message(conn, channel, CFSTR("runningProcesses"), NULL)
    || !recv_message(conn, &retobj, NULL)
    || retobj == NULL )
  {
    qeprintf("Error: failed to retrieve return value for runningProcesses\n");
    return false;
  }

  bool ok = true;
  if ( CFGetTypeID(retobj) == CFArrayGetTypeID() )
  {
    CFArrayRef array = (CFArrayRef)retobj;

    qprintf("proclist:\n");
    for ( size_t i = 0, size = CFArrayGetCount(array); i < size; i++ )
    {
      CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(array, i);

      CFStringRef _name = (CFStringRef)CFDictionaryGetValue(dict, CFSTR("name"));
      qstring name = to_qstring(_name);

      CFNumberRef _pid = (CFNumberRef)CFDictionaryGetValue(dict, CFSTR("pid"));
      int pid = 0;
      CFNumberGetValue(_pid, kCFNumberSInt32Type, &pid);

      qprintf("%6d %s\n", pid, name.c_str());
    }
  }
  else
  {
    qeprintf("Error: process list is not in the expected format: %s\n", get_description(retobj).c_str());
    ok = false;
  }

  CFRelease(retobj);
  return ok;
}

//-----------------------------------------------------------------------------
// invoke method -[DTApplicationListingService installedApplicationsMatching:registerUpdateToken:]
//   args:   CFDictionaryRef dict
//           CFStringRef token
//   returns CFArrayRef apps
static bool print_applist(am_device_service_connection *conn)
{
  int channel = make_channel(conn, CFSTR("com.apple.instruments.server.services.device.applictionListing"));
  if ( channel < 0 )
    return false;

  // the method expects a dictionary and a string argument.
  // pass empty values so we get descriptions for all known applications.
  CFDictionaryRef dict = CFDictionaryCreate(NULL, NULL, NULL, 0, NULL, NULL);

  message_aux_t args;
  args.append_obj(dict);
  args.append_obj(CFSTR(""));

  CFRelease(dict);

  CFTypeRef retobj = NULL;

  if ( !send_message(conn, channel, CFSTR("installedApplicationsMatching:registerUpdateToken:"), &args)
    || !recv_message(conn, &retobj, NULL)
    || retobj == NULL )
  {
    qeprintf("Error: failed to retrieve applist\n");
    return false;
  }

  bool ok = true;
  if ( CFGetTypeID(retobj) == CFArrayGetTypeID() )
  {
    CFArrayRef array = (CFArrayRef)retobj;
    for ( size_t i = 0, size = CFArrayGetCount(array); i < size; i++ )
    {
      CFDictionaryRef app_desc = (CFDictionaryRef)CFArrayGetValueAtIndex(array, i);
      qprintf("%s\n", get_description(app_desc).c_str());
    }
  }
  else
  {
    qeprintf("apps list has an unexpected format: %s", get_description(retobj).c_str());
    ok = false;
  }

  CFRelease(retobj);
  return ok;
}

//-----------------------------------------------------------------------------
// invoke method -[DTProcessControlService killPid:]
//   args:    CFNumberRef process_id
//   returns: void
static bool kill(am_device_service_connection *conn, int pid)
{
  int channel = make_channel(conn, CFSTR("com.apple.instruments.server.services.processcontrol"));
  if ( channel < 0 )
    return false;

  CFNumberRef _pid = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);

  message_aux_t args;
  args.append_obj(_pid);

  CFRelease(_pid);

  return send_message(conn, channel, CFSTR("killPid:"), &args, false);
}

//-----------------------------------------------------------------------------
// invoke method -[DTProcessControlService launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:]
//   args:    CFStringRef app_path
//            CFStringRef bundle_id
//            CFArrayRef args_for_app
//            CFDictionaryRef environment_vars
//            CFDictionaryRef launch_options
//   returns: CFNumberRef pid
static bool launch(am_device_service_connection *conn, const char *_bid)
{
  int channel = make_channel(conn, CFSTR("com.apple.instruments.server.services.processcontrol"));
  if ( channel < 0 )
    return false;

  // app path: not used, just pass empty string
  CFStringRef path = CFStringCreateWithCString(NULL, "", kCFStringEncodingUTF8);
  // bundle id
  CFStringRef bid = CFStringCreateWithCString(NULL, _bid, kCFStringEncodingUTF8);
  // args for app: not used, just pass empty array
  CFArrayRef appargs = CFArrayCreate(NULL, NULL, 0, NULL);
  // environment variables: not used, just pass empty dictionary
  CFDictionaryRef env = CFDictionaryCreate(NULL, NULL, NULL, 0, NULL, NULL);

  // launch options
  int _v0 = 0; // don't suspend the process after starting it
  int _v1 = 1; // kill the application if it is already running

  CFNumberRef v0 = CFNumberCreate(NULL, kCFNumberSInt32Type, &_v0);
  CFNumberRef v1 = CFNumberCreate(NULL, kCFNumberSInt32Type, &_v1);

  const void *keys[] =
  {
    CFSTR("StartSuspendedKey"),
    CFSTR("KillExisting")
  };
  const void *values[] = { v0, v1 };
  CFDictionaryRef options = CFDictionaryCreate(
        NULL,
        keys,
        values,
        qnumber(values),
        NULL,
        NULL);

  message_aux_t args;
  args.append_obj(path);
  args.append_obj(bid);
  args.append_obj(env);
  args.append_obj(appargs);
  args.append_obj(options);

  CFRelease(v1);
  CFRelease(v0);
  CFRelease(options);
  CFRelease(env);
  CFRelease(appargs);
  CFRelease(bid);
  CFRelease(path);

  CFTypeRef retobj = NULL;

  if ( !send_message(conn, channel, CFSTR("launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:"), &args)
    || !recv_message(conn, &retobj, NULL)
    || retobj == NULL )
  {
    qeprintf("Error: failed to launch %s\n", _bid);
    return false;
  }

  bool ok = true;
  if ( CFGetTypeID(retobj) == CFNumberGetTypeID() )
  {
    CFNumberRef _pid = (CFNumberRef)retobj;
    int pid = 0;
    CFNumberGetValue(_pid, kCFNumberSInt32Type, &pid);
    qprintf("pid: %d\n", pid);
  }
  else
  {
    qeprintf("failed to retrieve the process ID: %s\n", get_description(retobj).c_str());
    ok = false;
  }

  CFRelease(retobj);
  return ok;
}

//-----------------------------------------------------------------------------
static void usage(const char *prog)
{
  qeprintf("usage: %s [-v] [-d <device id>] TASK <task args>\n"
           "\n"
           "This is a sample client application for the iOS Instruments server.\n"
           "It is capable of rudimentary communication with the server and can\n"
           "ask it to perform some interesting tasks.\n"
           "\n"
           "TASK can be one of the following:\n"
           "  proclist  - print a list of running processes\n"
           "  applist   - print a list of installed applications\n"
           "  launch    - launch a given app. provide the bundle id of the app to launch\n"
           "  kill      - kill a given process. provide the pid of the process to kill\n"
           "\n"
           "other args:\n"
           "  -v  more verbose output\n"
           "  -d  device ID. if empty, this app will use the first device it finds\n", prog);
}

//-----------------------------------------------------------------------------
static bool parse_args(int argc, const char **argv)
{
  if ( argc > 1 )
  {
    for ( int i = 1; i < argc; )
    {
      if ( streq("-v", argv[i]) )
      {
        verbose = true;
        i++;
        continue;
      }
      else if ( streq("-d", argv[i]) )
      {
        if ( i == argc - 1 )
        {
          qeprintf("Error: -d option requires a device id string\n");
          break;
        }
        device_id = argv[i+1];
        i += 2;
        continue;
      }

      qstring task = argv[i];

      if ( task == "proclist" )
      {
        proclist = true;
        return true;
      }
      else if ( task == "applist" )
      {
        applist = true;
        return true;
      }
      else if ( task == "kill" )
      {
        if ( i == argc - 1 )
        {
          qeprintf("Error: \"kill\" requires a process id\n");
          break;
        }
        pid2kill = atoi(argv[i+1]);
        return true;
      }
      else if ( task == "launch" )
      {
        if ( i == argc - 1 )
        {
          qeprintf("Error: \"launch\" requires a bundle id\n");
          break;
        }
        bid2launch = argv[i+1];
        return true;
      }

      qeprintf("Error, invalid task: %s\n", task.c_str());
      break;
    }
  }

  usage(argv[0]);
  return false;
}

//-----------------------------------------------------------------------------
int main(int argc, const char **argv)
{
  if ( !parse_args(argc, argv) )
    return EXIT_FAILURE;

  if ( !load_mobile_device() )
    return EXIT_FAILURE;

  am_device_service_connection *conn = start_server();
  if ( conn == NULL )
    return EXIT_FAILURE;

  bool ok = false;
  if ( perform_handshake(conn) )
  {
    if ( proclist )
      ok = print_proclist(conn);
    else if ( applist )
      ok = print_applist(conn);
    else if ( pid2kill > 0 )
      ok = kill(conn, pid2kill);
    else if ( bid2launch != NULL )
      ok = launch(conn, bid2launch);
    else
      ok = true;

    CFRelease(channels);
  }

  AMDServiceConnectionInvalidate(conn);
  CFRelease(conn);

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
