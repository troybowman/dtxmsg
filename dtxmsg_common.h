#ifndef DTXMSG_COMMON_H
#define DTXMSG_COMMON_H

#include <CoreFoundation/CoreFoundation.h>
#include <pro.h>

//------------------------------------------------------------------------------
qstring to_qstring(CFStringRef ref);

//------------------------------------------------------------------------------
qstring get_description(CFTypeRef ref);

//------------------------------------------------------------------------------
void archive(bytevec_t *buf, CFTypeRef ref);

//------------------------------------------------------------------------------
CFTypeRef unarchive(const uchar *buf, size_t bufsize);

//------------------------------------------------------------------------------
// convert a serialized array to a CFArrayRef object
CFArrayRef deserialize(const uchar *buf, size_t bufsize, qstring *errbuf = NULL);

//------------------------------------------------------------------------------
// helper class for serializing method arguments
class message_aux_t
{
  bytevec_t buf;

public:
  void append_int(int32 val);
  void append_long(int64 val);
  void append_obj(CFTypeRef obj);

  void get_bytes(bytevec_t *out) const;
};

//-----------------------------------------------------------------------------
void append_d(bytevec_t &out, uint32 num);
void append_q(bytevec_t &out, uint64 num);
void append_b(bytevec_t &out, const bytevec_t &bv);
void append_v(bytevec_t &out, const void *v, size_t len);

//-----------------------------------------------------------------------------
struct DTXMessageHeader
{
  uint32 magic;
  uint32 cb;
  uint16 fragmentId;
  uint16 fragmentCount;
  uint32 length;
  uint32 identifier;
  uint32 conversationIndex;
  uint32 channelCode;
  uint32 expectsReply;
};

//-----------------------------------------------------------------------------
struct DTXMessagePayloadHeader
{
  uint32 flags;
  uint32 auxiliaryLength;
  uint64 totalLength;
};

#endif // DTXMSG_COMMON_H
