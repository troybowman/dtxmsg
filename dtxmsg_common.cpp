#include <Foundation/Foundation.h>
#include "dtxmsg_common.h"

//------------------------------------------------------------------------------
qstring to_qstring(CFStringRef ref)
{
  if ( ref == NULL )
    return "";

  CFIndex length = CFStringGetLength(ref);
  if ( length <= 0 )
    return "";

  CFIndex bufsize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  char *buf = (char *)qalloc(bufsize);

  qstring ret;
  if ( CFStringGetCString(ref, buf, bufsize, kCFStringEncodingUTF8) )
    ret.inject(buf);

  return ret;
}

//------------------------------------------------------------------------------
qstring get_description(CFTypeRef ref)
{
  CFStringRef desc = CFCopyDescription(ref);
  qstring ret = to_qstring(desc);
  CFRelease(desc);
  return ret;
}

//-----------------------------------------------------------------------------
void archive(bytevec_t *buf, CFTypeRef ref)
{
  @autoreleasepool
  {
    id object = (__bridge id)ref;
    NSData *data=[NSKeyedArchiver archivedDataWithRootObject:object];
    const void *bytes=[data bytes];
    int length=[data length];
    buf->append(bytes, length);
  }
}

//-----------------------------------------------------------------------------
CFTypeRef unarchive(const uchar *buf, size_t bufsize)
{
  @autoreleasepool
  {
    NSData *data=[NSData dataWithBytesNoCopy:(void *)buf length:bufsize freeWhenDone:false];
    id object=[NSKeyedUnarchiver unarchiveObjectWithData:data];
    return (__bridge CFTypeRef)[object retain];
  }
}

//-----------------------------------------------------------------------------
CFArrayRef deserialize(
        const uchar *buf,
        size_t bufsize,
        qstring *errbuf)
{
  if ( bufsize < 16 )
  {
    errbuf->sprnt("Error: buffer of size 0x%lx is too small for a serialized array", bufsize);
    return NULL;
  }

  uint64 size = *((uint64 *)buf+1);
  if ( size > bufsize )
  {
    errbuf->sprnt("size of array object (%llx) is larger than total length of data (%lx)", size, bufsize);
    return NULL;
  }

  CFMutableArrayRef array = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

  uint64 off = sizeof(uint64) * 2;
  uint64 end = off + size;

  while ( off < end )
  {
    int length = 0;
    int type = *((int *)(buf+off));
    off += sizeof(int);

    CFTypeRef ref = NULL;

    switch ( type )
    {
      case 2:
        // archived object
        length = *((int *)(buf+off));
        off += sizeof(int);
        ref = unarchive(buf+off, length);
        break;

      case 3:
        // 32-bit int
        ref = CFNumberCreate(NULL, kCFNumberSInt32Type, buf+off);
        length = 4;
        break;

      case 4:
        // 64-bit int
        ref = CFNumberCreate(NULL, kCFNumberSInt64Type, buf+off);
        length = 8;
        break;

      case 10:
        // dictionary key. for arrays, the keys are empty and we ignore them
        continue;

      default:
        // there are more. we will deal with them as necessary
        break;
    }

    if ( ref == NULL )
    {
      errbuf->sprnt("invalid object at offset %llx, type: %d\n", off, type);
      return NULL;
    }

    CFArrayAppendValue(array, ref);
    CFRelease(ref);
    off += length;
  }

  return (CFArrayRef)array;
}

//-----------------------------------------------------------------------------
void append_d(bytevec_t &out, uint32 num)
{
  out.append(&num, sizeof(num));
}

//-----------------------------------------------------------------------------
void append_q(bytevec_t &out, uint64 num)
{
  out.append(&num, sizeof(num));
}

//-----------------------------------------------------------------------------
void append_b(bytevec_t &out, const bytevec_t &bv)
{
  out.append(bv.begin(), bv.size());
}

//-----------------------------------------------------------------------------
void append_v(bytevec_t &out, const void *v, size_t len)
{
  out.append(v, len);
}

//-----------------------------------------------------------------------------
void message_aux_t::append_int(int32 val)
{
  append_d(buf, 10);  // empty dictionary key
  append_d(buf, 3);   // 32-bit int
  append_d(buf, val);
}

//-----------------------------------------------------------------------------
void message_aux_t::append_long(int64 val)
{
  append_d(buf, 10);  // empty dictionary key
  append_d(buf, 4);   // 64-bit int
  append_q(buf, val);
}

//-----------------------------------------------------------------------------
void message_aux_t::append_obj(CFTypeRef obj)
{
  append_d(buf, 10);  // empty dictionary key
  append_d(buf, 2);   // archived object

  bytevec_t tmp;
  archive(&tmp, obj);

  append_d(buf, tmp.size());
  append_b(buf, tmp);
}

//-----------------------------------------------------------------------------
void message_aux_t::get_bytes(bytevec_t *out) const
{
  if ( !buf.empty() )
  {
    // the final serialized array must start with a magic qword,
    // followed by the total length of the array data as a qword,
    // followed by the array data itself.
    append_q(*out, 0x1F0);
    append_q(*out, buf.size());
    append_b(*out, buf);
  }
}
