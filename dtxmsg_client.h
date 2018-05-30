#ifndef DTXMSG_CLIENT_H
#define DTXMSG_CLIENT_H

#include "dtxmsg_common.h"
#include <fpro.h>
#include <mach/error.h>

// reverse-engineered types from MobileDevice.framework
#define kAMDSuccess ERR_SUCCESS

// opaque structures
struct am_device;
struct am_device_notification;
struct am_device_service_connection;

#define ADNCI_MSG_CONNECTED    1
#define ADNCI_MSG_DISCONNECTED 2
#define ADNCI_MSG_UNKNOWN      3

// callback info for AMDeviceNotificationSubscribe()
struct am_device_notification_callback_info
{
  am_device *dev; // device handle
  uint32 code;    // one of ADNCI_MSG_...
};
typedef void am_device_notification_callback_t(am_device_notification_callback_info *cbi, void *arg);

#endif // DTXMSG_CLIENT_H
