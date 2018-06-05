# dtxmsg

This is an IDA plugin that helped me reverse-engineer the DTXConnectionServices framework.

DTXConnectionServices is a library developed by Apple that facilitates interoperability
between iOS and OSX. It is notably used to transmit debugging statistics between the
iOS Instruments Server and Xcode.

The goal of this plugin is to help uncover how this communication mechanism works.

## Overview

dtxmsg detects critical pieces of logic in the DTXConnectionServices binary, sets breakpoints
at these locations, then hooks into IDA's debugger events and dumps the packets of information
transmitted between iOS and OSX.

Apple calls these packets "DTXMessages", hence the name of the plugin.

The plugin can also decode these messages and print the contents to a file in plain text.

## Prerequisites

In order to build and run dtxmsg, you must have access to the following:

  * IDA 7.1 or later, with decompiler support
  * IDA SDK 7.1 or later
  * hexrays\_sdk 7.1 or later
  * a jailbroken iOS device
  * a patched iOS [debugserver][1]
  * OSX with Xcode installed

This plugin was tested with iOS 9.3.1 and OSX 10.13.

Theoretically, the plugin can work with any iOS between 9.3-11.4, and any OSX between 10.10-10.13,
but these have not been explicitly tested.

## Build

To build dtxmsg, run the following commands:

```
$ export IDA_INSTALL_DIR=/path/to/your/IDA/installation
$ export IDASDK=/path/to/your/idasdk
$ cd $IDASDK/plugins
$ git clone https://github.com/troybowman/dtxmsg
$ cd dtxmsg
$ __EA64__=1 $IDASDK/bin/idamake.pl
```

## Run

To demonstrate the dtxmsg plugin in action, we will use it to log all the messages
received by the iOS Instruments Server when Xcode queries the process list
("Debug>Attach to Process" in the Xcode IDE).

1. It may be a good idea brush up on [how IDA's iOS Debugger Works][2]

2. Launch Xcode, and open an iOS project (make sure your device is selected as the build target)

3. download [ios_deploy][3] and run the following commands:
   ```
   $ ios_deploy -d <device id> usbproxy -r 22 -l 2222 &
   $ ios_deploy -d <device id> usbproxy -r 1234 -l 4321 &
   $ ssh -p 2222 root@localhost
   Connected to port 22 on device
   iPhone-6-jailbroken:~ root# ps aux | grep DTServiceHub
   root           11451   0.0  0.5   712144  10960   ??  Ss   Tue04PM   0:02.91 /Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub
   iPhone-6-jailbroken:~ root# ./debugserver *:1234
   debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-340.3.124 for arm64.
   Listening to port 1234 for a connection from *...
   ```
   Note the PID of the application DTServiceHub (11451). This is the Instruments Server process.
   If this process is not running, go to your Xcode window and select menu Debug>Attach to process.
   This should launch the Instruments server.

4. Be sure to set the following options in $IDA\_INSTALL\_DIR/ida.app/Contents/MacOS/cfg/dbg\_ios.cfg:
   ```
   AUTOLAUNCH = NO
   SYMBOL_PATH = "~/Library/Developer/Xcode/iOS DeviceSupport/<your device's iOS version>/Symbols"
   DEVICE_ID = "<your device's ID>"
   ```

5. Run the plugin in IDA:
   ```
   $ hdiutil mount /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/<your device's iOS version>/DeveloperDiskImage.dmg
   $ mkdir /tmp/dtxmsg
   $ $IDA_INSTALL_DIR/ida.app/Contents/MacOS/ida64 -Odtxmsg:v:11451:/tmp/dtxmsg -o/tmp/dtxmsg/DTXConnectionServices.i64 -L/tmp/dtxmsg/ida.log /Volumes/DeveloperDiskImage/Library/PrivateFrameworks/DTXConnectionServices.framework/DTXConnectionServices
   ```
   Note the plugin options: -Odtxmsg:v:11451:/tmp/dtxmsg
   * v = enable verbose mode: deserialize the captured messages and print the results to a file in plain text
   * 11451 = PID of process to attach to
   * /tmp/dtxmsg = directory where messages will be logged

   If the plugin loads successfully, it will automatically attach to the given PID and allow the process to run idle,
   waiting for incoming messages.

6. Go back to Xcode, and select menu Debug>Attach to Process. If dtxmsg was able to intercept communications,
   it will print some messages to the console:
   ```
   DTXMSG: message: /tmp/dtxmsg/dtxmsg_1_0.bin
   DTXMSG: message: /tmp/dtxmsg/dtxmsg_2_0.bin
   DTXMSG: message: /tmp/dtxmsg/dtxmsg_3_0.bin
   ...
   ```
   There will also be .txt files that contain the decoded data.

## dtxmsg\_client

This project also includes a standalone application that can communicate with the iOS Instruments
Server independently. It serves as an example of how to "speak the language"
of the DTXConnectionServices framework.

To run it, see:

```
$ $IDASDK/bin/dtxmsg_client -h
```

[1]: http://iphonedevwiki.net/index.php/Debugserver
[2]: https://www.hex-rays.com/products/ida/support/tutorials/ios_debugger_tutorial.pdf
[3]: https://www.hex-rays.com/products/ida/support/ida/ios_deploy.zip
