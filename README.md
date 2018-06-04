# dtxmsg

This is an IDA plugin that helped me reverse-engineer the DTXConnectionServices framework.

## Overview

DTXConnectionServices is a framework developed by Apple that facilitates interoperability
between iOS and OSX. It is notably used to transmit debugging statistics between the
iOS Instruments Server and Xcode.

The goal of this plugin is to help uncover how this communication mechanism works,
in order to develop applications capable of communicating with the iOS Instruments Server
without the assistance of Xcode.

## What does it do?

dtxmsg detects critical pieces of logic in the DTXConnectionServices binary, sets breakpoints
at these locations, then hooks into IDA's debugger events and dumps the packets of information
transmitted between iOS and OSX.

Apple calls these packets "DTXMessages", hence the name of the plugin.

The plugin can also decode these messages and print the contents to a file in plain text.

## dtxmsg\_client

Also included in this project is a standalone application that is able to communicate
with the iOS instruments server independently. It serves as an example of how to
"speak the language" of the DTXConnectionServices framework.

dtxmsg\_client is able to perform some interesting tasks with a given iOS device:

  * fetch a list of running process
  * fetch a list of installed applications
  * launch a given application
  * kill a given process

# Prerequisites

In order to build and run dtxmsg, you must have access to the following:

  * IDA 7.0 or later, with decompiler support
  * IDA SDK 7.0 or later
  * hexrays\_sdk 7.0 or later
  * a jailbroken iOS device
  * a patched iOS debugserver. see http://iphonedevwiki.net/index.php/Debugserver
  * OSX with Xcode installed

This plugin was tested with iOS 9.3.1 and OSX 10.13.

Theoretically, the plugin can work with any iOS between 9.3-11.4, and any OSX between 10.10-10.13,
but these have not been explicitly tested.

# Build

To build dtxmsg, run the following commands:

```
$ export IDA_INSTALL_DIR=/path/to/your/IDA/installation
$ export IDASDK=/path/to/your/idasdk
$ cd $IDASDK/plugins
$ git clone https://github.com/troybowman/dtxmsg
$ cd dtxmsg
$ __EA64__=1 $IDASDK/bin/idamake.pl

```

<!--# Run-->

<!--dbg\_ios.cfg-->
