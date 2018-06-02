
# currently this plugin can only be built with __EA64__=1.
# this is for two reasons:
#   1. the DTXConnectionServices library is only available in 64-bit for both OSX and iOS
#      (at least for all versions I've seen), so for now the plugin assumes 64-bit
#   2. the sample dtxmsg_client app must link against pro.a/dumb.o, which are only available
#      for __EA64__ builds
ifdef __EA64__

PROC = dtxmsg
O1 = dtxmsg_common
ADDITIONAL_GOALS += dtxmsg_client

include ../plugin.mak

STDLIBS += -lobjc -framework Foundation -framework CoreFoundation

ifneq ($(IDA71),)
POSTACTION = cp $@ $(IDA71)/ida/ida.app/Contents/MacOS/plugins
endif

$(F)dtxmsg_common$(O): CFLAGS += -x objective-c++

.PHONY: dtxmsg_client
dtxmsg_client: $(R)dtxmsg_client
$(R)dtxmsg_client: $(F)dtxmsg_common$(O) $(F)dtxmsg_client$(O)
	$(call link_dumb,$@ $^)

# MAKEDEP dependency list ------------------
$(F)dtxmsg$(O)  : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
	          $(I)dbg.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h             \
	          $(I)funcs.hpp $(I)gdl.hpp $(I)hexrays.hpp $(I)ida.hpp     \
	          $(I)idd.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)moves.hpp  \
	          $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)pro.h       \
	          $(I)range.hpp $(I)segment.hpp $(I)struct.hpp              \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp dtxmsg.cpp        \
	          dtxmsg.h dtxmsg_common.h
$(F)dtxmsg_client$(O): $(I)err.h $(I)fpro.h $(I)llong.hpp $(I)pro.h         \
	          dtxmsg_client.cpp dtxmsg_client.h dtxmsg_common.h
$(F)dtxmsg_common$(O): $(I)llong.hpp $(I)pro.h dtxmsg_common.cpp            \
	          dtxmsg_common.h

else # __EA64__

ADDITIONAL_GOALS = skip
skip:
	@echo "warning: dtxmsg plugin cannot be built for EA32. Please build with __EA64__=1."

endif
