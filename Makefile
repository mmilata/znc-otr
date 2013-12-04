THISMOD=otr.so

all: $(THISMOD)

%.so: %.cpp
	LIBS="-lotr" znc-buildmod $<

install: $(THISMOD)
	cp $(THISMOD) ~/.znc/modules/$(THISMOD)

clean:
	-rm -f $(THISMOD)
