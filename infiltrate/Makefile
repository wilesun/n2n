OBJS = server client
OBJS-CLEAN = $(foreach n, $(OBJS), $(n)-clean)

.PHONY: $(OBJS)
all: $(OBJS)

$(OBJS):
	@echo "Make $@"
	@$(MAKE) -C $@

%-clean:
	$(MAKE) -C $* clean

clean: $(OBJS-CLEAN)

%.o: %.c
	@echo "CC $@"
	@$(CC) -o $@ $(CFLAGS) -c $<
