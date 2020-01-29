CFLAGS += -I./include -I../common/include -O2 -Wall
LDFLAGS += -lm

OBJS = main.o work.o ../common/cJSON.o ../common/sock.o ../common/timer.o

SAY=echo "libinfp_svr.a"
EXEC=libinfp_svr.a

all: clean $(EXEC)

$(EXEC): $(OBJS)
	@$(SAY) "AR $@"
	@$(AR) -crs $@ $^

clean:
	@$(SAY) "CLEAN"
	@rm -f $(EXEC) $(OBJS)
	@rm -f *.o

%.o: %.c
	@$(SAY) "CC $@"
	@$(CC) -o $@ $(CFLAGS) -c $<
