DEBUG := YES

CC = gcc
LD = gcc -o
AR = ar
LDFLAGS = `pkg-config --libs gthread-2.0` -levent
CFLAGS = -Wall

# # Debug
# #LDFLAGS += -lefence
# CPPFLAGS += -g `pkg-config --cflags gthread-2.0` -DDEBUG
# OPTIMIZATIONS =

# Production (NDEBUG = NO DEBUG / remove asserts)
CPPFLAGS += -Wall `pkg-config --cflags glib-2.0` -DNDEBUG
OPTIMIZATIONS = -O2 -funroll-loops -finline-functions

BIN =   gearmand

OBJ =   gearmand.o      \
        client.o        \
        job.o           \
        util.o          \
        memblock.o

all: $(BIN)

.c.o:
	$(CC) $(CPPFLAGS) $(OPTIMIZATIONS) -c $<

$(BIN): $(OBJ)
	$(LD) $(BIN) $(OBJ) $(LDFLAGS) 

clean : 
	rm -f *.o $(BIN) core *.core
