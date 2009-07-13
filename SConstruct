import os

env = Environment(ENV = {'PATH' : os.environ['PATH']}, CCFLAGS="-Wall ")
env.ParseConfig("pkg-config gthread-2.0 --cflags --libs")
env.ParseConfig("pkg-config glib-2.0 --cflags --libs")

debug = ARGUMENTS.get('debug', 0)
if int(debug):
    env.Append(CCFLAGS = '-g -DDEBUG ')
else:
    env.Append(CCFLAGS = '-DNDEBUG -O2 -funroll-loops -finline-functions ')

gearmand = env.Program("gearmand", ["gearmand.c", "client.c", "job.c", "memblock.c", "util.c"], LIBS=["libevent", "glib-2.0", "gthread-2.0"])
