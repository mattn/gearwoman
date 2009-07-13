import os

env = Environment(ENV = {'PATH' : os.environ['PATH']})
env.ParseConfig("pkg-config gthread-2.0 --cflags --libs")
env.ParseConfig("pkg-config glib-2.0 --cflags --libs")
env.Program("gearmand", ["gearmand.c", "client.c", "job.c", "memblock.c", "util.c"], LIBS=["libevent", "glib-2.0", "gthread-2.0"])
