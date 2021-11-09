import frida

# print host machine processes
dev = frida.get_device('local')
print(dev.enumerate_processes())
