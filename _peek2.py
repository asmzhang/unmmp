import re
src = open("unmmp_lib/semantic.py", encoding="utf-8").read().splitlines()
for i in range(270, 300):
    print("%4d: %s" % (i+1, src[i]))
print("...")
for i in range(415, 431):
    print("%4d: %s" % (i+1, src[i]))
