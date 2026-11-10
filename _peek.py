import re
src = open("unmmp_lib/decoder.py", encoding="utf-8").read().splitlines()
for i, line in enumerate(src, 1):
    if line.startswith("def decode"):
        for j in range(i-1, min(i+45, len(src))):
            print("%4d: %s" % (j+1, src[j]))
        break
