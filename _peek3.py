src = open("unmmp_lib/semantic.py", encoding="utf-8").read().splitlines()
for i in range(300, 340):
    print("%4d: %s" % (i+1, src[i]))
