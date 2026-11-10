p = 'unmmp_lib/recover.py'
s = open(p, encoding='utf-8').read()
s = s.replace("                        self.resolve(m['resolver'], 0, ins[pc+1], name[0] == 's')",
              "                        self.resolve(res, 0, ins[pc+1], name[0] == 's')")
s = s.replace("                        self.resolve(m['resolver'], 1, ins[pc+1], name.startswith('invoke-static'))",
              "                        self.resolve(res, 1, ins[pc+1], name.startswith('invoke-static'))")
s = s.replace("                        self.resolve(m['resolver'], 5, idx)",
              "                        self.resolve(res, 5, idx)")
s = s.replace("                        self.resolve(m['resolver'], 2, ins[pc+1])",
              "                        self.resolve(res, 2, ins[pc+1])")
s = s.replace("                        self.resolve(m['resolver'], 2, idx)",
              "                        self.resolve(res, 2, idx)")
open(p, 'w', encoding='utf-8').write(s)
print(s.count("m['resolver']"), 'remaining direct uses in resolve_references region')
