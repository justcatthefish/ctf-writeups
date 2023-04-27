import string
from subprocess import check_output
import subprocess

def get_instr_cnt(word):
    try:
        output = check_output(f'LC_ALL=C perf stat -e instructions:u ./check "{word}"', shell=True, stderr=subprocess.STDOUT)
    except Exception as e:
        o = e.output.decode()
        try:
            instr = next(filter(lambda line: 'instructions:u' in line, o.splitlines())).split('instructions')[0].strip().replace(' ', '')
            instr = int(instr)
            # print(instr, word.encode())
            return instr
        except Exception as e2: pass
    
    return 0

stats = {}
for c in string.printable:
    stats[c] = get_instr_cnt('T' + c * 16)

instr_sort = sorted(stats.items(), key=lambda t: t[1], reverse=True)
print(instr_sort)
