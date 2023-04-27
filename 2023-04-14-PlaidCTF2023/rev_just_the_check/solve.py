import string
from subprocess import check_output
import subprocess

FLAG_LEN = 16
recovered = [None] * FLAG_LEN

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

for i in range(FLAG_LEN):
    stats = {}
    for c in string.printable:
        word = ''.join(map(lambda c: '?' if c is None else c, recovered))
        word = word.replace('?', c)
        stats[c] = get_instr_cnt(word)

    instr_sort = sorted(stats.items(), key=lambda t: t[1], reverse=True)
    best_letter, instr_cnt = instr_sort[0]

    # now find the position
    stats = {}
    for pos in range(FLAG_LEN):
        word = list(map(lambda c: '?' if c is None else c, recovered))
        word[pos] = best_letter
        word = ''.join(word)
        stats[pos] = get_instr_cnt(word)

    instr_sort = sorted(stats.items(), key=lambda t: t[1], reverse=True)
    best_pos, instr_cnt = instr_sort[0]
    recovered[best_pos] = best_letter
    word = ''.join(map(lambda c: '?' if c is None else c, recovered))
    print(word)

# wat3rT1ghT-blAz3
