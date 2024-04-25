def read_block(f):
    block = []
    line = f.readline()
    while line != '' and line != '\n':
        block.append(line[:-1])
        line = f.readline()
    return block

def parse_block(block):
    if block[0] == 'DUMPING REGISTERS':
        regs = {}
        for line in block[1:]:
            reg_value_iter = iter(filter(lambda x: x != '', line.split(' ')))
            for reg_name in reg_value_iter:
                regs[reg_name] = int(next(reg_value_iter), 16)
        return regs
    elif block[0] == 'DUMPING MEMORY':
        addr_begin, addr_end = list(map(lambda x: int(x, 16), block[1][5:].split(' - '))) # one liner, let's gooo
        path = block[2][5:]
        offset = int(block[3][5:], 16)
        perms = block[4][5:]
        mem = map(lambda x: int(x, 16), block[5:])
        return {
            'addr_begin' : addr_begin,
            'addr_end'   : addr_end,
            'length'     : addr_end - addr_begin,
            'path'       : path,
            'offset'     : offset,
            'perms'      : perms,
            'mem'        : mem
        }
    else:
        assert False

def read_dump(filename, cb):
    with open(filename) as f:
        block = read_block(f)
        while block != []:
            cb(parse_block(block))
            block = read_block(f)

if __name__ == '__main__':
    import sys

    filename = 'mem.dump'
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    read_dump(filename, print)
