import re

with open('/usr/include/x86_64-linux-gnu/asm/unistd_64.h') as f:
    content = f.read()

pairs = re.findall(r'#define __NR_(\S+)\s+(\d+)', content)
pairs = [(name, int(num)) for name, num in pairs]
pairs.sort(key=lambda p: p[1])

print("// Code generated from /usr/include/x86_64-linux-gnu/asm/unistd_64.h — DO NOT EDIT.")
print("// Regenerate with scripts/gen_syscall_table.py if the kernel syscall table changes.")
print("//go:build linux")
print()
print("package ebpf")
print()
print("// x86_64SyscallNames maps syscall numbers to their canonical names.")
print("var x86_64SyscallNames = map[int64]string{")
for name, num in pairs:
    print(f'\t{num}: "{name}",')
print("}")
print()
print("// syscallName resolves a syscall number to its name, or a numeric")
print('// fallback ("sys_<n>") for unknown/architecture-specific numbers.')
print("func syscallName(nr int64) string {")
print("\tif name, ok := x86_64SyscallNames[nr]; ok {")
print("\t\treturn name")
print("\t}")
print('\treturn fmt.Sprintf("sys_%d", nr)')
print("}")
