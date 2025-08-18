with open('binary.txt', 'r') as f:
    instructions = f.readlines()

component = []

for i in instructions:
    if 'r0' in i and 'flag' in i:
        flag_1 = i[i.find('flag'):]
        component.append(flag_1.strip())
    if 'r1' in i and 'flag' in i:
        flag_2 = i[i.find('flag'):]
        component.append(flag_2.strip())
    if 'r0' in i and 'r1' in i:
        op1 = i.split()[-3]
        if op1 == 'xor':
            op1 = '^'
        elif op1 == 'add':
            op1 = '+'
        elif op1 == 'sub':
            op1 = '-'
        elif op1 == 'mul':
            op1 = '*'
        elif op1 == 'div':
            op1 = '/'
        elif op1 == 'mod':
            op1 = '%'
        component.append(op1.strip())
    if 'r2' in i and 'flag' in i:
        flag_3 = i[i.find('flag'):]
        component.append(flag_3.strip())
    if 'r0' in i and 'r2' in i:
        op2 = i.split()[-3]
        if op2 == 'xor':
            op2 = '^'
        elif op2 == 'add':
            op2 = '+'
        elif op2 == 'sub':
            op2 = '-'
        elif op2 == 'mul':
            op2 = '*'
        elif op2 == 'div':
            op2 = '/'
        elif op2 == 'mod':
            op2 = '%'
        component.append(op2.strip())
    if 'r3' in i and 'mov_imm' in i:
        res = i.split()[-1]
        component.append(res.strip())
        component.append('==')
        component.append('|')

def postfix_to_infix(tokens):
    stack = []
    # Các toán tử 2 ngôi
    binary_ops = {"+", "-", "*", "/", "^", "==", "!=", "<", ">", "<=", ">="}

    for token in tokens:
        if token in binary_ops:
            b = stack.pop()
            a = stack.pop()
            # thêm ngoặc cho rõ ràng
            stack.append(f"({a} {token} {b})")
        else:
            stack.append(token)
    return stack[0]

def convert_all(expressions):
    results = []
    current = []
    for token in expressions:
        if token == '|':  # phân tách biểu thức
            if current:
                results.append(postfix_to_infix(current))
                current = []
        else:
            current.append(token)
    if current:  # xử lý biểu thức cuối cùng
        results.append(postfix_to_infix(current))
    return results


for expr in convert_all(component):
    print('solver.add' + expr)
