
content = ""
with open("./exp.wasm","r") as fd:
    content = fd.read()

result = []
for i in content:
    result.append(ord(i))

print(result)