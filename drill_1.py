

def build_sandbox():
    file_name = "shadow_test.xml"
    with open("shadow_test.xml", "w") as f:
        f.write("<pfsense> test </pfsense>")

    return file_name

print(build_sandbox())