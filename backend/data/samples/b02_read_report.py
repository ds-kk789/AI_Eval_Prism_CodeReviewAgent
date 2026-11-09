def read_report(path):
    f = open(path)
    try:
        data = f.read()
    except:
        data = ""
    return data
