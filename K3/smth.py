with open("text2.txt", "rb") as f:
    data = f.read()
    data = data.replace("\u2018".encode("utf-8"), b"'").replace("\u2019".encode("utf-8"), b"'")
with open("text2.txt", "wb") as f:
    f.write(data)