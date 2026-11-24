import socket, os, struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
txn=os.urandom(12); s.sendto(struct.pack("!HHI",1,0,0x2112A442)+txn,("37.120.10.3",3478))
d,a=s.recvfrom(2048); t,l,c=struct.unpack("!HHI",d[:8]); print("reply type",hex(t),"len",l,"txn ok",d[8:20]==txn,"attr",d[20:].hex())
