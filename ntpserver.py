import socket
import time
import threading
import select
import sys
import ntplib
if sys.version_info[0] == 2:
    import Queue as queue
else:
    import queue

taskQueue = queue.Queue()
stopFlag = False


class RecvThread(threading.Thread):
    def __init__(self, socket):
        threading.Thread.__init__(self)
        self.socket = socket

    def run(self):
        global taskQueue, stopFlag
        while True:
            if stopFlag:
                print("RecvThread Ended")
                break
            rlist, wlist, elist = select.select([self.socket], [], [], 1)
            if len(rlist) != 0:
                print("Received %d packets" % len(rlist))
                for tempSocket in rlist:
                    try:
                        data, addr = tempSocket.recvfrom(1024)
                        recvTimestamp = ntplib.system_to_ntp_time(time.time())
                        taskQueue.put((data, addr, recvTimestamp))
                    except socket.error as msg:
                        print(msg)


class WorkThread(threading.Thread):
    def __init__(self, socket):
        threading.Thread.__init__(self)
        self.socket = socket

    def run(self):
        global taskQueue, stopFlag
        while True:
            if stopFlag:
                print("WorkThread Ended")
                break
            try:
                data, addr, recvTimestamp = taskQueue.get(timeout=1)
                recvPacket = ntplib.NTPPacket()
                recvPacket.from_data(data)
                timeStamp_high = ntplib._to_int(recvPacket.tx_timestamp)
                timeStamp_low = ntplib._to_frac(recvPacket.tx_timestamp)
                sendPacket = ntplib.NTPPacket(version=3, mode=4)
                sendPacket.stratum = 2
                sendPacket.poll = 10
                '''
                sendPacket.precision = 0xfa
                sendPacket.root_delay = 0x0bfa
                sendPacket.root_dispersion = 0x0aa7
                sendPacket.ref_id = 0x808a8c2c
                '''
                sendPacket.ref_timestamp = recvTimestamp-5
                sendPacket.orig_timestamp = ntplib._to_time(timeStamp_high,
                                                            timeStamp_low)
                sendPacket.recv_timestamp = recvTimestamp
                sendPacket.tx_timestamp = ntplib.system_to_ntp_time(
                        time.time())
                socket.sendto(sendPacket.to_data(), addr)
                print("Sended to %s:%d" % (addr[0], addr[1]))
            except queue.Empty:
                continue


listenIp = "0.0.0.0"
listenPort = 123
socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind((listenIp, listenPort))
print("local socket: ", socket.getsockname())
recvThread = RecvThread(socket)
recvThread.start()
workThread = WorkThread(socket)
workThread.start()

while True:
    try:
        time.sleep(0.5)
    except KeyboardInterrupt:
        print("Exiting...")
        stopFlag = True
        recvThread.join()
        workThread.join()
        # socket.close()
        print("Exited")
        break
