import sys
import socket
import time
import threading
import select
import sys
import ntplib
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


if sys.version_info[0] == 2:
    import Queue as queue
else:
    import queue


class RecvThread(threading.Thread):
    def __init__(self, sock, taskQueue, what_time_is_it=None):
        self.what_time_is_it = what_time_is_it if what_time_is_it else time.time
        threading.Thread.__init__(self)
        self.sock = sock
        self.taskQueue = taskQueue
        self.stop_flag = False

    def run(self):
        while not self.stop_flag:
            rlist, wlist, elist = select.select([self.sock], [], [], 1)
            if len(rlist) != 0:
                print("Received %d packets" % len(rlist))
                for tempSocket in rlist:
                    try:
                        data, addr = tempSocket.recvfrom(1024)
                        recvTimestamp = ntplib.system_to_ntp_time(
                            self.what_time_is_it())
                        self.taskQueue.put((data, addr, recvTimestamp))
                    except socket.error as msg:
                        print(msg)


class WorkThread(threading.Thread):
    def __init__(self, sock, taskQueue, what_time_is_it=None):
        threading.Thread.__init__(self)

        self.what_time_is_it = (what_time_is_it if what_time_is_it
                                else time.time)
        self.sock = sock
        self.taskQueue = taskQueue
        self.stop_flag = False

    def run(self):
        while not self.stop_flag:
            try:
                data, addr, recvTimestamp = self.taskQueue.get(timeout=1)
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
                        self.what_time_is_it())
                self.sock.sendto(sendPacket.to_data(), addr)
                print("Sent to %s:%d" % (addr[0], addr[1]))
            except queue.Empty:
                continue


class NTPServer:
    def __init__(self, ip='0.0.0.0', port=1123, what_time_is_it=None):
        "docstring"
        taskQueue = queue.Queue()

        self.ip = ip
        self.port = port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        logger.info('Opened socket on {}:{}'.format(ip, port))
        self.recvThread = RecvThread(sock, taskQueue, what_time_is_it)
        self.recvThread.daemon = True
        self.workThread = WorkThread(sock, taskQueue, what_time_is_it)
        self.workThread.daemon = True

    def start(self):
        self.workThread.start()
        self.recvThread.start()
        logger.info('NTPServer is started at {}:{}'.format(self.ip, self.port))

    def stop(self):
        self.workThread.stop_flag = True
        self.recvThread.stop_flag = True
        self.workThread.join()
        self.recvThread.join()
        logger.info('NTP server stopped!')


if __name__ == "__main__":
    args = []
    if len(sys.argv) == 3:
        args = (sys.argv[1], int(sys.argv[2]))

    server = NTPServer(*args)
    server.start()
    while True:
        try:
            time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("Exiting...")
            server.stop()
            break
