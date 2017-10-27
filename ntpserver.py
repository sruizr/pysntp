import datetime
import socket
import struct
import time
import threading
import select
import sys
import logging
import logging.handlers
import argparse
import netifaces
import queue

logger = logging.getLogger()
taskQueue = queue.Queue()
packetQueue = queue.Queue()
stopFlag = False

def get_network_addresses():
    ifaces = netifaces.interfaces()
    bcast_addresses = []
    interface_addresses = []
    for iface in ifaces:
        details = netifaces.ifaddresses(iface)
        for k, vals in details.items():
            if k == netifaces.AF_INET:
                for addr in vals:
                    bcast_addresses.append(addr['broadcast'])
                    interface_addresses.append(addr['addr'])
    return interface_addresses, bcast_addresses



def setup_logger(logger, level=logging.INFO, file_path=None):
    logger.setLevel(level)
    console_formatter = logging.Formatter(
            fmt='%(asctime)s - %(levelname)s - %(message)s')
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    if file_path:
        #also add a file handler
        file_formatter = logging.Formatter(
            fmt='%(asctime)s - %(levelname)s - %(funcName)s - %(lineno)d - %(message)s')
        file_handler = logging.handlers.TimedRotatingFileHandler(
                filename=file_path,
                when='D',
                backupCount=7 #allow for a week of logs
                )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)



def system_to_ntp_time(timestamp):
    """Convert a system time to a NTP time.

    Parameters:
    timestamp -- timestamp in system time

    Returns:
    corresponding NTP time
    """
    return timestamp + NTP.NTP_DELTA

def _to_int(timestamp):
    """Return the integral part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp

    Retuns:
    integral part
    """
    return int(timestamp)

def _to_frac(timestamp, n=32):
    """Return the fractional part of a timestamp.

    Parameters:
    timestamp -- NTP timestamp
    n         -- number of bits of the fractional part

    Retuns:
    fractional part
    """
    return int(abs(timestamp - _to_int(timestamp)) * 2**n)

def _to_time(integ, frac, n=32):
    """Return a timestamp from an integral and fractional part.

    Parameters:
    integ -- integral part
    frac  -- fractional part
    n     -- number of bits of the fractional part

    Retuns:
    timestamp
    """
    return integ + float(frac)/2**n	
		


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class NTP:
    """Helper class defining constants."""

    _SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
    """system epoch"""
    _NTP_EPOCH = datetime.date(1900, 1, 1)
    """NTP epoch"""
    NTP_DELTA = (_SYSTEM_EPOCH - _NTP_EPOCH).days * 24 * 3600
    """delta between system and NTP time"""

    REF_ID_TABLE = {
            'DNC': "DNC routing protocol",
            'NIST': "NIST public modem",
            'TSP': "TSP time protocol",
            'DTS': "Digital Time Service",
            'ATOM': "Atomic clock (calibrated)",
            'VLF': "VLF radio (OMEGA, etc)",
            'callsign': "Generic radio",
            'LORC': "LORAN-C radionavidation",
            'GOES': "GOES UHF environment satellite",
            'GPS': "GPS UHF satellite positioning",
    }
    """reference identifier table"""

    STRATUM_TABLE = {
        0: "unspecified",
        1: "primary reference",
    }
    """stratum table"""

    MODE_TABLE = {
        0: "unspecified",
        1: "symmetric active",
        2: "symmetric passive",
        3: "client",
        4: "server",
        5: "broadcast",
        6: "reserved for NTP control messages",
        7: "reserved for private use",
    }
    """mode table"""

    LEAP_TABLE = {
        0: "no warning",
        1: "last minute has 61 seconds",
        2: "last minute has 59 seconds",
        3: "alarm condition (clock not synchronized)",
    }
    """leap indicator table"""

class NTPPacket:
    """NTP packet class.

    This represents an NTP packet.
    """
    
    _PACKET_FORMAT = "!B B B b 11I"
    """packet format to pack/unpack"""

    def __init__(self, version=4, mode=3, tx_timestamp=0):
        """Constructor.

        Parameters:
        version      -- NTP version
        mode         -- packet mode (client, server)
        tx_timestamp -- packet transmit timestamp
        """
        self.leap = 0
        """leap second indicator"""
        self.version = version
        """version"""
        self.mode = mode
        """mode"""
        self.stratum = 1
        """stratum"""
        self.poll = 10
        """poll interval"""
        self.precision = -10
        """precision"""
        self.root_delay = 0
        """root delay"""
        self.root_dispersion = 0
        """root dispersion"""
        self.ref_id = 0
        """reference clock identifier"""
        self.ref_timestamp = 0
        """reference timestamp"""
        self.orig_timestamp = 0
        self.orig_timestamp_high = 0
        self.orig_timestamp_low = 0
        """originate timestamp"""
        self.recv_timestamp = 0
        """receive timestamp"""
        self.tx_timestamp = tx_timestamp
        self.tx_timestamp_high = 0
        self.tx_timestamp_low = 0
        """tansmit timestamp"""

    def __str__(self):
        '''create a nice string representation of the packet data modelled off
        of format described in RFC2030:

                     1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Root Delay                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Root Dispersion                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                     Reference Identifier                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                   Reference Timestamp (64)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                   Originate Timestamp (64)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                    Receive Timestamp (64)                     |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                    Transmit Timestamp (64)                    |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                 Key Identifier (optional) (32)                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                                                               |
      |                 Message Digest (optional) (128)               |
      |                                                               |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+'''
        packet_str = f'''\
LI|VN|Mode|Stratum|Poll|Precision: {self.leap}|{self.version}|{self.mode}|{self.stratum}|{self.poll}|{self.precision}
Root Delay                       : {self.root_delay}
Root Dispersion                  : {self.root_dispersion}
Reference Identifier             : {self.ref_id}
Reference Timestamp (64)         : {self.ref_timestamp}
Originate Timestamp (64)         : {self.orig_timestamp}
Receive Timestamp (64)           : {self.recv_timestamp}
Transmit Timestamp (64)          : {self.tx_timestamp}'''
        return packet_str
    def to_data(self):
        """Convert this NTPPacket to a buffer that can be sent over a socket.

        Returns:
        buffer representing this packet

        Raises:
        NTPException -- in case of invalid field
        """
        try:
            packed = struct.pack(NTPPacket._PACKET_FORMAT,
                (self.leap << 6 | self.version << 3 | self.mode),
                self.stratum,
                self.poll,
                self.precision,
                _to_int(self.root_delay) << 16 | _to_frac(self.root_delay, 16),
                _to_int(self.root_dispersion) << 16 |
                _to_frac(self.root_dispersion, 16),
                self.ref_id,
                _to_int(self.ref_timestamp),
                _to_frac(self.ref_timestamp),
                #Change by lichen, avoid loss of precision
                self.orig_timestamp_high,
                self.orig_timestamp_low,
                _to_int(self.recv_timestamp),
                _to_frac(self.recv_timestamp),
                _to_int(self.tx_timestamp),
                _to_frac(self.tx_timestamp))
        except struct.error:
            raise NTPException("Invalid NTP packet fields.")
        return packed

    def from_data(self, data):
        """Populate this instance from a NTP packet payload received from
        the network.

        Parameters:
        data -- buffer payload

        Raises:
        NTPException -- in case of invalid packet format
        """
        try:
            unpacked = struct.unpack(NTPPacket._PACKET_FORMAT,
                    data[0:struct.calcsize(NTPPacket._PACKET_FORMAT)])
        except struct.error:
            raise NTPException("Invalid NTP packet.")

        self.leap = unpacked[0] >> 6 & 0x3
        self.version = unpacked[0] >> 3 & 0x7
        self.mode = unpacked[0] & 0x7
        self.stratum = unpacked[1]
        self.poll = unpacked[2]
        self.precision = unpacked[3]
        self.root_delay = float(unpacked[4])/2**16
        self.root_dispersion = float(unpacked[5])/2**16
        self.ref_id = unpacked[6]
        self.ref_timestamp = _to_time(unpacked[7], unpacked[8])
        self.orig_timestamp = _to_time(unpacked[9], unpacked[10])
        self.orig_timestamp_high = unpacked[9]
        self.orig_timestamp_low = unpacked[10]
        self.recv_timestamp = _to_time(unpacked[11], unpacked[12])
        self.tx_timestamp = _to_time(unpacked[13], unpacked[14])
        self.tx_timestamp_high = unpacked[13]
        self.tx_timestamp_low = unpacked[14]

    def GetTxTimeStamp(self):
        return (self.tx_timestamp_high,self.tx_timestamp_low)

    def SetOriginTimeStamp(self,high,low):
        self.orig_timestamp_high = high
        self.orig_timestamp_low = low

class workerThread(threading.Thread):
    def __init__(self,socket, broadcast_interval, port):
        threading.Thread.__init__(self)
        self.socket = socket
        self.broadcast_interval = broadcast_interval
        logging.debug("Broadcast interval set to: %d", broadcast_interval)
        self.port = port

        if broadcast_interval:
            self.interface_addresses, self.broadcast_addresses = get_network_addresses()
            logger.debug("broadcast addresses: %s", self.broadcast_addresses)

    def run(self):
        global taskQueue,stopFlag
        last_broadcast_time = time.time()
        while True:
            if stopFlag == True:
                logger.info("workerThread Ended")
                break
            rlist,wlist,elist = select.select([self.socket],[self.socket],[],1);
            if len(rlist) != 0:
                for tempSocket in rlist:
                    try:
                        data,addr = tempSocket.recvfrom(1024)
                        logger.info("Received packet from %s", addr[0])
                        if addr[0] in self.interface_addresses:
                            logger.debug("Ignoring broadcast from self")
                            continue
                    except socket.error as msg:
                        logging.critical(msg);
                    recvTimestamp = recvTimestamp = system_to_ntp_time(time.time())
                    self.send_response(data,addr,recvTimestamp)
            if len(wlist) != 0:
                current_time = time.time()
                if self.broadcast_interval and current_time - last_broadcast_time > self.broadcast_interval:
                    last_broadcast_time = current_time
                    for tempSocket in wlist:
                        self.send_broadcast(tempSocket)
            time.sleep(1)

    def send_broadcast(self, socket):
        broadcastPacket = NTPPacket()
        broadcastPacket = NTPPacket(tx_timestamp = system_to_ntp_time(time.time()))
        broadcastPacket.poll = 10
        broadcastPacket.mode = 5
        broadcastPacket.ref_timestamp = broadcastPacket.tx_timestamp-5
        logger.debug("Broadcast Packet details: \n%s", broadcastPacket)
        for bcast_address in self.broadcast_addresses:
            self.socket.sendto(broadcastPacket.to_data(),(bcast_address, self.port))
            logger.info("Sending broadcast packet to %s:%d", bcast_address,self.port)


    def send_response(self, data, addr, recvTimestamp):
        recvPacket = NTPPacket()
        recvPacket.from_data(data)
        logger.debug("Received Packet details: \n%s", recvPacket)
        timeStamp_high,timeStamp_low = recvPacket.GetTxTimeStamp()
        sendPacket = NTPPacket(version=3,mode=4)
        '''
        sendPacket.precision = 0xfa
        sendPacket.ref_id = 0x808a8c2c
        '''
        sendPacket.ref_timestamp = recvTimestamp-5
        sendPacket.recv_timestamp = recvTimestamp
        sendPacket.tx_timestamp = system_to_ntp_time(time.time())
        self.socket.sendto(sendPacket.to_data(),addr)
        logger.info("Sending response packet to %s:%d", addr[0],addr[1])
        logger.debug("Sent Packet details: \n%s", sendPacket)


def get_parser():
    parser = argparse.ArgumentParser(description='SNTP server')
    parser.add_argument('-p', '--port', type=int, default=123,
        help='The port to listen on, defaults to 123')
    parser.add_argument('-a', '--address', default='0.0.0.0',
        help='The address to listen on, defaults to 0.0.0.0 (all interfaces)')
    parser.add_argument('-v', action='store_true', help='use verbose logging')
    parser.add_argument('-l', nargs=1, metavar='log_file_path',
            help='additionally log to a file')
    parser.add_argument('-b', type=int, default=0,
            help='broadcast_interval in secs, defaults to 0 (no broadcast)')
    return parser.parse_args()

if __name__ == '__main__':

    p = get_parser()

    log_file = None
    if p.l:
        log_file = p.l[0]
    if p.v:
        setup_logger(logger, level=logging.DEBUG, file_path=log_file)
    else:
        setup_logger(logger, level=logging.INFO, file_path=log_file)

    socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    socket.bind((p.address,p.port))
    logger.info("local socket: %s", socket.getsockname());
    worker_thread = workerThread(socket, p.b, p.port)
    worker_thread.start()

    while True:
        try:
            time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("Exiting...")
            stopFlag = True
            worker_thread.join()
            logger.info("Exited")
            break

