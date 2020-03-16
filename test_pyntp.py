from ntpserver import NTPServer
import ntplib
import time
from unittest.mock import Mock


def test_ntp_server():
    what_time_is_it = Mock()
    what_time_is_it.return_value = 1584358705.860036

    server = NTPServer('127.0.0.1', 1234, what_time_is_it)
    server.start()

    client = ntplib.NTPClient()
    response = client.request('127.0.0.1', port=1234, version=3)
    assert response.tx_time == what_time_is_it()
