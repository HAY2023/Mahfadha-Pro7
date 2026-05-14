"""
ONVIF Discovery Module for CamHunter v2.0
"""

import socket
import logging
import uuid

logger = logging.getLogger("camhunter.onvif")

class ONVIFScanner:
    def __init__(self, cfg: dict):
        self.cfg = cfg

    def discover(self) -> list:
        """
        Sends a WS-Discovery probe to find ONVIF devices.
        """
        devices = []
        msg = f"""
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            <s:Header>
                <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/08/discovery/Probe</a:Action>
                <a:MessageID>uuid:{uuid.uuid4()}</a:MessageID>
                <a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2004:08:discovery</a:To>
            </s:Header>
            <s:Body>
                <Probe xmlns="http://schemas.xmlsoap-org:ws:2004/08/discovery">
                    <Types>dn:NetworkVideoTransmitter</Types>
                </Probe>
            </s:Body>
        </s:Envelope>
        """
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(msg.encode(), ('239.255.255.250', 3702))
            
            while True:
                data, addr = sock.recvfrom(65507)
                devices.append(addr[0])
        except socket.timeout:
            pass
        except Exception as e:
            logger.error(f"ONVIF error: {e}")
            
        return list(set(devices))
