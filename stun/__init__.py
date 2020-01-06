import binascii
import logging
import random
import socket
from typing import Any, Dict, Optional, Tuple

__version__ = "0.2.0"

log = logging.getLogger("pystun")

STUN_SERVERS = (
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
    "stun.ekiga.net",
    "stun.ideasip.com",
    "stun.voiparound.com",
    "stun.voipbuster.com",
    "stun.voipstunt.com",
    "stun.voxgratia.org",
)

DEFAULTS = {"stun_port": 3478, "source_ip": "0.0.0.0", "source_port": 54320}

# stun attributes
MappedAddress = "0001"
ResponseAddress = "0002"
ChangeRequest = "0003"
SourceAddress = "0004"
ChangedAddress = "0005"
Username = "0006"
Password = "0007"
MessageIntegrity = "0008"
ErrorCode = "0009"
UnknownAttribute = "000A"
ReflectedFrom = "000B"
XorOnly = "0021"
XorMappedAddress = "8020"
ServerName = "8022"
SecondaryAddress = "8050"  # Non standard extension

# types for a stun message
BindRequestMsg = "0001"
BindResponseMsg = "0101"
BindErrorResponseMsg = "0111"
SharedSecretRequestMsg = "0002"
SharedSecretResponseMsg = "0102"
SharedSecretErrorResponseMsg = "0112"

dictAttrToVal = {
    "MappedAddress": MappedAddress,
    "ResponseAddress": ResponseAddress,
    "ChangeRequest": ChangeRequest,
    "SourceAddress": SourceAddress,
    "ChangedAddress": ChangedAddress,
    "Username": Username,
    "Password": Password,
    "MessageIntegrity": MessageIntegrity,
    "ErrorCode": ErrorCode,
    "UnknownAttribute": UnknownAttribute,
    "ReflectedFrom": ReflectedFrom,
    "XorOnly": XorOnly,
    "XorMappedAddress": XorMappedAddress,
    "ServerName": ServerName,
    "SecondaryAddress": SecondaryAddress,
}

dictMsgTypeToVal = {
    "BindRequestMsg": BindRequestMsg,
    "BindResponseMsg": BindResponseMsg,
    "BindErrorResponseMsg": BindErrorResponseMsg,
    "SharedSecretRequestMsg": SharedSecretRequestMsg,
    "SharedSecretResponseMsg": SharedSecretResponseMsg,
    "SharedSecretErrorResponseMsg": SharedSecretErrorResponseMsg,
}

dictValToMsgType = {}
for key, value in dictMsgTypeToVal.items():
    dictValToMsgType[value] = key

dictValToAttr = {}
for key, value in dictAttrToVal.items():
    dictValToAttr[value] = key

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restric NAT"
RestricPortNAT = "Restric Port NAT"
SymmetricNAT = "Symmetric NAT"
ChangedAddressError = "Meet an error, when do Test1 on Changed IP and Port"

FAMILY_TYPES = {1: "IPv4", 2: "IPv6"}


def gen_transaction_id() -> str:
    return "".join(random.choice("0123456789ABCDEF") for i in range(32))


def b2a_hex(buffer: bytes) -> str:
    return binascii.b2a_hex(buffer).decode("ascii")


def parse_address(buffer, offset):
    # Parse MAPPED-ADDRESS, RESPONSE-ADDRESSS, CHANGED-ADDRESS, SOURCE-ADDRESS
    # TODO(jlvillal): Support IPv6

    # The first 4 bytes are the Type (2) and Length (2)
    # The 5th byte is Reserved
    # The 6th byte is the Family: 0x01 = IPv4, 0x02 = IPv6
    # The remaining bytes are the IP address. 32 bits for IPv4 or 128 bits for
    # IPv6.
    # More info at: https://tools.ietf.org/html/rfc3489#section-11.2.1
    # And at: https://tools.ietf.org/html/rfc5389#section-15.1
    family = int(b2a_hex(buffer[offset + 5: offset + 6]), 16)
    log.debug("family: %s (%s)", family, FAMILY_TYPES.get(family))
    if family != 1:
        raise ValueError("Family other than IPv4 not supported. "
                         "Received family: {}".format(family))
    port = int(b2a_hex(buffer[offset + 6 : offset + 8]), 16)
    log.debug("port: %s", port)
    ip = ".".join(
        [
            str(int(b2a_hex(buffer[offset + 8 : offset + 9]), 16)),
            str(int(b2a_hex(buffer[offset + 9 : offset + 10]), 16)),
            str(int(b2a_hex(buffer[offset + 10 : offset + 11]), 16)),
            str(int(b2a_hex(buffer[offset + 11 : offset + 12]), 16)),
        ]
    )
    return (ip, port)


def stun_test(
    *,
    sock: socket.socket,
    host: str,
    port: int,
    source_ip: str,
    source_port: int,
    send_data: str = ""
) -> Dict[str, Any]:
    retVal: Dict[str, Any] = {
        "Resp": False,
        "ExternalIP": None,
        "ExternalPort": None,
        "SourceIP": None,
        "SourcePort": None,
        "ChangedIP": None,
        "ChangedPort": None,
    }
    str_len = "%#04d" % (len(send_data) / 2)
    log.debug("send_data: %s", (send_data))
    log.debug("str_len: %s", (str_len))
    transaction_id = gen_transaction_id()
    str_data = "".join([BindRequestMsg, str_len, transaction_id, send_data])
    log.debug("str_data: %s", (str_data))
    data = binascii.a2b_hex(str_data)
    recv_correct = False
    while not recv_correct:
        received = False
        count = 3
        while not received:
            log.debug("sendto: %s", (host, port))
            try:
                sock.sendto(data, (host, port))
            except socket.gaierror:
                log.debug("sendto gaierror: %s", (host, port))
                retVal["Resp"] = False
                return retVal
            try:
                buf, addr = sock.recvfrom(2048)
                log.debug("recvfrom: %s", addr)
                received = True
            except socket.timeout as exc:
                log.debug("recvfrom Exception: %s", exc)
                received = False
                if count > 0:
                    count -= 1
                else:
                    retVal["Resp"] = False
                    return retVal
            except Exception as exc:
                raise
                log.debug("recvfrom Exception: %s", exc)
        log.debug("buffer: %s", buf)
        msgtype = b2a_hex(buf[0:2])
        log.debug("msgtype: %s (%s)", msgtype, dictValToMsgType.get(msgtype))
        bind_resp_msg = (dictValToMsgType[msgtype] == "BindResponseMsg")
        tranid_match = (transaction_id == b2a_hex(buf[4:20]).upper())
        if bind_resp_msg and tranid_match:
            recv_correct = True
            retVal["Resp"] = True
            len_message = int(b2a_hex(buf[2:4]), 16)
            log.debug("len_message: %s", len_message)
            len_remain = len_message
            base = 20
            while len_remain:
                attr_type = b2a_hex(buf[base : (base + 2)])
                attr_len = int(b2a_hex(buf[(base + 2) : (base + 4)]), 16)
                log.debug("attr_type: %s (%s)", attr_type, dictValToAttr.get(attr_type))
                if attr_type == MappedAddress:
                    ip, port = parse_address(buf, base)
                    retVal["ExternalIP"] = ip
                    retVal["ExternalPort"] = port
                elif attr_type == SourceAddress:
                    ip, port = parse_address(buf, base)
                    retVal["SourceIP"] = ip
                    retVal["SourcePort"] = port
                elif attr_type == ChangedAddress:
                    ip, port = parse_address(buf, base)
                    retVal["ChangedIP"] = ip
                    retVal["ChangedPort"] = port
                else:
                    log.debug("Unhandled attribute: %s %s", attr_type,
                              dictValToAttr.get(attr_type))
                # if attr_type == ServerName:
                # serverName = buf[(base+4):(base+4+attr_len)]
                base = base + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)
    return retVal


def get_nat_type(
    *,
    sock: socket.socket,
    source_ip: str,
    source_port: int,
    stun_host: Optional[str] = None,
    stun_port: int = 3478
) -> Tuple[str, Dict[str, Any]]:
    port = stun_port
    log.debug("Do Test1")
    resp = False
    if stun_host:
        ret = stun_test(
            sock=sock,
            host=stun_host,
            port=port,
            source_ip=source_ip,
            source_port=source_port,
        )
        resp = ret["Resp"]
    else:
        for stun_host in STUN_SERVERS:
            if ':' in stun_host:
                temp_host, temp_port = stun_host.split(':', 1)
                stun_host = temp_host
                port = int(temp_port)
            else:
                port = stun_port
            log.debug("Trying STUN host: %s", stun_host)
            ret = stun_test(
                sock=sock,
                host=stun_host,
                port=port,
                source_ip=source_ip,
                source_port=source_port,
            )
            resp = ret["Resp"]
            if resp:
                break
    if not resp:
        return Blocked, ret
    log.debug("Result: %s", ret)
    external_ip = ret["ExternalIP"]
    external_port = ret["ExternalPort"]
    changed_ip = ret["ChangedIP"]
    changed_port = ret["ChangedPort"]
    if ret["ExternalIP"] == source_ip:
        change_request = "".join([ChangeRequest, "0004", "00000006"])
        ret = stun_test(
            sock=sock,
            host=stun_host,
            port=port,
            source_ip=source_ip,
            source_port=source_port,
            send_data=change_request,
        )
        if ret["Resp"]:
            typ = OpenInternet
        else:
            typ = SymmetricUDPFirewall
    else:
        change_request = "".join([ChangeRequest, "0004", "00000006"])
        log.debug("Do Test2")
        ret = stun_test(
            sock=sock,
            host=stun_host,
            port=port,
            source_ip=source_ip,
            source_port=source_port,
            send_data=change_request,
        )
        log.debug("Result: %s", ret)
        if ret["Resp"]:
            typ = FullCone
        else:
            log.debug("Do Test1")
            ret = stun_test(
                sock=sock,
                host=changed_ip,
                port=changed_port,
                source_ip=source_ip,
                source_port=source_port,
            )
            log.debug("Result: %s", ret)
            if not ret["Resp"]:
                typ = ChangedAddressError
            else:
                if (
                    external_ip == ret["ExternalIP"]
                    and external_port == ret["ExternalPort"]
                ):
                    change_port_request = "".join([ChangeRequest, "0004", "00000002"])
                    log.debug("Do Test3")
                    ret = stun_test(
                        sock=sock,
                        host=changed_ip,
                        port=port,
                        source_ip=source_ip,
                        source_port=source_port,
                        send_data=change_port_request,
                    )
                    log.debug("Result: %s", ret)
                    if ret["Resp"]:
                        typ = RestricNAT
                    else:
                        typ = RestricPortNAT
                else:
                    typ = SymmetricNAT
    return typ, ret


def get_ip_info(
    source_ip: str = "0.0.0.0",
    source_port: int = 54320,
    stun_host: Optional[str] = None,
    stun_port: int = 3478,
) -> Tuple[str, str, int]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((source_ip, source_port))
        nat_type, nat = get_nat_type(
            sock=sock,
            source_ip=source_ip,
            source_port=source_port,
            stun_host=stun_host,
            stun_port=stun_port,
        )
        external_ip = nat["ExternalIP"]
        external_port = nat["ExternalPort"]
    return (nat_type, external_ip, external_port)
