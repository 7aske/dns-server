import socket, glob, json

HOST = "127.0.0.1"
PORT = 53
domains_json = {}

# RESPONSE PARAMETERS
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))


def load_zones():
    global domains_json
    zone_files = glob.glob("domains/*.domain")
    for zone in zone_files:
        with open(zone) as zone_data:
            data = json.load(zone_data)
            domains_json[data["$origin"]] = data
    return domains_json


def get_domain(data):
    expected_len = data[0]
    domain = ""
    current = 0
    question_type = ""
    for i, byte in enumerate(data):
        if byte == 0:
            question_type = data[i + 1: i + 3]
            break
        if i != 0:
            if current < expected_len:
                domain += chr(byte)
                current += 1
            else:
                domain += '.'
                expected_len = byte
                current = 0

    return domain, question_type


def get_records(domain, question_type):
    global domains_json
    try:
        domain_data = domains_json[domain]
    except KeyError as e:
        print("No such domain")
        return None
    return domain_data[question_type]


def rec_to_bytes(recttl, recval):
    record = b"\xc0\x0c"
    record += bytes([0]) + bytes([1])
    record += bytes([0]) + bytes([1])
    record += int(recttl).to_bytes(4, byteorder='big')
    record += bytes([0]) + bytes([4])
    for part in recval.split('.'):
        record += bytes([int(part)])
    return record


def build_response(data):
    ID = ""
    QR = '1'
    OPCODE = ""
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = "000"
    RCODE = "0000"
    QDCOUNT = b"\x00\x01"

    for i, byte in enumerate(data):
        if i in [0, 1]:
            ID += hex(byte)[2:]
        if i == 2:
            for bit in range(1, 5):
                OPCODE += str(ord(bytes(byte)) & (1 << bit))

    ID = int(ID).to_bytes(1, byteorder='big')
    byte_1 = int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big')
    byte_2 = int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')
    domain, question_type = get_domain(req[12:])
    records = get_records(domain, "a")
    if records is None:
        return (0).to_bytes(2, byteorder='big')
    ANCOUNT = len(records).to_bytes(2, byteorder='big')

    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dns_header = ID + byte_1 + byte_2 + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    domain_array = domain.split('.')

    question = b""
    for part in domain_array:
        question += bytes([len(part)])
        for char in part:
            question += ord(char).to_bytes(1, byteorder='big')
    question += (0).to_bytes(1, byteorder='big')
    question += (1).to_bytes(2, byteorder='big')
    question += (1).to_bytes(2, byteorder='big')

    dns_body = b""
    dns_body += question
    for record in records:
        dns_body += rec_to_bytes(record["ttl"], record["value"])

    return dns_header + dns_body


load_zones()

while True:
    req, addr = sock.recvfrom(512)
    resp = build_response(req)
    print(resp)
    sock.sendto(resp, addr)
