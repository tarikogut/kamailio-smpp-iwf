#!/usr/bin/env python3
"""
Test SMPP Client Script
Path: Client (You) -> Kamailio SMS-IWF (Port 2779) -> Melrose SMSC Simulators (1..4)
"""

import sys
import socket
import struct
import time

KAMAILIO_HOST = "127.0.0.1"
KAMAILIO_PORT = 2779
SYSTEM_ID = "kamailio_client"
PASSWORD = "kamailio_pass"

def main():
    print(f"[*] Connecting to Kamailio SMS-IWF at {KAMAILIO_HOST}:{KAMAILIO_PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((KAMAILIO_HOST, KAMAILIO_PORT))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return 1

    # 1. BIND_TRANSCEIVER
    sys_id_b = SYSTEM_ID.encode('latin1') + b'\x00'
    passwd_b = PASSWORD.encode('latin1') + b'\x00'
    systype_b = b'CMT\x00'
    ver_b = b'\x34'
    body = sys_id_b + passwd_b + systype_b + ver_b + b'\x00\x00\x00'
    header = struct.pack('>IIII', 16 + len(body), 0x00000009, 0, 1)

    s.sendall(header + body)
    resp = s.recv(1024)
    r_len, r_id, r_status, r_seq = struct.unpack('>IIII', resp[:16])

    if r_status != 0:
        print(f"[-] Bind failed with status: 0x{r_status:08X}")
        s.close()
        return 1
    print(f"[+] Successfully BOUND to Kamailio SMS-IWF as '{SYSTEM_ID}'! (Cmd=0x{r_id:08X})")

    # 2. SUBMIT_SM
    src_addr = b'BTK-SMS\x00'
    dst_addr = b'905321000000\x00'
    message_text = "Merhaba Dunya! Kamailio SMPP IWF Test Mesaji (BTK & NLI Destekli)"
    msg_bytes = message_text.encode('utf-8')

    svc_type = b'\x00'
    src_ton, src_npi = b'\x05', b'\x00'
    dst_ton, dst_npi = b'\x01', b'\x01'
    flags = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00' # esm, proto, prio, sched, val, reg_dlr, repl, coding, def_id
    sm_len = struct.pack('B', len(msg_bytes))

    submit_body = svc_type + src_ton + src_npi + src_addr + dst_ton + dst_npi + dst_addr + flags + sm_len + msg_bytes
    submit_hdr = struct.pack('>IIII', 16 + len(submit_body), 0x00000004, 0, 2)

    print(f"[*] Sending SUBMIT_SM: '{message_text}'...")
    s.sendall(submit_hdr + submit_body)
    resp2 = s.recv(1024)
    r2_len, r2_id, r2_status, r2_seq = struct.unpack('>IIII', resp2[:16])
    kamailio_msg_id = resp2[16:].split(b'\x00')[0].decode('latin1')

    print(f"[+] SUBMIT_SM ACK received from Kamailio! Status=0x{r2_status:08X}, MsgID='{kamailio_msg_id}'")
    print(f"[+] Mesaj Kamailio SMS-IWF tarafindan sim1 (Melrose SMSC) simulatorune iletildi.")
    print(f"[*] Waiting for DELIVER_SM (DLR) from Kamailio...")

    dlr_received = False
    start_wait = time.time()
    s.settimeout(12.0)
    try:
        while time.time() - start_wait < 12.0:
            dlr_pkt = s.recv(1024)
            if not dlr_pkt or len(dlr_pkt) < 16:
                break
            d_len, d_id, d_status, d_seq = struct.unpack('>IIII', dlr_pkt[:16])
            if d_id == 0x00000005:  # DELIVER_SM
                print(f"[+] >>> DELIVER_SM (DLR) RECEIVED from Kamailio! Seq={d_seq}")
                dlr_body = dlr_pkt[16:]
                # Print receipt text if available
                parts = dlr_body.split(b'\x00')
                for p in parts:
                    if b'id:' in p or b'stat:' in p:
                        print(f"[+] DLR Content: '{p.decode('latin1', errors='ignore')}'")

                # Send DELIVER_SM_RESP
                resp_hdr = struct.pack('>IIII', 16, 0x80000005, 0, d_seq)
                s.sendall(resp_hdr)
                print(f"[+] Sent DELIVER_SM_RESP ACK back to Kamailio (Seq={d_seq})")
                dlr_received = True
                break
    except socket.timeout:
        print("[-] Timed out waiting for DLR.")

    s.close()
    if dlr_received:
        print("[SUCCESS] Full End-to-End Cycle Complete: BIND -> SUBMIT_SM -> SUBMIT_SM_RESP -> DELIVER_SM (DLR) -> DELIVER_SM_RESP!")
        return 0
    else:
        print("[-] DLR not received within timeout")
        return 1

if __name__ == "__main__":
    sys.exit(main())
