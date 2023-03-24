#!/usr/bin/env python3

import os
import pyshark
import argparse

def extract_ntlmssp(packet):
    """
    Extracts NTLMSSP details from a packet

    Args:
        packet: A pyshark packet object

    Returns:
        A pyshark NTLMSSP object or None if no NTLMSSP details were found
    """
    if "<HTTP " in str(packet.layers):
        return packet.http.ntlmssp
    else:
        return None

def extract_challenge(packet):
    """
    Extracts the NTLMSSP challenge from a packet

    Args:
        packet: A pyshark packet object

    Returns:
        The NTLMSSP challenge as a string, or None if no challenge was found
    """
    ntlmssp = extract_ntlmssp(packet)
    if ntlmssp and ntlmssp.ntlmssp_messagetype == "0x00000002":
        return ntlmssp.ntlmssp_ntlmserverchallenge.replace(":", "")
    else:
        return None

def extract_response(packet):
    """
    Extracts the NTLMSSP response from a packet

    Args:
        packet: A pyshark packet object

    Returns:
        A dictionary containing the NTLMSSP response details (username, domain, and response), or None if no response
        was found
    """
    ntlmssp = extract_ntlmssp(packet)
    if ntlmssp and ntlmssp.ntlmssp_messagetype == "0x00000003":
        domain = ntlmssp.auth_domain if ntlmssp.auth_domain != "NULL" else ""
        return {"username": ntlmssp.auth_username, "domain": domain, "response": ntlmssp.auth_ntresponse.replace(":", "")}
    else:
        return None

def extract_ntlmssp_details(packet):
    """
    Extracts NTLMSSP details from a packet

    Args:
        packet: A pyshark packet object

    Returns:
        A dictionary containing the extracted details, or None if no details were found
    """
    challenge = extract_challenge(packet)
    response = extract_response(packet)
    if challenge:
        return {"stream": packet.tcp.stream, "challenge": challenge}
    elif response:
        response["stream"] = packet.tcp.stream
        return response
    else:
        return None



def print_hashes(output_format, hashes):
    hashes_keys = sorted(hashes.keys())
    for k in hashes_keys:
        arr = hashes[k]
        if len(arr) != 4:
            continue
        try:
            uname = arr["username"]
            chal = arr["challenge"]
            domain = arr["domain"]
            ntlm_1 = arr["response"][:32]
            ntlm_2 = arr["response"][32:]
            if output_format == 1:
                print(uname + ":$NETNTLMv2$" + domain + "$" + chal + "$" + ntlm_1 + "$" + ntlm_2)
            else:
                print(uname + "::" + domain + ":" + chal + ":" + ntlm_1 + ":" + ntlm_2)
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="Extract NetNTLMv2 hashes from a pcap file with NTLMSSP authentication")
    parser.add_argument("-t", "--type", metavar="format", type=int, required=True, help="Hash output format (0 => Hashcat; 1 => John)")
    parser.add_argument("-f", "--file", metavar="pcap", type=str, required=True, help="PCAP file path")
    args = parser.parse_args()

    format = args.type
    if format not in [0, 1]:
        print(f"[!] Incorrect format. Please provide either 0 for hashcat or 1 for john.")
        exit(1)

    path = args.file
    if not os.path.exists(path):
        print(f"[!] The pcap file does not exist at \"{path}\".")
        exit(1)

    try:
        cap = pyshark.FileCapture(path, display_filter="ntlmssp")
    except FileNotFoundError as e:
        print(e)
        exit(1)

    hashes = extract_ntlmssp_details(cap)
    print_hashes(format, hashes)


if __name__ == '__main__':
    main()
