#!/usr/bin/env python3

import os
import pyshark
import argparse

def extract_ntlmssp_details(cap):
    """Extracts NTLMSSP details from a pcap capture.

    Args:
        cap (pyshark.FileCapture): A pyshark file capture object.

    Returns:
        dict: A dictionary of NTLMSSP details, with stream IDs as keys and dictionaries of details as values.
    """
    packs = {}
    for pack in cap:
        data = get_packet_data(pack)
        if data:
            try:
                stream_id = pack.tcp.stream
                if data.ntlmssp_messagetype == "0x00000002":
                    add_challenge(packs, stream_id, data.ntlmssp_ntlmserverchallenge)
                elif data.ntlmssp_messagetype == "0x00000003":
                    add_response(packs, stream_id, data.ntlmssp_auth_username, data.ntlmssp_auth_domain, data.ntlmssp_auth_ntresponse)
            except Exception:
                pass
    return packs


def get_packet_data(pack):
    """Extracts relevant packet data from a pyshark packet.

    Args:
        pack (pyshark.packet.packet): A pyshark packet object.

    Returns:
        pyshark.packet.layers.*: The relevant packet data, or None if none is found.
    """
    data = None
    if "<HTTP " in str(pack.layers):
        data = pack.http
    return data


def add_challenge(packs, stream_id, challenge):
    """Adds a challenge to the packs dictionary.

    Args:
        packs (dict): A dictionary of NTLMSSP details, with stream IDs as keys and dictionaries of details as values.
        stream_id (int): The ID of the stream.
        challenge (str): The NTLMSSP server challenge.
    """
    if stream_id not in packs:
        packs[stream_id] = {}
    packs[stream_id]["challenge"] = challenge.replace(":", "")


def add_response(packs, stream_id, username, domain, response):
    """Adds a response to the packs dictionary.

    Args:
        packs (dict): A dictionary of NTLMSSP details, with stream IDs as keys and dictionaries of details as values.
        stream_id (int): The ID of the stream.
        username (str): The username from the NTLMSSP authentication.
        domain (str): The domain from the NTLMSSP authentication.
        response (str): The NTLMSSP authentication response.
    """
    if stream_id not in packs:
        packs[stream_id] = {}
    packs[stream_id]["username"] = username
    packs[stream_id]["domain"] = domain if domain != "NULL" else ""
    packs[stream_id]["response"] = response.replace(":", "")




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

    try:
        cap = pyshark.FileCapture(path, display_filter="ntlmssp")
    except FileNotFoundError as e:
        print(e)
        exit(1)

    hashes = extract_ntlmssp_details(cap)
    print_hashes(format, hashes)


if __name__ == '__main__':
    main()
