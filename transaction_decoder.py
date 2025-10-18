"""
Bitcoin Transaction Hex Decoder
Description:
    This script parses a Bitcoin transaction hex string (SegWit or non-SegWit)
    and outputs a structured, readable dictionary of its contents.
"""

import pprint

def read_bytes(tx_hex, offset, length):
    """
    Read 'length' bytes from tx_hex starting at offset.
    Returns the bytes and the updated offset.
    """
    bytes_data = bytes.fromhex(tx_hex[offset:offset + length * 2])
    return bytes_data, offset + length * 2


def read_varint(tx_hex, offset):
    """
    Read a Bitcoin variable-length integer (varint) from tx_hex starting at offset.
    Returns the integer value and the new offset.
    """
    first_byte = int(tx_hex[offset:offset + 2], 16)
    offset += 2

    if first_byte < 0xfd:
        return first_byte, offset
    elif first_byte == 0xfd:
        value = int(tx_hex[offset:offset + 4], 16)
        offset += 4
        return value, offset
    elif first_byte == 0xfe:
        value = int(tx_hex[offset:offset + 8], 16)
        offset += 8
        return value, offset
    else:  # 0xff
        value = int(tx_hex[offset:offset + 16], 16)
        offset += 16
        return value, offset


def parse_transaction(tx_hex):
    """
    Parse a Bitcoin transaction hex string and return a dictionary with:
        - version
        - segwit flag
        - inputs
        - outputs
        - witnesses
        - locktime
    """
    offset = 0

    # --- Version ---
    version_bytes, offset = read_bytes(tx_hex, offset, 4)
    version = int.from_bytes(version_bytes, byteorder='little')

    # --- Check for SegWit ---
    marker = int(tx_hex[offset:offset + 2], 16)
    flag = int(tx_hex[offset + 2:offset + 4], 16)

    segwit = False
    if marker == 0 and flag != 0:
        segwit = True
        offset += 4

    # --- Input count ---
    input_count, offset = read_varint(tx_hex, offset)

    # --- Parse inputs ---
    inputs = []
    for _ in range(input_count):
        txid_bytes, offset = read_bytes(tx_hex, offset, 32)
        txid = txid_bytes[::-1].hex()  # reverse byte order
        vout_bytes, offset = read_bytes(tx_hex, offset, 4)
        vout = int.from_bytes(vout_bytes, byteorder='little')
        script_len, offset = read_varint(tx_hex, offset)
        script_sig_bytes, offset = read_bytes(tx_hex, offset, script_len)
        sequence_bytes, offset = read_bytes(tx_hex, offset, 4)
        sequence = int.from_bytes(sequence_bytes, byteorder='little')
        inputs.append({
            "txid": txid,
            "vout": vout,
            "scriptSig": script_sig_bytes.hex(),
            "sequence": sequence
        })

    # --- Output count ---
    output_count, offset = read_varint(tx_hex, offset)

    # --- Parse outputs ---
    outputs = []
    for _ in range(output_count):
        value_bytes, offset = read_bytes(tx_hex, offset, 8)
        value = int.from_bytes(value_bytes, byteorder='little') / 1e8  # convert to BTC
        script_len, offset = read_varint(tx_hex, offset)
        script_pubkey_bytes, offset = read_bytes(tx_hex, offset, script_len)
        outputs.append({
            "value": value,
            "scriptPubKey": script_pubkey_bytes.hex()
        })

    # --- Parse witnesses (for SegWit) ---
    witnesses = []
    if segwit:
        for i in range(input_count):
            witness_count, offset = read_varint(tx_hex, offset)
            witness_items = []
            for _ in range(witness_count):
                item_len, offset = read_varint(tx_hex, offset)
                item_bytes, offset = read_bytes(tx_hex, offset, item_len)
                witness_items.append(item_bytes.hex())
            witnesses.append(witness_items)

    # --- Locktime ---
    locktime_bytes, offset = read_bytes(tx_hex, offset, 4)
    locktime = int.from_bytes(locktime_bytes, byteorder='little')

    return {
        "version": version,
        "segwit": segwit,
        "inputs": inputs,
        "outputs": outputs,
        "witnesses": witnesses,
        "locktime": locktime
    }


if __name__ == "__main__":
    tx_hex = "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00"

    parsed_tx = parse_transaction(tx_hex)

    print("\nDecoded Bitcoin Transaction:\n")
    pprint.pprint(parsed_tx)
