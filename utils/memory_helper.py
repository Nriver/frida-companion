def add_address_offset(base_address, offset):
    """
    add memory address with offset

    :param base_address:
    :param offset:
    :return:

    Usage:
    add_address_offset("0x55f2b285f000", "0000000000001149")
    """
    return hex(int(base_address, 16) + int(offset, 16))
