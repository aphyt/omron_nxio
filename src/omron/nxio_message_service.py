__author__ = 'Joseph Ryan'
__license__ = "GPLv2"
__maintainer__ = "Joseph Ryan"
__email__ = "jr@aphyt.com"


import socket


class NXIOResponse:
    """

    """
    def __init__(self, response_bytes):
        """
        Parse Response Bytes

        | Message sequence number   | 2 bytes little endian |
        | Data size                 | 2 bytes little endian |
        | Reserved                  | 1 bytes little endian |
        | Service code              | 1 bytes little endian |
        | General Status            | 1 bytes little endian |
        | Size of additional status | 1 bytes little endian |
        | Data                      | 496 bytes max         |

        :param response_bytes:
        """
        self.message_sequence_number = int.from_bytes(response_bytes[0:2], 'little')
        self.data_size = int.from_bytes(response_bytes[2:4], 'little')
        self.reserved = response_bytes[4:5]
        self.service_code = response_bytes[5:6]
        self.general_status = response_bytes[6:7]
        self.size_of_additional_status = response_bytes[7:8]
        self.data = response_bytes[8:]

    def __repr__(self):
        return 'Message Number: %s contains: %s' % (self.message_sequence_number, self.data)


class NXIOMessage:
    def __init__(self, service_code, class_id, instance_id, attribute_id, sequence_number, data=b''):
        """ Assemble as CIP Message

        | Message sequence number | 2 bytes little endian |
        | Reserved 1              | 2 bytes little endian |
        | Data size               | 2 bytes little endian |
        | Reserved 2              | 1 bytes little endian |
        | Service code            | 1 bytes little endian |
        | Class ID                | 2 bytes little endian |
        | Instance ID             | 2 bytes little endian |
        | Attribute ID            | 2 bytes little endian |
        | Data                    | 490 bytes max         |

        :param service_code:
        :param class_id:
        :param instance_id:
        :param attribute_id:
        :param sequence_number:
        :param data:
        """
        self.reserved_byte_1 = b'\x00\x00'
        self.reserved_byte_2 = b'\x00'
        self.command = self.reserved_byte_2 + service_code + class_id + instance_id + attribute_id
        self.command += data
        self.command_length_bytes = len(self.command).to_bytes(2, 'little')
        self.command = (sequence_number.to_bytes(2, 'little') + self.reserved_byte_1 +
                        self.command_length_bytes + self.command)


class NXMessageDispatcher:
    def __init__(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sequence_number = 0

    def __del__(self):
        self.tcp_socket.close()

    def connect(self, ip_address: str = '192.168.250.1', port: int = 64000):
        self.tcp_socket.connect((ip_address, port))

    def disconnect(self):
        try:
            self.tcp_socket.shutdown(socket.SHUT_RDWR)
            self.tcp_socket.close()
        finally:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def execute_command(self, service_code, class_id, instance_id, attribute_id=b'', data=b''):
        cip_message = NXIOMessage(service_code, class_id, instance_id,
                                  attribute_id, self.sequence_number, data)
        self.tcp_socket.send(cip_message.command)
        response_bytes = self.tcp_socket.recv(512)
        response = NXIOResponse(response_bytes)
        self.sequence_number += 1
        return response

    def get_all_identity_object_attributes(self):
        response = self.execute_command(b'\x01', b'\x01\x00', b'\x01\x00', b'\x00\x00')
        return response

    def get_input_data_size(self):
        response = self.execute_command(b'\x0e', b'\x74\x00', b'\x01\x00', b'\x02\x00')
        return response

    def get_output_data_size(self):
        response = self.execute_command(b'\x0e', b'\x74\x00', b'\x01\x00', b'\x01\x00')
        return response

    def get_input_data(self):
        response = self.execute_command(b'\x0e', b'\x04\x00', b'\x64\x00', b'\x03\x00')
        return response

    def get_output_data(self):
        response = self.execute_command(b'\x0e', b'\x04\x00', b'\x94\x00', b'\x03\x00')
        return response

    def get_configuration_instance_data(self):
        response = self.execute_command(b'\x0e', b'\x04\x00', b'\xc7\x00', b'\x03\x00')
        return response

    def set_output_data(self, data):
        response = self.execute_command(b'\x10', b'\x04\x00', b'\x94\x00', b'\x03\x00', data=data)
        return response

    def clear_nx_error_status(self):
        response = self.execute_command(b'\x32', b'\x74\x00', b'\x01\x00', b'\x00\x00')
        return response

    def change_nx_state(self, output_watchdog_timeout=100, operational=True):
        if operational:
            data = b'\x08'
        else:
            data = b'\x04'

        data += b'\x00'+int.to_bytes(output_watchdog_timeout, 4, 'little')
        print("data is %s", data)
        response = self.execute_command(b'\x39', b'\x74\x00', b'\x01\x00', b'\x00\x00', data)
        return response

    def read_nx_object(self, unit=0, index=0x1000, sub_index=0, control_field=0):
        data = int.to_bytes(unit, 2, 'little')
        data += int.to_bytes(index, 2, 'little')
        data += int.to_bytes(sub_index, 1, 'little')
        data += int.to_bytes(control_field, 1, 'little')
        response = self.execute_command(b'\x33', b'\x74\x00', b'\x01\x00', b'', data)
        return response
