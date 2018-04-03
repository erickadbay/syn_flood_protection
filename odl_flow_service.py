from requests import put
from xmler import dict2xml
from sys import exit

class ODLFlowService:
    ODL_CONTROLLER_IP = '192.168.56.10'
    ODL_USERNAME = 'admin'
    ODL_PASSWORD = 'admin'

    DEFAULT_FLOW_NAME = 'SYN-FLOOD PROTECTION FLOW'
    TCP_FLAGS = '0x02'
    # Drop packets for 5 minutes
    FLOW_TIMEOUT = 300

    @classmethod
    def create_block_flow(cls, flow_id, ip_to_block):
        url = 'http://' + cls.ODL_CONTROLLER_IP + ':8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/' + flow_id
        request = put(
            url, 
            headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'},
            auth = (cls.ODL_USERNAME, cls.ODL_PASSWORD),
            data = cls.create_xml_payload(flow_id = flow_id, ip_to_block = ip_to_block)
        )

        if request.status_code == 400:
            print(request.text)
            exit()
        else:
            print('Successfully created block flow! Yay!')

    @classmethod
    def create_xml_payload(cls, flow_id, ip_to_block):
        xml_prolog = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'

        # TWEAK FOR ACTUAL FLOW THAT BLOCKS PACKETS FROM ip_to_block
        body = {
            'flow': {
                '@attrs': {'xmlns': 'urn:opendaylight:flow:inventory'},
                'id': flow_id,
                'table_id': '0',
                'flow-name': cls.DEFAULT_FLOW_NAME,
                'match': {
                    'ethernet-match':{
                        'ethernet-type': {
                            'type': '2048'
                        }
                    },
                    'ipv4-source': ip_to_block,
                    'tcp-flags-match': {
                        'tcp-flags': cls.TCP_FLAGS
                    }
                },
                'instructions': {
                    'instruction': {
                        'order': '0',
                        'apply-actions': {
                            'action': {
                                'order': '0',
                                'drop-action': {}
                            }
                        }
                    }
                },
                'priority': '2',
                'hard-timeout': str(cls.FLOW_TIMEOUT),
            }
        }

        return xml_prolog + dict2xml(body)


