from requests import put
from xmler import dict2xml
import sys
class ODLFlowService:

    #change to something meaningful
    DEFAULT_FLOW_NAME = 'Foo'
    ODL_USERNAME = 'admin'
    ODL_PASSWORD = 'admin'

    TCP_FLAGS = '0x02'
    FLOW_TIMEOUT = 12

    @classmethod
    def create_block_flow(cls, odl_ip, flow_id, ip_to_block):
        url = 'http://' + odl_ip + ':8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0' + 'flow/' + flow_id
        print(url)
        print(cls.create_xml_payload(flow_id = flow_id, ip_to_block = ip_to_block))
        print("-------------------------------")
        r = put( 
            url, 
            headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'},
            auth = (cls.ODL_USERNAME, cls.ODL_PASSWORD),
            data = cls.create_xml_payload(flow_id = flow_id, ip_to_block = ip_to_block)
        )

        if r.status_code == 400:
            print(r.text)
            sys.exit()
        else:
            print("Successfully created block flow! Yay!")

    @classmethod
    def create_xml_payload(cls, flow_id, ip_to_block):
        xml_prolog = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'

        # TWEAK FOR ACTUAL FLOW THAT BLOCKS PACKETS FROM ip_to_block
        body = {
            'flow': {
                '@attrs': {'xmlns': 'urn:opendaylight:flow:inventory'},
                'id': str(flow_id),
                'table_id': '0',
                'flow-name': cls.DEFAULT_FLOW_NAME,
                'match': {
                    'ethernet-match':{
                        'ethernet-type': {
                            'type': '2048'
                        }
                    },
                    'ipv6-source': ip_to_block,
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


