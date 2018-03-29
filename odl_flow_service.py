from requests import put
from xmler import dict2xml

class ODLFlowService:

    DEFAULT_FLOW_NAME = 'Foo'
    ODL_USERNAME = 'admin'
    ODL_PASSWORD = 'admin'

    @classmethod
    def create_block_flow(cls, odl_ip, flow_id, ip_to_block):
        url = f'http://{odl_ip}:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/{flow_id}'

        put( 
            url, 
            headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'},
            auth = (ODL_USERNAME, ODL_PASSWORD),
            data = cls.create_xml_payload(flow_id = flow_id, ip_to_block = ip_to_block)
        )

    @classmethod
    def create_xml_payload(cls, flow_id, ip_to_block):
        xml_prolog = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'

        # TWEAK FOR ACTUAL FLOW THAT BLOCKS PACKETS FROM ip_to_block
        body = {
            'flow': {
                '@attrs': {'xmlns': 'urn:opendaylight:flow:inventory'},
                'priority': "2",
                'flow-name': cls.DEFAULT_FLOW_NAME,
                'match': {
                    'ethernet-match':{
                        'ethernet-type': {
                            'type': f'{2048}'
                        }
                    },
                    'ipv4-destination': f'{ip_to_block}'
                },
                'id': f'{flow_id}',
                'table_id': f'{0}',
                'instructions': {
                    'instruction': {
                        'order': f'{0}',
                        'apply-actions': {
                            'action': {
                                'order': f'{0}',
                            }
                        }
                    }
                }
            }
        }

        return xml_prolog + dict2xml(body)


