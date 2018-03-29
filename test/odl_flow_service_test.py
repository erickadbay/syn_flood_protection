from unittest import TestCase
from odl_flow_service import ODLFlowService

class ODLFlowServiceTest(TestCase):

    def test_create_xml_payload(self):
        expected = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><priority>2</priority><flow-name>Foo</flow-name><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ipv4-destination>10.0.10.2/24</ipv4-destination></match><id>1</id><table_id>0</table_id><instructions><instruction><order>0</order><apply-actions><action><order>0</order></action></apply-actions></instruction></instructions></flow>'

        self.assertEqual(expected, ODLFlowService.create_xml_payload(flow_id = 1, ip_to_block = "10.0.10.2/24"))
