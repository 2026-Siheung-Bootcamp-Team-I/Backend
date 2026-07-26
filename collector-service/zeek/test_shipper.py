"""
shipper 의 순수 변환 로직 테스트.

  python3 -m unittest discover collector-service/zeek

collector 의 RawEventMapper 가 읽는 필드와 1:1로 맞는지 확인한다.
여기가 어긋나면 이벤트가 조용히 버려지거나 network 가 아닌 타입으로 분류된다.
"""

import importlib.util
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location(
    "shipper", pathlib.Path(__file__).with_name("edrdog-zeek-shipper.py")
)
shipper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shipper)


def conn(**over):
    base = {
        "ts": 1785006412.123456,
        "uid": "CAcJw21BbVedgFnYH3",
        "id.orig_h": "192.168.0.10",
        "id.orig_p": 54321,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_bytes": 517,
    }
    base.update(over)
    return base


class ToRecordTest(unittest.TestCase):

    def test_쿼리명이_socket_events_라서_network_로_분류된다(self):
        rec = shipper.to_record(conn(), "mac-001")
        # RawEventMapper.classify 는 이름에 socket 이 들어가면 network 로 본다
        self.assertIn("socket", rec["name"])

    def test_목적지_주소와_포트가_columns_에_들어간다(self):
        rec = shipper.to_record(conn(), "mac-001")
        self.assertEqual(rec["columns"]["remote_address"], "93.184.216.34")
        self.assertEqual(rec["columns"]["remote_port"], "443")

    def test_host_와_시간이_루트에_들어간다(self):
        rec = shipper.to_record(conn(), "mac-001")
        self.assertEqual(rec["hostIdentifier"], "mac-001")
        # unixTime 은 초 단위 문자열. collector 가 ×1000 해서 밀리초로 만든다.
        self.assertEqual(rec["unixTime"], "1785006412")

    def test_action_이_added_라야_스킵되지_않는다(self):
        # RawEventMapper 는 action=removed 를 버린다
        self.assertEqual(shipper.to_record(conn(), "mac-001")["action"], "added")

    def test_목적지가_없으면_버린다(self):
        self.assertIsNone(shipper.to_record(conn(**{"id.resp_h": None}), "mac-001"))

    def test_시간이_없으면_버린다(self):
        self.assertIsNone(shipper.to_record(conn(ts=None), "mac-001"))

    def test_포트가_없어도_0_으로_보낸다(self):
        rec = shipper.to_record(conn(**{"id.resp_p": None}), "mac-001")
        self.assertEqual(rec["columns"]["remote_port"], "0")


if __name__ == "__main__":
    unittest.main()
