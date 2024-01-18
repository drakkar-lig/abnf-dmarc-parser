import unittest
import pytest

from dmarcparser import DmarcException
from dmarcparser import DmarcParser
from dmarcparser.parser import DmarcObject


def assert_error(record: str, follow_downgrade: bool = False):
    with pytest.raises(DmarcException):
        parse(record, follow_downgrade)


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; p=reject; rua=mailto:bob@example.com; ruf=mailto:bob@example.com; fo=0; adkim=r; aspf=r",
        "v=DMARC1;p=none;pct=100;adkim=r;aspf=r;ruf=mailto:dmarc-ruf@univ.com;fo=1;rua=mailto:dmarc-rua@univ.com",
        "v=DMARC1;p=none;pct=100;adkim=r;aspf=r;ruf=mailto:dmarc-ruf@univ.com;fo=1;rua=mailto:dmarc-rua@univ.com;",
        "v=DMARC1; p=none; rf=afrf; rua=mailto:dmarc-a@abuse.net; ruf=mailto:dmarc-f@abuse.net",
        "v=DMARC1; p=none;",
    ],
)
def test_valid_dmarc(record: str):
    parse(record)


def parse(record: str, follow_downgrade: bool = False) -> DmarcObject:
    return DmarcParser().parse(record, follow_downgrade)


class DmarcTest(unittest.TestCase):
    def assert_raises(self, record, follow_downgrade=False):
        with self.assertRaises(DmarcException):
            parse(record, follow_downgrade=follow_downgrade)


class TestOpenDmarcCases(DmarcTest):
    def test_valid_1(self):
        result = parse(
            "v=DMARC1; p=none; rf=afrf; rua=mailto:dmarc-a@abuse.net; ruf=mailto:dmarc-f@abuse.net"
        )
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual("DMARC1", result.v.effective_value)
        self.assertEqual(1, len(result.rua.valid))
        self.assertEqual("dmarc-a@abuse.net", result.rua.valid[0]["email"])
        self.assertEqual(1, len(result.ruf.valid))
        self.assertEqual("dmarc-f@abuse.net", result.ruf.valid[0]["email"])

    def test_valid_2(self):
        result = parse("v=DMARC1; p=none;")
        self.assertEqual("DMARC1", result.v.effective_value)
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual(0, len(result.rua.valid))
        self.assertEqual(0, len(result.ruf.valid))

    def test_valid_3(self):
        result = parse("v=DMARC1; p=reject;")
        self.assertEqual("DMARC1", result.v.effective_value)
        self.assertEqual("reject", result.p.effective_value)
        self.assertEqual(0, len(result.rua.valid))
        self.assertEqual(0, len(result.ruf.valid))

    def test_valid_4(self):
        result = parse("v=DMARC1; p=quarantine;")
        self.assertEqual("DMARC1", result.v.effective_value)
        self.assertEqual("quarantine", result.p.effective_value)
        self.assertEqual(0, len(result.rua.valid))
        self.assertEqual(0, len(result.ruf.valid))

    def test_valid_5(self):
        result = parse("v=DMARC1; p=none; rua=ftp://abuse.com")
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual(0, len(result.rua.valid))
        self.assertEqual(1, len(result.rua.other))
        self.assertEqual(0, len(result.ruf.valid))
        self.assertEqual(0, len(result.ruf.other))
        self.assertIn("ftp://abuse.com", result.rua.other)

    def test_valid_6(self):
        result = parse("v=DMARC1; p=none; ruf=mailto://abuse.com")
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual(0, len(result.rua.valid))
        self.assertEqual(0, len(result.rua.other))
        self.assertEqual(0, len(result.ruf.valid))
        self.assertEqual(1, len(result.ruf.other))
        self.assertIn("mailto://abuse.com", result.ruf.other)

    def test_valid_7(self):
        result = parse("v=DMARC1; p=none; ruf=mailto://abuse.com; foo=bar; buzz=happy;")
        self.assertEqual("none", result.p.effective_value)
        self.assertIsNone(result.ruf.value_to_str())
        self.assertIn("mailto://abuse.com", result.ruf.other)
        self.assertIn("foo=bar", result.ignored_tags)
        self.assertIn("buzz=happy", result.ignored_tags)


class NewTests(DmarcTest):
    def test_valid_8(self):
        result = parse("v=DMARC1; p=none; ruf=mailto:test@test.com!1;")
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual(1, len(result.ruf.valid))
        self.assertEqual(1, result.ruf.valid[0]["limit"])
        self.assertEqual("test@test.com", result.ruf.valid[0]["email"])

    def test_valid_10(self):
        result = parse("v=DMARC1; p=none; ruf=mailto:test@test.com!100m;")
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual(1, len(result.ruf.valid))
        self.assertEqual(104857600, result.ruf.valid[0]["limit"])
        self.assertEqual("test@test.com", result.ruf.valid[0]["email"])

    def test_valid_11(self):
        result = parse(
            "v=DMARC1; p=none; ruf=mailto:test@test.com!2G,mailto:test2@test.com!3m;"
        )
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual(2, len(result.ruf.valid))
        self.assertEqual(2147483648, result.ruf.valid[0]["limit"])
        self.assertEqual("test@test.com", result.ruf.valid[0]["email"])
        self.assertEqual(3145728, result.ruf.valid[1]["limit"])
        self.assertEqual("test2@test.com", result.ruf.valid[1]["email"])

    def test_case_insensitive(self):
        result = parse("v=DMARC1;p=ReJect")
        self.assertEqual("reject", result.p.effective_value)

    def test_case_space(self):
        result = parse("v = DMARC1;p=reject;")
        self.assertEqual("reject", result.p.effective_value)

    def test_tag_case_1(self):
        result = parse("V=DMARC1;p=reject;")
        self.assertEqual("reject", result.p.effective_value)

    def test_tag_case_2(self):
        result = parse("V=DMARC1;P=reject;")
        self.assertEqual("reject", result.p.effective_value)

    def test_without_p_downgrade(self):
        self.assert_raises("v=DMARC1; p=reject; sp=error; rua=mailto:rua@example.com")

    def test_p_downgrade(self):
        result = parse("v=DMARC1; p=reject; sp=error; rua=mailto:rua@example.com", True)
        self.assertEqual("none", result.p.effective_value)

    def test_without_p_downgrade_1(self):
        self.assert_raises("v=DMARC1; p=error; rua=mailto:rua@example.com")

    def test_p_downgrade_1(self):
        result = parse("v=DMARC1; p=error; rua=mailto:rua@example.com", True)
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual("none", result.sp.effective_value)

    def test_p_missing(self):
        self.assert_raises("v=DMARC1;rua=mailto:rua@example.com;")

    def test_p_missing_downgrade(self):
        result = parse("v=DMARC1;rua=mailto:rua@example.com;", True)
        self.assertEqual("none", result.p.effective_value)
        self.assertTrue(result.p.downgraded)
        self.assertEqual("none", result.sp.effective_value)
        self.assertTrue(result.sp.inherited)

    def test_p_missing_downgrade_2(self):
        result = parse("v=DMARC1;p=error;rua=mailto:rua@example.com;", True)
        self.assertEqual("none", result.p.effective_value)
        self.assertTrue(result.p.downgraded)
        self.assertEqual("none", result.sp.effective_value)
        self.assertTrue(result.sp.inherited)
        self.assertIsNone(result.sp.value)
        self.assertEqual("none", result.sp.effective_value)

    def test_p_missing_downgrade_3(self):
        result = parse("v=DMARC1;p=error;sp=reject;rua=mailto:rua@example.com;", True)
        self.assertEqual("none", result.p.effective_value)
        self.assertTrue(result.p.downgraded)
        self.assertFalse(result.sp.inherited)
        self.assertEqual("reject", result.sp.value)
        self.assertEqual("reject", result.sp.effective_value)

    def test_p_missing_downgrade_4(self):
        result = parse("v=DMARC1;p=reject;sp=nonee; rua=mailtoo:me@example.com", True)
        self.assertEqual("none", result.p.effective_value)
        self.assertTrue(result.p.downgraded)
        self.assertTrue(result.sp.inherited)
        self.assertEqual("nonee", result.sp.value)
        self.assertEqual("none", result.sp.effective_value)

    def test_p_sp_fo(self):
        result = parse(
            "v=DMARC1;p=reject;sp=reject;rua=mailto:me@example.com!1G;fo=1:0:s:d:d:1:0:0:1"
        )
        self.assertFalse(result.sp.inherited)

    # Record with a trailing whitespace must be accepted.
    def test_trailing_whitespace(self):
        result = parse("v=DMARC1; p=reject; ")
        self.assertEqual("reject", result.p.effective_value)

    def test_downgrade_only_v_tag(self):
        self.assert_raises("v=DMARC1", True)

    def test_downgrade_2(self):
        result = parse(
            "v=DMARC1;p=notgood;sp=rejet;rua=mailto:rua@example.com",
            follow_downgrade=True,
        )
        self.assertEqual("none", result.p.effective_value)
        self.assertEqual("none", result.sp.effective_value)
        self.assertIn("rua@example.com", result.rua.effective_value[0]["email"])


@pytest.mark.parametrize(
    "record",
    [
        # OpenDmarc failing Tests
        "v=DMARC1; p=n;",
        "V=BOB",
        "v=DMARC1; p=bob;",
        "v=DMARC1; p=bob;",
        "v=DMARC1; p=none; sp=bob;",
        "v=DMARC1; p=none; adkim=bob;",
        "v=DMARC1; p=none; aspf=bob;",
        "v=DMARC1; p=none; rf=bob;",
        "v=DMARC1; p=none; ri=bob;",
        "v=DMARC1; p=none; pct=500;",
        "v=DMARC1; pct=100;",
        "v=DMARC1; p=none; rf=000000000000000000000000000000000",
        "v=DMARC1; sp=none; p=reject",
        "",
        # Tests from checkdmarc
        "v=DMARC1; p=none; rua=reports@dmarc.cyber.dhs.gov,mailto:dmarcreports@usdoj.gov",
        "v=DMARC1; p=none; rua=__mailto:reports@dmarc.cyber.dhs.gov,mailto:dmarcreports@usdoj.gov",
        "v=DMARC1; p=foo; rua=mailto:dmarc@example.com",
        # our failing tests
        "v=DMARC1; p=reject; p=quarantine",
        "v=DMARC1; p=reject; p=quarantine" "v=dmarc1;p=reject",
        "v=DMARC1;p=rejecttest",
        "p=reject;v=DMARC1;",
        "v=DMARC1;rua=mailto:rua@example.com!am",
        "v=DMARC1;p=reject;sp=nonee",
        "v=DMARC1; p=reject; rua=bob@example.com",
        "p=none;",
        "p=none;v=DMARC1;",
        "v=DMARC1;p=reject;;" "v=DMARC1;rua=mailto:rua@example.com!100p",
    ],
)
def test_failing(record):
    assert_error(record)
