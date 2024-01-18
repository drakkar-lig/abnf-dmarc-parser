import functools
import re
from typing import Union, Optional, Tuple, List

import validators
from apg_py.api.api import Grammar
from apg_py.lib import utilities as apg_util
from apg_py.lib.identifiers import MATCH
from apg_py.lib.parser import Parser as APGParser

from dmarcparser.grammars import load_grammar, GrammarType
from dmarcparser.tags import (
    FOTag,
    RUFTag,
    RUATag,
    RITag,
    PCTTag,
    DMARC1Tag,
    PTag,
    SPTag,
    ADKIMTag,
    ASPFTag,
    RFTag,
    DmarcTag,
    TDmarcAttr,
    EmailObj,
)

POLICY_VALUES = {"none", "reject", "quarantine"}

CHAR_TO_BYTE_MAP = {"k": 2**10, "m": 2**20, "g": 2**30, "t": 2**40}
VALID_DMARC_TAGS = [
    "v",
    "p",
    "sp",
    "adkim",
    "aspf",
    "fo",
    "rf",
    "ri",
    "pct",
    "rua",
    "ruf",
]
VALID_DMARC_TAGS_SET = set(VALID_DMARC_TAGS)

SKIP_WSP_REGEX = re.compile(r"\s")
SIZE_LIMIT_REGEX = re.compile(r"!(?P<limit>[0-9]+)(?P<mult_byte>[KMGTkmgt]?)$")


class DmarcException(Exception):
    """Exception raised when there is an error using parsing DMARC fiels
    Attributes :
    value -- raw value that triggered the error
    code -- Different code exception
    1 : DMARC is not valid
    2 : Tag allready exist
    3 : Non optional tag not found
    4 :
    """

    BACKSLAH_ZERO = 0
    NOT_VALID_RECORD = 1
    TAG_ALLREADY_EXIST = 2
    FO_ERRORS = 3

    ErrorString = {
        1: "This Dmarc records is not valid",
        2: "The tag allready exist",
        0: "\\0 is not allowed",
        3: "Error in the fo parameters",
    }

    def __init__(self, code, value, plus=""):
        self.code = code
        self.value = value
        self.plus = plus

    def problem(self):
        return f"{self.value}:{self.plus}"

    def __str__(self) -> str:
        return (
            f'Dmarc Error : {self.ErrorString.get(self.code, "Unknown")}: {self.value}'
        )


class DmarcParserException(Exception):
    pass


class DmarcObject:
    __slots__ = (
        "v",
        "p",
        "sp",
        "adkim",
        "aspf",
        "fo",
        "rf",
        "ri",
        "rua",
        "ruf",
        "pct",
        "cur",
        "current_index",
        "ignored_tags",
        "original_record",
        "effective_value",
    )

    def __init__(self, original_record):
        self.v = DMARC1Tag()
        self.p = PTag()
        self.sp = SPTag()
        self.adkim = ADKIMTag()
        self.aspf = ASPFTag()
        self.fo = FOTag()
        self.rf = RFTag()
        self.ri = RITag()
        self.rua = RUATag()
        self.ruf = RUFTag()
        self.pct = PCTTag()
        self.current_index = 0
        self.ignored_tags = []
        self.original_record = original_record
        self.effective_value = None

    def __getitem__(self, item: Union[str, DmarcTag]) -> Optional[TDmarcAttr]:
        if not hasattr(self, item):
            raise DmarcParserException("this tag does not exist in DMARC")
        else:
            return getattr(self, item)

    def validate(self):
        pass


ABNF_to_option = {
    "dmarc-version": DMARC1Tag.name(),
    "dmarc-request": PTag.name(),
    "dmarc-srequest": SPTag.name(),
    "dmarc-adkim": ADKIMTag.name(),
    "dmarc-aspf": ASPFTag.name(),
    "dmarc-rfmt": RFTag.name(),
    "dmarc-ainterval": RITag.name(),
    "dmarc-percent": PCTTag.name(),
    "dmarc-fo": FOTag.name(),
    "dmarc-auri": RUATag.name(),
    "dmarc-furi": RUFTag.name(),
}


class DmarcParser:
    def __init__(self):
        self.tag_grammar: Grammar = load_grammar(GrammarType.DKIM_TAG_LIST_ABNF)
        self.dmarc_grammar: Grammar = load_grammar(GrammarType.DMARC_ABNF)

    @staticmethod
    def extract_value(apg_res):
        phrase_index = apg_res["phrase_index"]
        phrase_length = apg_res["phrase_length"]
        value = apg_res["input"][phrase_index : phrase_index + phrase_length]
        str_val = apg_util.tuple_to_string(value)
        return str_val

    @staticmethod
    def _parser_cb(res, tag_list: list):
        if res["state"] == MATCH:
            value = DmarcParser.extract_value(res)
            tag_list.append(value)

    def _check_tag_list_syntax(self, record: str):
        tag_list = []
        tag_spec_list = []
        tag_list_parser = APGParser(self.tag_grammar)
        tag_list_parser.add_callbacks(
            {
                "tag-spec": functools.partial(self._parser_cb, tag_list=tag_spec_list),
                "tag-name": functools.partial(self._parser_cb, tag_list=tag_list),
            }
        )
        result = tag_list_parser.parse(
            apg_util.string_to_tuple(record), start_rule="tag-list"
        )
        return result, tag_list, tag_spec_list

    def _check_tag_semantics(self, tag_list: list) -> None:
        if len(tag_list) != len(set(tag_list)):
            raise DmarcException(
                98, "record is DKIM-defined list of tags contains duplicate tags"
            )

    @staticmethod
    def retrieve_mail_list(tag_value: str) -> Tuple[List[EmailObj], List[str]]:
        values = tag_value.split(",")
        values = [value.strip(";") for value in values]
        valid_mailto = []
        other_uris = []
        for value in values:
            if value.startswith("mailto:"):
                limit_in_byte = None
                limit_org = None
                match = SIZE_LIMIT_REGEX.search(value)
                if match is not None:
                    email = value[: match.start()]
                    limit_org = value[match.start() + 1 :]
                    limit = match.groupdict().get("limit", None)
                    if limit is None:
                        # should never happen
                        limit = 0
                    int_limit = int(limit)
                    byte_char = match.groupdict().get("mult_byte", None)
                    byte_char = CHAR_TO_BYTE_MAP.get(byte_char, 1)
                    limit_in_byte = int_limit * byte_char
                else:
                    email = value
                if email.startswith("mailto:"):
                    email = email[len("mailto:") :]
                if validators.email(email) is True:
                    valid_mailto.append(
                        EmailObj(
                            email=email.strip(),
                            limit=limit_in_byte,
                            limit_org=limit_org,
                        )
                    )
                else:
                    other_uris.append(value)
            else:
                other_uris.append(value)
        return valid_mailto, other_uris

    def _process(self, dmarc_tag_parsed: list, dmarc_obj: DmarcObject):
        for i, (abnf_tag_name, tag_value) in enumerate(dmarc_tag_parsed):
            tag_name = ABNF_to_option.get(abnf_tag_name, None)
            if tag_name is None:
                # should never happen
                raise DmarcException(99, f"non existent DMARC tag {abnf_tag_name}")
            tag_obj = dmarc_obj[tag_name]
            if tag_obj is None:
                # should never happen
                raise DmarcException(99, f"non existent DMARC tag {abnf_tag_name}")

            num_skip_chars = len(tag_obj.name()) + 1
            stripped_value = tag_value[num_skip_chars:].lower()
            if isinstance(tag_obj, FOTag):
                fo_params = {param for param in stripped_value.split(":")}
                sorted_fo_options = list(sorted(fo_params))
                tag_obj.value = sorted_fo_options
            elif isinstance(tag_obj, RUFTag) or isinstance(tag_obj, RUATag):
                valid_mailto, other_uris = self.retrieve_mail_list(stripped_value)
                tag_obj.valid.extend(valid_mailto)
                tag_obj.other.extend(other_uris)

            elif isinstance(tag_obj, RITag) or isinstance(tag_obj, PCTTag):
                tag_obj.value = int(stripped_value)
            else:
                tag_obj.value = stripped_value
            tag_obj.index = i
        return dmarc_obj

    @staticmethod
    def _dmarc_tag_handler(res, abnf_tag_name: str, dmarc_tag_parsed: list):
        if res["state"] == MATCH:
            value = DmarcParser.extract_value(res)
            dmarc_tag_parsed.append((abnf_tag_name, value))

    def _check_dmarc_syntax(
        self, tag_list: list, tag_spec_list: list, original_record: str
    ):
        dmarc_tag_parsed = []
        dmarc_parser = APGParser(self.dmarc_grammar)
        dmarc_obj = DmarcObject(original_record=original_record)
        accepted_tags = []
        for tag, tag_value in zip(tag_list, tag_spec_list):
            stripped = SKIP_WSP_REGEX.sub("", tag_value)
            if tag.lower() in VALID_DMARC_TAGS_SET:
                accepted_tags.append(stripped)
            else:
                dmarc_obj.ignored_tags.append(stripped)
        effective_value = "".join(f"{accepted};" for accepted in accepted_tags)
        dmarc_obj.effective_value = effective_value
        cb_dict = {
            abnf_tag_name: functools.partial(
                self._dmarc_tag_handler,
                abnf_tag_name=abnf_tag_name,
                dmarc_tag_parsed=dmarc_tag_parsed,
            )
            for abnf_tag_name in ABNF_to_option.keys()
        }
        dmarc_parser.add_callbacks(cb_dict)
        result = dmarc_parser.parse(
            apg_util.string_to_tuple(effective_value), start_rule="dmarc-record"
        )
        return result, dmarc_tag_parsed, dmarc_obj

    def _dmarc_semantic_check(self, dmarc_obj: DmarcObject, follow_downgrade: bool):
        if dmarc_obj.v.index != 0:
            # should never happen thanks to abnf
            raise DmarcException(97, "version must appear as the first tag")

        if not dmarc_obj.p.provided and not follow_downgrade:
            raise DmarcException(97, "p not provided")

        if dmarc_obj.p.provided and dmarc_obj.p.index != 1:
            raise DmarcException(
                97,
                f"p provided but appeared in other than second "
                f"position (i={dmarc_obj.p.index}",
            )

        if not dmarc_obj.sp.provided and dmarc_obj.p.effective_value in POLICY_VALUES:
            dmarc_obj.sp.inherited = dmarc_obj.p.effective_value

        if (
            not isinstance(dmarc_obj.pct.effective_value, int)
            or dmarc_obj.pct.effective_value < 0
            or dmarc_obj.pct.effective_value > 100
        ):
            raise DmarcException(
                95, f"pct value {dmarc_obj.pct.effective_value} is not valid"
            )

        p_provided_and_invalid = (
            dmarc_obj.p.provided and dmarc_obj.p.effective_value not in POLICY_VALUES
        )
        sp_provided_and_invalid = (
            dmarc_obj.sp.provided and dmarc_obj.sp.effective_value not in POLICY_VALUES
        )
        p_downgrade = False
        if follow_downgrade:
            if len([*dmarc_obj.rua.valid, *dmarc_obj.rua.other]) >= 1:
                if not dmarc_obj.p.provided or p_provided_and_invalid:
                    p_downgrade = True
                if sp_provided_and_invalid:
                    p_downgrade = True
            if p_downgrade:
                dmarc_obj.p.downgraded = True
                if not dmarc_obj.sp.provided or sp_provided_and_invalid:
                    dmarc_obj.sp.inherited = dmarc_obj.p.effective_value

        if not p_downgrade:
            if not dmarc_obj.p.provided:
                raise DmarcException(
                    99, "Even if downgraded is true, p value was missing and no rua."
                )
            if p_provided_and_invalid:
                raise DmarcException(99, f"p value was {dmarc_obj.sp.effective_value}")
            elif sp_provided_and_invalid:
                raise DmarcException(99, f"sp value was {dmarc_obj.sp.effective_value}")

    def parse(self, record: str, follow_downgrade: bool = True) -> DmarcObject:
        tag_result, tag_list, tag_spec_list = self._check_tag_list_syntax(record)
        if tag_result.success:
            self._check_tag_semantics(tag_list)
            dmarc_result, dmarc_tag_parsed, dmarc_obj = self._check_dmarc_syntax(
                tag_list, tag_spec_list, record
            )
            if dmarc_result.success:
                self._process(dmarc_tag_parsed, dmarc_obj)
                self._dmarc_semantic_check(dmarc_obj, follow_downgrade)
                return dmarc_obj
            else:
                raise DmarcException(
                    98,
                    "record is DKIM-defined list of tags but not a valid DMARC record",
                )

        else:
            raise DmarcException(99, "record is not DKIM-defined list of tags")
