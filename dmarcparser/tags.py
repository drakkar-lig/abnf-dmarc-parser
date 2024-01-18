from typing import List, Generic, TypeVar, Union, Optional

TTag = TypeVar("TTag", str, None, int, List[str])


class DmarcTag(Generic[TTag]):
    _name: str
    _default_value: TTag
    _optional: bool

    def __init__(self, value: Union[TTag, None] = None):
        self._value = value
        self.index = None

    @classmethod
    def default_value(cls) -> TTag:
        return cls._default_value

    @property
    def effective_value(self) -> TTag:
        if self._value is None:
            return self._default_value
        else:
            return self._value

    def to_tag(self):
        str_val = self.value_to_str()
        if str_val is None:
            return ""
        return f"{self.name()}={str_val};"

    def value_to_str(self):
        return str(self.effective_value)

    @classmethod
    def name(cls) -> str:
        return cls._name

    @classmethod
    def optional(cls) -> bool:
        return cls._optional

    @property
    def value(self) -> Union[TTag, None]:
        return self._value

    @value.setter
    def value(self, value: Union[TTag, None]):
        self._value = value

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, index: int):
        self._index = index

    @property
    def provided(self) -> bool:
        return self._value is not None

    def provided_same_as_default(self) -> bool:
        if not self.provided:
            return True
        else:
            return self.default_value() == self.value


class OptionalDmarcTag(DmarcTag[TTag]):
    _optional = True


class RequiredDmarcTag(DmarcTag[TTag]):
    _optional = False


class DMARC1Tag(RequiredDmarcTag[str]):
    _name = "v"

    def __str__(self):
        return "v=DMARC1"

    @property
    def effective_value(self) -> str:
        return "DMARC1"


class PTag(RequiredDmarcTag[str]):
    _name = "p"
    _default_value = "none"

    def __init__(self):
        super().__init__()
        self.downgraded = False

    @property
    def downgraded(self):
        return self._downgraded

    @downgraded.setter
    def downgraded(self, downgraded: bool):
        self._downgraded = downgraded

    @property
    def effective_value(self) -> str:
        if self.downgraded:
            return "none"
        else:
            return self.value

    def value_to_str(self):
        return self.effective_value


class SPTag(OptionalDmarcTag[str]):
    _name = "sp"
    _default_value = None

    def __init__(self):
        super().__init__()
        self.inherited = None

    @property
    def inherited(self):
        return self._inherited_value

    @inherited.setter
    def inherited(self, inherited_value: str):
        self._inherited_value = inherited_value

    @property
    def effective_value(self) -> str:
        if self.inherited is not None:
            return self.inherited
        else:
            return self.value


class ADKIMTag(OptionalDmarcTag[str]):
    _name = "adkim"
    _default_value = "r"


class ASPFTag(OptionalDmarcTag[str]):
    _name = "aspf"
    _default_value = "r"


class FOTag(OptionalDmarcTag[List[str]]):
    _name = "fo"
    _default_value = ["0"]

    def value_to_str(
        self,
    ):
        return ":".join(sorted(set(self.effective_value)))


class RFTag(OptionalDmarcTag[str]):
    _name = "rf"
    _default_value = "afrf"


class RITag(OptionalDmarcTag[int]):
    _name = "ri"
    _default_value = 86400


class EmailObj:
    def __init__(self, email: str, limit: Optional[int], limit_org: Optional[str]):
        self._email = email
        self._limit = limit
        self._limit_org = limit_org

    @property
    def email(self) -> str:
        return self._email

    @property
    def limit(self) -> Optional[int]:
        return self._limit

    @property
    def limit_org(self) -> str:
        return self._limit_org

    def __str__(self):
        if self.limit is None:
            return self.email
        else:
            return f"{self.email}!{self.limit_org}"

    def __getitem__(self, item):
        return getattr(self, item)


class RUTag(OptionalDmarcTag[List[str]]):
    _default_value = []

    def __init__(self):
        super().__init__()
        self.valid: List[EmailObj] = []
        self.other: List[str] = []

    def value_to_str(self):
        if len(self.valid) == 0:
            return None
        return ",".join(f"mailto:{value}" for value in [*self.valid, *self.other])

    @property
    def effective_value(self) -> List[Union[EmailObj, str]]:
        return [*self.valid, *self.other]


class RUATag(RUTag):
    _name = "rua"


class RUFTag(RUTag):
    _name = "ruf"


class PCTTag(OptionalDmarcTag[int]):
    _name = "pct"
    _default_value = 100


TDmarcAttr = TypeVar(
    "TDmarcAttr",
    DMARC1Tag,
    PTag,
    SPTag,
    ADKIMTag,
    ASPFTag,
    RFTag,
    RITag,
    PCTTag,
    FOTag,
    RUATag,
)
