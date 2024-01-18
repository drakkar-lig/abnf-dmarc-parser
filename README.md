# dmarcparser

`dmarcparser` parses a TXT resource record and determines whether it contains a valid DMARC record including syntax and semantics validation. 
The syntax parser is built on top of the [apg-py](https://github.com/ldthomas/apg-py) library for parsing ABNF and the ABNF grammar defined in 
RFCs [7489](https://datatracker.ietf.org/doc/html/rfc7489),
[6376](https://datatracker.ietf.org/doc/html/rfc6376),
[3986](https://datatracker.ietf.org/doc/html/rfc3986).
The semantics validation follows the specification from the DMARC [RFC7489](https://datatracker.ietf.org/doc/html/rfc7489) such 
as tag default values, ignoring unknown tags, the `sp` inheritance, 
or `p`-downgrade in the case of a valid `rua` tag present in the record. In case of a valid DMARC record, the result 
object contains the parsed (understood) values following the specification.

## Install :

``` 
pip install git+https://github.com/anonymous-deposit/abnf-dmarc-parser-pam
```

## Usage

Parsing a valid DMARC record: 
```python
from dmarcparser import DmarcParser

dmarc_record = "v=DMARC1; p=reject; rua=mailto:bob@example.com; ruf=mailto:bob@example.com; fo=0; adkim=r; aspf=r"
parser = DmarcParser()
result = parser.parse(dmarc_record, follow_downgrade=True)

assert result.v.effective_value == "DMARC1"
assert result.p.effective_value == "reject"
assert result.sp.effective_value == "reject"
assert result.rua.valid[0]['email'] == "bob@example.com"
```

Parsing an invalid DMARC record raises an exception containing an error code an explanation:
```python
from dmarcparser import DmarcParser, DmarcException

dmarc_record = "v=DMARC1; p=invalidstring;"
parser = DmarcParser()
try:
    result = parser.parse(dmarc_record, follow_downgrade=True)
except DmarcException as e:
    print(f"error in DMARC record: {e.value}")
```

