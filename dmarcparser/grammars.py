import enum
from functools import lru_cache

from apg_py.api.api import Api

core_rules = [
    "ALPHA          =  %x41-5A / %x61-7A",
    'BIT            =  "0" / "1"',
    "CHAR           =  %x01-7F",
    "CR             =  %x0D",
    "CRLF           =  CR LF",
    "CTL            =  %x00-1F / %x7F",
    "DIGIT          =  %x30-39",
    "DQUOTE         =  %x22",
    'HEXDIG         =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"',
    "HTAB           =  %x09",
    "LF             =  %x0A",
    "LWSP           =  *(WSP / CRLF WSP)",
    "OCTET          =  %x00-FF",
    "SP             =  %x20",
    "VCHAR          =  %x21-7E",
    "WSP            =  SP / HTAB",
]

# Original tag-list  is 'tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]'
# However, RFC 6376
dkim_grammar = [
    'tag-list  =  tag-spec *( ";" tag-spec ) [ ";" *WSP] ',
    'tag-spec  =  [FWSDKIM] tag-name [FWSDKIM] "=" [FWSDKIM] tag-value [FWSDKIM]',
    "tag-name  =  ALPHA *ALNUMPUNC",
    "tag-value =  [ tval *( 1*(WSP / FWSDKIM) tval ) ]",
    "tval      =  1*VALCHAR",
    "VALCHAR   =  %x21-3A / %x3C-7E",
    'ALNUMPUNC =  ALPHA / DIGIT / "_"',
    "FWSDKIM =   [*WSP CRLF] 1*WSP",
]

rfc3986_grammar = [
    'URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]',
    'hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty',
    "URI-reference = URI / relative-ref",
    'absolute-URI = scheme ":" hier-part [ "?" query ]',
    'relative-ref = relative-part [ "?" query ] [ "#" fragment ]',
    'relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty',
    'scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )',
    'authority = [ userinfo "@" ] host [ ":" port ]',
    'userinfo = *( unreserved / pct-encoded / sub-delims / ":" )',
    "host = IP-literal / IPv4address / reg-name",
    "port = *DIGIT",
    'IP-literal = "[" ( IPv6address / IPvFuture ) "]"',
    'IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )',
    'IPv6address = 6( h16 ":" ) ls32 / "::" 5( h16 ":" ) ls32 / [ h16 ] "::" 4( h16 ":" ) ls32 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32 / [ *3( h16 ":" ) h16 ] "::" h16 ":" ls32 / [ *4( h16 ":" ) h16 ] "::" ls32 / [ *5( h16 ":" ) h16 ] "::" h16 / [ *6( h16 ":" ) h16 ] "::"',
    "h16 = 1*4HEXDIG",
    'ls32 = ( h16 ":" h16 ) / IPv4address',
    'IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet',
    # alternatives reordered for correct matching.
    'dec-octet = "25" %x30-35 / "2" %x30-34 DIGIT / "1" 2DIGIT / %x31-39 DIGIT / DIGIT',
    "reg-name = *( unreserved / pct-encoded / sub-delims )",
    "path = path-abempty / path-absolute / path-noscheme / path-rootless / path-empty",
    'path-abempty = *( "/" segment )',
    'path-absolute = "/" [ segment-nz *( "/" segment ) ]',
    'path-noscheme = segment-nz-nc *( "/" segment )',
    'path-rootless = segment-nz *( "/" segment )',
    'path-empty = ""',
    "segment = *pchar",
    "segment-nz = 1*pchar",
    'segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )',
    'pchar = unreserved / pct-encoded / sub-delims / ":" / "@"',
    'query = *( pchar / "/" / "?" )',
    'fragment = *( pchar / "/" / "?" )',
    'pct-encoded = "%" HEXDIG HEXDIG',
    'unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"',
    "reserved = gen-delims / sub-delims",
    'gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"',
    # removed semicolon to be compatible with DKIM tag-list:
    # https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
    # Unencoded semicolon (";") characters MUST NOT occur in
    # the tag value, since that separates tag-specs.
    'sub-delims = "!" / "$" / "&" / "\'" / "(" / ")" / "*" / "+" / "," / "="',
]

rfc7489_grammar = [
    *core_rules,
    *rfc3986_grammar,
    *dkim_grammar,
    # 'URI = %x6D %x61 %x69 %x6C %x74 %x6F %x3A addr-spec',
    'dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]',
    'dmarc-version = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31',
    "dmarc-sep = *WSP %x3b *WSP",
    'dmarc-request = "p" *WSP "=" *WSP tag-value',
    'dmarc-srequest  = "sp" *WSP "=" *WSP tag-value',
    'dmarc-auri = "rua" *WSP "=" *WSP dmarc-uri *(*WSP "," *WSP dmarc-uri)',
    'dmarc-furi  = "ruf" *WSP "=" *WSP dmarc-uri *(*WSP "," *WSP dmarc-uri)',
    'dmarc-adkim = "adkim" *WSP "=" *WSP ( "r" / "s" )',
    'dmarc-aspf = "aspf" *WSP "=" *WSP ( "r" / "s" )',
    'dmarc-ainterval = "ri" *WSP "=" *WSP 1*DIGIT',
    'dmarc-fo = "fo" *WSP "=" *WSP ( "0" / "1" / "d" / "s" ) *(*WSP ":" *WSP ( "0" / "1" / "d" / "s" ))',
    # Keyword for 'rf' in the rfc are only limited to afrf 'dmarc-rfmt = "rf"  *WSP "=" *WSP Keyword *(*WSP ":" Keyword)',
    'dmarc-rfmt = "rf"  *WSP "=" *WSP "afrf"',
    # Originally 'dmarc-percent = "pct" *WSP "=" *WSP 1*3DIGIT'. 'pct=999' is following the grammar, but it is wrong
    # 'dmarc-percent = "pct" *WSP "=" *WSP ( "100" / 1*2DIGIT / "0" )',
    'dmarc-percent = "pct" *WSP "=" *WSP 1*3DIGIT',
    "dmarc-record = dmarc-version *(dmarc-sep ( dmarc-request / dmarc-srequest / dmarc-auri / dmarc-furi / dmarc-aspf / dmarc-adkim / dmarc-aspf / dmarc-ainterval / dmarc-fo / dmarc-percent / dmarc-rfmt)) [ dmarc-sep ]",
]


class GrammarType(enum.Enum):
    DKIM_TAG_LIST_ABNF = "tag-list"
    DMARC_ABNF = "dmarc"


def _load_tag_grammar():
    return "\n".join([*core_rules, *dkim_grammar]) + "\n"


def _load_dmarc_grammar():
    return "\n".join(rfc7489_grammar) + "\n"


def generate_parser(grammar: str):
    grammar_api = Api()
    grammar_obj = grammar_api.generate(grammar)
    # print()
    assert (
        len(grammar_api.errors) == 0
    ), f"errors found in grammar: {grammar_api.display_errors()}, contact maintainers"
    return grammar_obj


@lru_cache
def load_grammar(grammar_type: GrammarType):
    return _generate_grammar(grammar_type)


def _generate_grammar(grammar_type):
    if grammar_type == GrammarType.DMARC_ABNF:
        abnf_str = _load_dmarc_grammar()
    elif grammar_type == GrammarType.DKIM_TAG_LIST_ABNF:
        abnf_str = _load_tag_grammar()
    else:
        raise Exception(f"unknown grammar type {grammar_type}")
    grammar = generate_parser(abnf_str)
    return grammar
