import re
import shlex
import string


def test_encode_shell():
    a = shlex.split(encode_shell(["a", "b", "c"]))
    assert a == ["a", "b", "c"]
    a = shlex.split(encode_shell(["\\a", "!b", "\tc"]))
    assert a == ["\\a", "!b", "\tc"]
    a = shlex.split(encode_shell(["\\a \tc"]))
    assert a == ["\\a \tc"]
    a = shlex.split(encode_shell(["\"'"]))
    assert a == ["\"'"], repr(a)
    a = shlex.split(encode_shell(['"abc']))
    assert a == ['"abc']
    a = shlex.split(encode_shell(["'abc\""]))
    assert a == ["'abc\""]
    a = shlex.split("--test=\"masala chicken\" --test='chicken masala'")
    assert a == ["--test=masala chicken", "--test=chicken masala"]
    a = encode_shell(["--test=masala chicken", "--test=chicken masala"])
    assert a == "--test='masala chicken' --test='chicken masala'"


# The opposite of shlex.split(). It doesn't matter how the stuff is
# going to be encoded, as long as shlex() and potentially bash will
# parse it the same way. With regard to tabs and special chars we
# kindof lost, as passing them via bash is hard. But we should make
# sure at least quotes and spaces work as intended.
#
# Thre is a special exception for parsing --param=argument syntax.
# Although technicall sound, most likely you don't want to encode it
# like that: ' "--param=the argument" ', you most likely want:
# '--pram="the argument"', so there's an exception for it.

PARAM = re.compile("^--(?P<opt>[a-z_-]+)[ =](?P<rest>.*)$")
ACCEPTABLE_CHARS = set(string.printable) - \
    set(string.whitespace) - set("'\"\\&#!`()[]{}$|")


def encode_shell(params):
    r"""
    >>> test_encode_shell()
    """
    s = []
    for token in params:
        m = PARAM.match(token)
        if m:
            m = m.groupdict()
            token = m["rest"]
        if not set(token) - ACCEPTABLE_CHARS:
            enc_token = token
        else:
            if "'" not in token:
                enc_token = "'" + token + "'"
            else:
                t = token.replace("`", "\\`").replace('"', '\\"')
                enc_token = '"' + t + '"'
        if not m:
            s.append(enc_token)
        else:
            s.append("--%s=%s" % (m["opt"], enc_token))
    return " ".join(s)
