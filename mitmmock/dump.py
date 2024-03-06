import json

from collections.abc import Iterable

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow
from mitmproxy.addonmanager import Loader


def decode_bytes_in_state(obj: dict):
    def decode_value(value):
        if type(value) == bytes:
            return value.decode()
        if type(value) != str and isinstance(value, Iterable):
            return [decode_value(v) for v in value]
        return value
    return {k: decode_value(v) for k, v in obj.items()}


class MitmMockConfigDump:
    def __init__(self):
        self.chain = []

    def load(self, loader: Loader):
        loader.add_option(
            name='mitmmock_dump',
            typespec=str,
            default='mitmmock.dump.json',
            help='File to serialize flows'
        )

    def request(self, flow: HTTPFlow):
        self.chain.append(
            {'Request': decode_bytes_in_state(flow.request.get_state())}
        )

    def response(self, flow: HTTPFlow):
        self.chain.append(
            {'Response': decode_bytes_in_state(flow.response.get_state())}
        )

    def done(self):
        with open(ctx.options.mitmmock_dump, 'w') as f:
            header = r'''{{def(__left__, __right__)}}
{{if False}}
    This is comment block.
    Requests, for now, displayed here only as context for the user.

    MitmMock execution is splitted in two parts:
        - load time -- preprocessing of json
        - runtime -- processing of json keys/values

    To modify responses in load time, you can use preppy as it stated
    in preppy's documentation (see https://preppy.readthedocs.io)

    To modify responses in runtime, you should use functions defined
    below:
        - runtime escapes expression, so it would not affect preppy
        in the load time
        - imp escapes `import` template, so it would not affect preppy
        in the load time

    Also, current request is exported to this environment as {{Request}}
    dictionary and request from the mitmmock file is exported as {{SRequest}}.
{{endif}}

{{def runtime_def(args)}}{{__left__}}{{__def__}}(args){{__right__}}{{enddef}}
{{def runtime(expr)}}{{__left__}}{{expr}}{{__right__}}{{enddef}}
{{def imp(module)}}{{__left__}}import {{module}}{{__right__}}{{enddef}}
'''
            f.write(header)
            f.write(json.dumps(self.chain, indent=2))


addons = [MitmMockConfigDump()]
