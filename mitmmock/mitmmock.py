import json

import preppy

from collections.abc import Iterable

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow, Response, Headers
from mitmproxy.addonmanager import Loader


class MitmMock:
    def __init__(self):
        self.chain = []

    def load(self, loader: Loader):
        loader.add_option(
            name='mitmmock_dump',
            typespec=str,
            default='mitmmock.dump.json',
            help='File to load serialized flows'
        )

    def configure(self, updates: set):
        if 'mitmmock_dump' in updates:
            self.mitmmock_dump_path = ctx.options.mitmmock_dump
            with open(self.mitmmock_dump_path, 'r') as mitmmockflows:
                self.mitmmockflows_raw = mitmmockflows.read()

            self.initial_prep = preppy.getModule('mitmmock',
                                                 sourcetext=self.mitmmockflows_raw,
                                                 source_extension=None)
            self.initial_json = self.initial_prep.get('{{', '}}')
            self.chain = json.loads(self.initial_json)
            self.requests = [e['Request'] for e in self.chain if 'Request' in e]
            self.responses = [e['Response'] for e in self.chain if 'Response' in e]
            self.ptr = 0

    def eval_preppy_value(self, value, idx: int = None):
        request_obj = {} if idx is None else {'Request': self.requests[idx]}
        if type(value) == str:
            return preppy.getModule('mm_part',
                                    sourcetext=value,
                                    source_extension=None).getOutput(request_obj)
        if type(value) != str and isinstance(value, Iterable):
            return [self.eval_preppy_value(v, idx) for v in value]
        return value

    def eval_preppy(self, obj: dict, idx: int = None):
        return {self.eval_preppy_value(k, idx): self.eval_preppy_value(v, idx)
                for k, v in obj.items()}

    def request(self, flow: HTTPFlow):
        saved_resp = self.responses[self.ptr]
        headers = Headers()
        for k, v in saved_resp['headers']:
            headers[self.eval_preppy_value(k, self.ptr)] = self.eval_preppy_value(v, self.ptr)
        saved_resp['headers'] = headers

        flow.response = Response.make(status_code=saved_resp['status_code'],
                                      content=saved_resp['content'],
                                      headers=saved_resp['headers'])
        flow.is_replay = "response"
        self.ptr += 1
        self.ptr %= len(self.responses)


addons = [MitmMock()]
