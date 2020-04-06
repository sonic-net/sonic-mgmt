import json
import argparse
import inspect
import sonic_platform

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

platform = sonic_platform.platform.Platform()


class PlatformAPITestService(BaseHTTPRequestHandler):
    ''' Handles HTTP POST requests and translated them into platform API call.
    The expected URL path format is the following:
    1. /platform/<component_0>/<component_1>/.../<component_n>/<api>
       e.g. /platform/chassis/watchdog/get_remaining_time
    2. /platform/<component_0>/<component_1>/.../<component_n>/<index>/<api>
       e.g. /platform/chassis/sfp/0/get_voltage
    Client should also pass a JSON object in body which has an "args" key, which
    contains a list of arguments to be passed to API:
       e.g. to arm watchdog: {"args": [30]}, where 30 is a timeout passed to arm() API
    The response is a JSON object with "res" key that holds the result object returned by
    the API, e.g. arm() API of the watchdog may return a JSON {"res": 32} as response.
    This class makes several assumptions to make this as generic as possible.
    First, arguments to API and result are JSON serializable/deserializable.
    Second, to access the object by the path like in 1st example, it is assumed that
    the get_<component_1> is a method of <component_0> object.
    If the <component_n> is a list accessed by index, it is assumed that get_<component_n>
    is a method of <compoment_n-1> object which accepts "index" as parameter.
    '''

    def do_POST(self):
        if self.path.startswith('/platform/'):
            self.do_platform_api()
        else:
            return

    def do_platform_api(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        request = json.loads(body)

        path = list(reversed(self.path.strip('/').split('/')))
        if path.pop() != 'platform':
            raise Exception("invalid path " + self.path)

        obj = platform
        while len(path) != 1:
            _dir = path.pop()
            args = inspect.getargspec(getattr(obj, 'get_' + _dir)).args
            if 'index' in args:
                _idx = int(path.pop())
                obj = getattr(obj, 'get_' + _dir)(_idx)
            else:
                obj = getattr(obj, 'get_' + _dir)()

        api = path.pop()
        args = request['args']

        res = getattr(obj, api)(*args)

        response = BytesIO()
        response.write(json.dumps({'res': res}))

        self.wfile.write(response.getvalue())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='port to listent to', required=True)
    args = parser.parse_args()
    httpd = HTTPServer(('', args.port), PlatformAPITestService)
    httpd.serve_forever()
