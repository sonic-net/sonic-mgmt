import json
import inspect
import sonic_platform

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

PLATFORM_TEST_SERVICE_PORT = 8000

platform = sonic_platform.platform.Platform()


class PlatformAPITestService(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path.startswith('/platform/'):
            self.do_platform_api()
        else:
            return

    def do_platform_api(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        request = json.loads(body)

        # /platform/<component_0>/<component_1>/.../<component_n>/<api>
        # /platform/<component_0>/<component_1>/.../<component_n>/<index>/<api>

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
    httpd = HTTPServer(('', PLATFORM_TEST_SERVICE_PORT), PlatformAPITestService)
    httpd.serve_forever()

