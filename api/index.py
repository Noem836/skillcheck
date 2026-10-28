import urllib.parse

import server

server.Handler.store = server.make_store(":memory:")


class handler(server.Handler):
    def parse_request(self):
        valid = super().parse_request()
        if valid:
            marker = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("__skillcheck_path")
            if marker and marker[0].startswith("/"):
                self.path = marker[0]
        return valid
