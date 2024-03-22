import requests
import os

VMESSY_HOST = os.environ.get("VMESSY_HOST", "localhost")
VMESSY_PORT = 1090

def test_basic_response():
    response = requests.get('http://google.com', allow_redirects=False, proxies={
        'http': f'http://{VMESSY_HOST}:{VMESSY_PORT}',
    }).text

    expected = ('<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n'
                '<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n'
                '<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
    assert response == expected

