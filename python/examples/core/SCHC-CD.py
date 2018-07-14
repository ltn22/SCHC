import os
import sys
sys.path.insert(0, '../../SCHC')

import getopt
from flask import Flask
from flask import request
from flask import Response
import base64
import pprint
import BitBuffer
import RuleMngt
import Parser

app = Flask(__name__)

app.debug = True


@app.route('/', methods=['POST'])
def get_from_LNS():

    fromGW = request.get_json(force=True)

    if "data" in fromGW:
        payload = base64.b64decode(fromGW["data"])
        print (payload)

        answer = {
          "fport" : 2,
          "devEUI": fromGW["devEUI"],
          "data"  : base64.b64encode(b"Pleased to meet you")
        }

        resp = Response(answer, status=200, mimetype="application/json")
        print (resp)
        return resp

if __name__ == '__main__':
    print (sys.argv)

    defPort=7009
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hp:",["port="])
    except getopt.GetoptError:
        print ("{0} -p <port> -h".format(sys.argv[0]))
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h':
            print ("{0} -p <port> -h".format(sys.argv[0]))
            sys.exit()
        elif opt in ("-p", "--port"):
            defPort = int(arg)

            
    app.run(host="0.0.0.0", port=defPort)