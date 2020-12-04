from flask import Flask, request
import sys

app = Flask(__name__)

# Setup a command route to listen for prefix advertisements
@app.route('/', methods=['POST'])
def run_command():
    command = request.form['command']
    sys.stdout.write('%s\n' % command)
    sys.stdout.flush()
    return 'OK\n'

if __name__ == '__main__':
    app.run(port=sys.argv[1])

