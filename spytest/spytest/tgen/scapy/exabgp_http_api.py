from flask import Flask, request  # pylint: disable=import-error
import sys

app = Flask(__name__)

# Setup a command route to listen for prefix advertisements


@app.route('/', methods=['POST'])
def run_command():
    # nosemgrep-next-line
    sys.stdout.write('%s\n' % request.form['command'])
    sys.stdout.flush()
    return 'OK\n'


if __name__ == '__main__':
    app.run(port=sys.argv[1])
