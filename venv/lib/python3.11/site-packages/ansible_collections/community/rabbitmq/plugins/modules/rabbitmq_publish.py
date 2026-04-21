#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, John Imison <john+github@imison.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: rabbitmq_publish
short_description: Publish a message to a RabbitMQ queue.
description:
   - Publish a message on a RabbitMQ queue using a blocking connection.
options:
  url:
    description:
      - An URL connection string to connect to the RabbitMQ server.
      - I(url) and I(host)/I(port)/I(user)/I(pass)/I(vhost) are mutually exclusive, use either or but not both.
    type: str
  proto:
    description:
      - The protocol to use.
    type: str
    choices: [amqps, amqp]
  host:
    description:
      - The RabbitMQ server hostname or IP.
    type: str
  port:
    description:
      - The RabbitMQ server port.
    type: int
  username:
    description:
      - The RabbitMQ username.
    type: str
  password:
    description:
      - The RabbitMQ password.
    type: str
  vhost:
    description:
      - The virtual host to target.
      - If default vhost is required, use C('%2F').
    type: str
  queue:
    description:
      - The queue to publish a message to.  If no queue is specified, RabbitMQ will return a random queue name.
      - A C(queue) cannot be provided if an C(exchange) is specified.
    type: str
  exchange:
    description:
      - The exchange to publish a message to.
      - An C(exchange) cannot be provided if a C(queue) is specified.
    type: str
  routing_key:
    description:
      - The routing key.
    type: str
  body:
    description:
      - The body of the message.
      - A C(body) cannot be provided if a C(src) is specified.
    type: str
  src:
    description:
      - A file to upload to the queue.  Automatic mime type detection is attempted if content_type is not defined (left as default).
      - A C(src) cannot be provided if a C(body) is specified.
      - The filename is added to the headers of the posted message to RabbitMQ. Key being the C(filename), value is the filename.
    type: path
    aliases: ['file']
  content_type:
    description:
      - The content type of the body.
    type: str
    default: text/plain
  durable:
    description:
      - Set the queue to be durable.
    type: bool
    default: False
  exclusive:
    description:
      - Set the queue to be exclusive.
    type: bool
    default: False
  auto_delete:
    description:
      - Set the queue to auto delete.
    type: bool
    default: False
  headers:
    description:
      - A dictionary of headers to post with the message.
    type: dict
    default: {}
  cafile:
    description:
      - CA file used during connection to the RabbitMQ server over SSL.
      - If this option is specified, also I(certfile) and I(keyfile) must be specified.
    type: str
  certfile:
    description:
      - Client certificate to establish SSL connection.
      - If this option is specified, also I(cafile) and I(keyfile) must be specified.
    type: str
  keyfile:
    description:
      - Client key to establish SSL connection.
      - If this option is specified, also I(cafile) and I(certfile) must be specified.
    type: str



requirements: [ pika ]
notes:
  - This module requires the pika python library U(https://pika.readthedocs.io/).
  - Pika is a pure-Python implementation of the AMQP 0-9-1 protocol that tries to stay fairly independent of the underlying network support library.
  - This module is tested against RabbitMQ. Other AMQP 0.9.1 protocol based servers may work but not tested/guaranteed.
  - The certificate authentication was tested with certificates created
    via U(https://www.rabbitmq.com/ssl.html#automated-certificate-generation) and RabbitMQ
    configuration variables C(ssl_options.verify = verify_peer) & C(ssl_options.fail_if_no_peer_cert = true).
author: "John Imison (@Im0)"
'''

EXAMPLES = r'''
- name: Publish to an exchange
  community.rabbitmq.rabbitmq_publish:
    exchange: exchange1
    url: "amqp://guest:guest@192.168.0.32:5672/%2F"
    body: "Hello exchange from ansible module rabbitmq_publish"
    content_type: "text/plain"

- name: Publish to an exchange with routing_key
  community.rabbitmq.rabbitmq_publish:
    exchange: exchange1
    routing_key: queue1
    url: "amqp://guest:guest@192.168.0.32:5672/%2F"
    body: "Hello queue via exchange routing_key from ansible module rabbitmq_publish"
    content_type: "text/plain"

- name: Publish a message to a queue with headers
  community.rabbitmq.rabbitmq_publish:
    url: "amqp://guest:guest@192.168.0.32:5672/%2F"
    queue: 'test'
    body: "Hello world from ansible module rabbitmq_publish"
    content_type: "text/plain"
    headers:
      myHeader: myHeaderValue

- name: Publish a file to a queue
  community.rabbitmq.rabbitmq_publish:
    url: "amqp://guest:guest@192.168.0.32:5672/%2F"
    queue: 'images'
    file: 'path/to/logo.gif'

- name: RabbitMQ auto generated queue
  community.rabbitmq.rabbitmq_publish:
    url: "amqp://guest:guest@192.168.0.32:5672/%2F"
    body: "Hello world random queue from ansible module rabbitmq_publish"
    content_type: "text/plain"

- name: Publish with certs
  community.rabbitmq.rabbitmq_publish:
    url: "amqps://guest:guest@192.168.0.32:5671/%2F"
    body: "Hello test queue from ansible module rabbitmq_publish via SSL certs"
    queue: 'test'
    content_type: "text/plain"
    cafile: 'ca_certificate.pem'
    certfile: 'client_certificate.pem'
    keyfile: 'client_key.pem'

'''

RETURN = r'''
result:
  description:
    - If posted to an exchange, the result contains the status I(msg), content type I(content_type) the exchange name I(exchange)
    - and the routing key I(routing_key).
    - If posted to a queue, the result contains the status I(msg), content type I(content_type) and the queue name I(queue).
  returned: success
  type: dict
  sample: |
    'result': { 'content_type': 'text/plain', 'msg': 'Successfully published to queue test', 'queue': 'test' }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.rabbitmq.plugins.module_utils.rabbitmq import RabbitClient


def main():
    argument_spec = RabbitClient.rabbitmq_argument_spec()
    argument_spec.update(
        exchange=dict(type='str'),
        routing_key=dict(type='str', required=False, no_log=False),
        body=dict(type='str', required=False),
        src=dict(aliases=['file'], type='path', required=False),
        content_type=dict(default="text/plain", type='str'),
        durable=dict(default=False, type='bool'),
        exclusive=dict(default=False, type='bool'),
        auto_delete=dict(default=False, type='bool'),
        headers=dict(default={}, type='dict'),
        cafile=dict(type='str', required=False),
        certfile=dict(type='str', required=False),
        keyfile=dict(type='str', required=False, no_log=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['body', 'src'], ['queue', 'exchange']],
        required_together=[['cafile', 'certfile', 'keyfile']],
        supports_check_mode=False
    )

    rabbitmq = RabbitClient(module)

    if rabbitmq.basic_publish():
        rabbitmq.close_connection()
        if (rabbitmq.queue is not None):
            module.exit_json(changed=True, result={"msg": "Successfully published to queue %s" % rabbitmq.queue,
                             "queue": rabbitmq.queue, "content_type": rabbitmq.content_type}
                             )
        elif (rabbitmq.exchange is not None):
            module.exit_json(changed=True, result={"msg": "Successfully published to exchange %s" % rabbitmq.exchange,
                             "routing_key": rabbitmq.routing_key, "exchange": rabbitmq.exchange, "content_type": rabbitmq.content_type}
                             )

    else:
        rabbitmq.close_connection()
        if (rabbitmq.queue is not None):
            module.fail_json(changed=False, msg="Unsuccessful publishing to queue %s" % rabbitmq.queue)
        elif (rabbitmq.exchange is not None):
            module.fail_json(changed=False, msg="Unsuccessful publishing to exchange %s" % rabbitmq.exchange)


if __name__ == '__main__':
    main()
