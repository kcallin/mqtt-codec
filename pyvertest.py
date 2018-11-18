#!/bin/env python3
import sys
from os.path import (
    dirname,
    abspath,
    join)
from plumbum import local


host_root = abspath(dirname(__file__))
docker = local['docker']


images = [
    'python:2.7-alpine3.8',
    'python:3.4',
    'python:3.5',
    'python:3.6-alpine3.8',
    'python:3.7-alpine3.8',
]


return_codes = []
image_root='/mqtt-codec'
for image in images:
    volume_param = '{host_root}:{image_root}'.format(host_root=host_root, image_root=image_root)
    print(50*'*')
    print('Test on image', image)
    params = ['run', '--rm', '-v', volume_param, image,
              'python', join(image_root, 'setup.py'), 'clean', '--all', 'test']
    print('docker', ' '.join(params))
    proc = docker.popen(args=params, stdout=sys.stdout, stderr=sys.stderr)
    rc = proc.wait()
    return_codes.append(rc)
    print('Return code', rc)

for image in images:
    volume_param = '{host_root}:{image_root}'.format(host_root=host_root, image_root=image_root)
    print('pip install', image)
    params = ['run', '--rm', '-v', volume_param, image, 'pip', 'install', image_root]
    print('docker', ' '.join(params))
    proc = docker.popen(args=params, stdout=sys.stdout, stderr=sys.stderr)
    rc = proc.wait()
    return_codes.append(rc)
    print('Return code', rc)

if any(return_codes):
    print('! There were failures.')
else:
    print('> All okay.')
