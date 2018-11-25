#!/bin/env python3
import sys
from os.path import (
    dirname,
    abspath,
    join, isdir)
from shutil import rmtree
from tempfile import mkdtemp

from plumbum import local

host_haka_dir = abspath(dirname(__file__))
docker = local['docker']
git = local['git']


def run_cmd(image_id, host_haka_dir, container_haka_dir, cmd):
    container_id = docker('create', image_id, *cmd).strip()
    try:
        print('Created {container_id} from image {image_id}'.format(container_id=container_id, image_id=image_id))
        docker('cp', host_haka_dir, '{}:{}'.format(container_id, container_haka_dir))
        print('Cloned haka to {container_id}:{container_haka_dir}'.format(container_id=container_id,
                                                                           container_haka_dir=container_haka_dir))
        print('Running container', container_id)
        proc = docker.popen(args=['start', '-a', container_id], stdout=sys.stdout, stderr=sys.stderr)
        rc = proc.wait()
        print('Return code', rc)
    finally:
        print('Removing container id {}.'.format(container_id))
        docker('rm', container_id)

    return rc


def main():
    images = [
        'python:2.7-alpine3.8',
        'python:3.4',
        'python:3.5',
        'python:3.6-alpine3.8',
        'python:3.7-alpine3.8',
    ]

    return_codes = []
    container_haka_dir= '/mqtt-codec'

    temp_host_haka_dir = mkdtemp()
    assert isdir(temp_host_haka_dir)
    try:
        git('clone', host_haka_dir, temp_host_haka_dir)
        print('Cloned {} into {}.'.format(host_haka_dir, temp_host_haka_dir))
        for image in images:
            print(50 * '*')
            return_codes.append(run_cmd(image, temp_host_haka_dir, container_haka_dir,
                                        ['python', join(container_haka_dir, 'setup.py'), 'test']))
            return_codes.append(run_cmd(image, temp_host_haka_dir, container_haka_dir,
                                        ['pip', 'install', container_haka_dir]))
    finally:
        print('Removing temp directory {}.'.format(temp_host_haka_dir))
        rmtree(temp_host_haka_dir)

    if any(return_codes):
        num_okay = len(rc for rc in return_codes if rc)
        num_fail = len(return_codes) - num_okay
        print('! {} okay, {} fail'.format(num_okay, num_fail))
    else:
        print('> {}/{} okay.'.format(len(return_codes), len(return_codes)))


if __name__ == '__main__':
    main()
