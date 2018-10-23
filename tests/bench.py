from __future__ import print_function
from mqtt_codec import packet
from tests.stopwatch import Stopwatch


def bench_mqtt_connect_init(iterations=1000000):
    for i in xrange(0, iterations):
        packet.MqttConnect('client_id', False, 15000, username='username', password='password',
                           will=packet.MqttWill(0, 'topic', 'message', True))

def main():
    stopwatch = Stopwatch()

    with stopwatch:
        bench_mqtt_connect_init()

    print('bench_mqtt_connect_init', stopwatch.elapsed())


if __name__ == '__main__':
    main()
