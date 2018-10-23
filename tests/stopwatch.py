from time import time


class Stopwatch(object):
    def __init__(self):
        self.__start_time = None
        self.__stop_time = None

    def __enter__(self):
        self.__start_time = time()
        return self

    def elapsed(self):
        if self.__start_time is not None:
            stop_time = self.__stop_time
            if stop_time is None:
                stop_time = time()
            rv = stop_time - self.__start_time
        else:
            rv = None

        return rv

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__stop_time = time()
        return False
