import sys
import threading
import _thread

def quit_function(fn_name):
    print('{0} took too long'.format(fn_name), file=sys.stderr)
    _thread.interrupt_main()

def timeout(s):
    """
    use as decorator to exit process if 
    function takes longer than s seconds
    """
    def outer(fn):
        def inner(*args, **kwargs):
            timer = threading.Timer(s, quit_function, args=[fn.__name__])
            timer.start()
            try:
                result = fn(*args, **kwargs)
            finally:
                timer.cancel()
            return result
        return inner
    return outer
