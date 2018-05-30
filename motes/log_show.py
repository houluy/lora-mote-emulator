# from colorline import cprint
# from functools import partial
# colorprint = partial(cprint, color='r', bcolor='k')
# colorprint = print


class LogShow:
    def __init__(self, config, print_method):
        self._p = print_method
        self.log_file = config
        self.all_files = [
            'connector',
            'server',
            'join',
            'application',
            'join_error',
            'connector_error',
        ]

    def show(self, log='full', line=-1):
        if log == 'full':
            log_file = [self.log_file.get(x) for x in self.all_files]
        else:
            if isinstance(log, list):
                log_file = [
                    self.log_file.get(x) for x in log
                ]
            else:
                log_file = [self.log_file.get(log)]
        for log in log_file:
            # colorprint('Log from : {}'.format(log), bcolor='k', color='r')
            print('Log from: {}'.format(log))
            with open(log, 'r') as fi:
                self._p(fi.readlines()[line])
