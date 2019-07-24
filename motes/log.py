import logging

logger = logging.getLogger('main')

handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s\n\n'
)

handler.setFormatter(formatter)

logger.addHandler(handler)
