from datetime import datetime


def timestamp_diff_in_days(begin, end):
    return abs((datetime.fromtimestamp(begin) - datetime.fromtimestamp(end)).days)
