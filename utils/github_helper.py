import logging

from utils.requests_helper import requests_get

logger = logging.getLogger(__name__)


def get_latest_repo_release(repo_name):
    """get latest version info"""
    logger.info('get latest version info()')
    url = f'https://api.github.com/repos/{repo_name}/releases/latest'
    res = requests_get(url)
    return res.json()['tag_name']
