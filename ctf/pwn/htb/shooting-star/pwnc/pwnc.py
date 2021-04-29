import urllib3
import json

LIBC_RIP_FIND = "https://libc.rip/api/find"
LIBC_RIP_LIBC = "https://libc.rip/api/libc/"

def get_libc(known_symbols : dict):
    """
    This function will use the libc.rip api to download a libc based on
    addresses of leaked symbols.

    @known_symbols: dictionary of symbol names (strings) mapped to their
    addresses (strings)

    @returns: a libc binary as a string of bytes
    """
    download_url = _query_download_url(known_symbols)

    libc = None
    with urllib3.PoolManager() as http:
        r = http.request("GET", download_url)
        libc = r.data

    return libc

def query(requested_symbols : list, known_symbols : dict):
    """
    This function uses the libc.rip api to attempt to find libc symbols based
    on leaked addresses.

    @known_symbols: dict of symbol names (strings) mapped to addresses (strings)
    @request_symbols: list of requested symbols (strings)

    @returns: a dictionary of requested symbols (strings) mappped to their
    addresses (int). If things go wrong an exception will be raised
    """
    results = {}
    
    # first get the buildid
    buildid = _query_build_id(known_symbols)

    # now get the desired symbols based on the buildid
    results = _query_symbols(requested_symbols, buildid)

    return results

def _query_build_id(symbols : dict):
    """
    This funcion returns the 'id' value from an API find call

    @symbols: dictionary of symbol names (strings) mapped to addresses (strings)

    @returns: a build ID (string) that can be used too query symbol addresses.
    If things go wrong this function raises an execption.
    """
    return _query(symbols, "id")

def _query_download_url(symbols : dict):
    """
    This funcion returns the 'download_url' value from an API find call

    @symbols: dictionary of symbol names (strings) mapped to addresses (strings)

    @returns: a download url (string) where the libc can be downloaded
    """
    return _query(symbols, "download_url")

def _query(symbols : dict, desired_value : str):
    """
    This function querys https://libc.rip/api/find with a dictionary of symbols
    (strings) mappped to addresses (int). It returns the desired_value from the
    resulting json object

    @symbols: dictionary of symbol names (strings) mapped to addresses (strings)

    @returns: the values assocaited with the desired_value key passed to this
    function
    """
    with urllib3.PoolManager() as http:

        # build the POST request and send it
        encoded_body = json.dumps({'symbols': symbols})
        response = http.request(
            'POST',
            LIBC_RIP_FIND,
            body = encoded_body,
            headers = {
                "Content-Type": "application/json"
            }
        )

        # parse the response
        parsed = json.loads(response.data.decode('utf-8'))

    return parsed[0][desired_value]

def _query_symbols(desired_symbols : list, buildid : str):
    """
    This function querys https://libc.rip/api/libc/<buildid> with a list of
    symbols (strings).

    @desired_symbols: list of strings. Each is a libc symbol
    @build: string id of the libc to query

    @returns: a dictionary of symbols (strings) mappped to their addresses
    (strings) If things go wrong an exception will be raised
    """
    with urllib3.PoolManager() as http:
    
        encoded_body = json.dumps({'symbols': desired_symbols})
        response = http.request(
            'POST',
            f"{LIBC_RIP_LIBC}{buildid}",
            body = encoded_body,
            headers = {
                "Content-Type": "application/json"
            }
        )

        parsed = json.loads(response.data.decode('utf-8'))

    return parsed['symbols']
