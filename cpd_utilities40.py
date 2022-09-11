###################################################
# Utility functions for the Data REST API in CP4D


# * cpd_rest_request35(cpd_access_info,method,request,postdata=None)
# * cpd_search_assets(cpd_access_info,asset_type,name)
# * cpd_lookup_asset(cpd_access_info,asset_type,name)
# * cpd_get_asset_content(...)
# * cpd_delete_asset(...)


# Examples for getting asset metadata:

# In a CP4D project :
# 1. Upload this file as data asset
# 2. In a notebook:
#    %cd /project_data/data_asset
#    import cpd_utilities35 as cpdu
#    cpdu.cpd_search_assets({},'data_asset')
#    # returns metadata for all data assets


# In a command line shell on your laptop:
#
#    # set up environment variables
#    eval $(python cpd_access.py --username me --password mypw https://mycpd.server.com MyProject)
#
#    python -c "import cpd_utilities35 as cpdu; print( cpdu.cpd_search_assets({},'notebook') )"
#
# Display corresponding cURL command:
#    export CPD_REQUEST_SHOW_CURL=1
#    python -c "import cpd_utilities35 as cpdu; print( cpdu.cpd_search_assets({},'data_asset') )"



##########
# This sample code is provided "as is", without warranty of any kind.
#
# The functions defined in this module are just examples that 
# demonstrate usage of the CP4D "Watson Data API".
# The functions are not part of the CP4D product. They are provided without any formal support.
##########


# This Python file can be imported as in `from cpd_utilities import *`
# or individual functions can be copied, e.g., via `%load -n cpd_conn_default_project`
# to make the main script or notebook self-contained.
# The function names generally have the prefix "cpd_".
# The functions are not designed as classes and methods because that would
# make copy&paste more involved.


def hello():
    print("I'm cpd_util")


#######################################################################################
#
# Custom logging functions

import logging

# default logging setup is logging.basicConfig(level=logging.WARNING)

# usage: wmlu_logger = wmlu.logging_setup()
#
def logging_setup(logfile="cpd_utilities.log", level=logging.INFO):
    """Set up logging using logging package and custom Logger.
    Returns custom Logger
    """
    # import logging
    # logfile = os.path.join(os.getcwd(),"cpd_utilities.log")
    wmlu_logger = logging.getLogger("cpd_utilities")  # create or get new logger
    wmlu_logger.setLevel(level)  # e.g. logging.INFO, or logging.DEBUG for more details
    wmlu_logger.addHandler(logging.FileHandler(logfile))
    # https://docs.python.org/3/library/logging.html#levels
    # later: logging.getLogger('cpd_utilities').info('my obj '+repr(some_obj))
    #
    return wmlu_logger


# convenience function for writing log messages
# copy this function to your code and modify as you like
def _my_log_msg(level, label, arg=None):
    # nonlocal wmlu_logger
    wmlu_logger = logging.getLogger("cpd_utilities")
    assert isinstance(label, str)
    # if level >= logging.DEBUG : print(level,label,arg)
    wmlu_logger.log(
        level,
        label + " : " + (arg if isinstance(arg, str) else (repr(arg) if arg else "")),
    )


def logging_snapshot():
    """Get content of log file"""
    # import logging
    # root_logfile = '/opt/ibm/scoring/python/logs/server_default.log'  # root logger in WML
    # root_logfile = logging.getLoggerClass().root.handlers[0].baseFilename
    logfile = logging.getLogger("cpd_utilities").handlers[0].baseFilename
    try:
        with open(logfile, "r") as f:
            logging_trace = f.read()
    except:
        logging_trace = 'log file "{}" not found'.format(logfile)
    return logging_trace


#


#######################################################################################
#
# Utility functions for Data REST API in CP4D
#

# Calls to the REST APIs in CP4D generally need
# * the URL of the CP4D system
# * a bearer token to authenticate the user
# * an of the project or deployment space
# The values are provided by the caller or extracted from environment variables.
# These attributes are passed to the utility function in a simple dictionary.


def cpd_conn_default_project():
    """Get CP4D connection info for default project."""
    import os

    return _cpd_conn_complete({"project_id": os.environ["PROJECT_ID"]})


def cpd_conn_default_space():
    """Get CP4D connection info for default space."""
    import os

    return _cpd_conn_complete({"space_id": os.environ["SPACE_ID"]})


def cpd_conn_space(name):
    """Get CP4D connection info for space."""
    return _cpd_conn_complete({"space_name": name})



def _cpd_conn_complete(access_info):
    """Derive a complete CP4D connection dictionary for calls of the REST API.
    Attributes are derived from access_info argument and from environment variables.
    Input argument may also be a wml client object.
    Returns a dictionary with url, token, version?
    """
    import os
    import copy

    # 1. extract properties from access_info argument

    if isinstance(access_info, dict):
        cpd_conn = copy.deepcopy(access_info)
    else:
        # access_info is assumed to be WML client object
        # e.g. type(wml_client) == ibm_watson_machine_learning.client.APIClient
        cpd_conn = {}
        cred = access_info.wml_credentials
        cpd_conn["url"] = cred.get("url")
        cpd_conn["token"] = cred.get("token")
        # 'instance_id': 'openshift', 'version': '3.5'
        #  wml client has 'default_project_id' or 'default_space_id'
        if access_info.default_project_id:
            cpd_conn["project_id"] = access_info.default_project_id
        if access_info.default_space_id:
            cpd_conn["space_id"] = access_info.default_space_id

    # 2. fill in blanks from environment variables

    if not cpd_conn.get("url"):
        cpd_conn["url"] = os.getenv(
            "RUNTIME_ENV_APSX_URL", "https://internal-nginx-svc:12443"
        )
        # nginx url works when running in the CP4D cluster

    if not cpd_conn.get("token"):
        token = os.getenv("USER_ACCESS_TOKEN", os.getenv("PROJECT_ACCESS_TOKEN"))
        # RStudio (job) runtime might have PROJECT_ACCESS_TOKEN instead of USER_ACCESS_TOKEN
        # Token in RStudio may start with "bearer ..."
        if token and token.lower().startswith("bearer "):
            token = token[7:]
        cpd_conn["token"] = token

        
    if not cpd_conn.get("space_id") and not cpd_conn.get("project_id"):
        if cpd_conn.get("space_name"):
            spc = lookup_cpd_space(cpd_conn["url"],cpd_conn["token"],cpd_conn["space_name"])    
            assert spc and isinstance(spc, dict) , f"space with name {cpd_conn['space_name']} not found"
            cpd_conn["space_id"] = spc["metadata"]["id"]
            #? os.environ["SPACE_ID"] = cpd_conn["space_id"]
        
    if not cpd_conn.get("space_id") and not cpd_conn.get("project_id"):
        cpd_conn["space_id"] = os.getenv("SPACE_ID")

    if not cpd_conn.get("project_id") and not cpd_conn.get("space_id") :
        cpd_conn["project_id"] = os.getenv("PROJECT_ID")
        
        
    # regular project has 'entity': {'storage': {'type': 'assetfiles', ...}}
    # v4 git project has  'entity': {'storage': {'type': 'local_git_storage', ...}}
    if cpd_conn.get("project_id"):
        import requests
        from urllib.parse import urljoin

        headers = { "Authorization": f"Bearer {cpd_conn['token']}" }
        urlreq = urljoin(cpd_conn["url"] , f"/v2/projects/{cpd_conn['project_id']}")
        response = requests.request("GET",urlreq,headers=headers,verify=False,timeout=30)
        prj = response.json()
        if prj["entity"]["storage"]["type"] == "local_git_storage":
            cpd_conn["userfs"] = True
        else:
            assert prj["entity"]["storage"]["type"] == "assetfiles" , \
                   "Unkown storage type " + str(prj["entity"]["storage"]["type"])

    cpd_conn["is_complete"] = True
    return cpd_conn


# from cpd_access.py
def lookup_cpd_space(url, token, name):
    """Get information about a space in CP4D.
    * name is the name of the deployment space to look up.
    Uses /v2/spaces which is available in CP4D 3.5 but not in v3.0
    """
    import requests
    # from posixpath import join as urljoin
    from urllib.parse import urljoin

    header = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
    response = requests.get(
        urljoin(url, "/v2/spaces"), headers=header, verify=False, timeout=100
    )
    if response.status_code == 404:  # might be old cpd
        return None
    if response.status_code != 200 and response.status_code != 201:
        raise Exception(response.text)
    #
    spcl = [
        spc for spc in response.json()["resources"] if spc["entity"]["name"] == name
    ]
    return spcl[0] if spcl else None









###############
# Submit requests
#
# Sample usage:
#    cpd_rest_request35({},"GET","/v2/spaces?limit=1")
# or
#    cpd_conn = cpd.cpd_conn_default_project()
#    r = cpd.cpd_rest_request35(cpd_conn,"POST","/v2/asset_types/data_asset/search",json={'query':'*:*'})
#    r.json()

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def cpd_rest_request(
    cpd_access_info, method, request, postdata=None, json=None, files=None, verbose=False
):
    return cpd_rest_request40(
        cpd_access_info, method, request, postdata=postdata, json=json, files=files, verbose=verbose
    )


def cpd_rest_request40(
    cpd_access_info, method, request, postdata=None, json=None, files=None, verbose=False
):
    """Call REST API in CP4D.
    The full URL with query options for the actual REST request is
    constructed from the cpd_access_info and request parameters.
    * cpd_access_info is a dictionary providing the url, location, and access token.
    * method is "GET", "POST", "PUT", PATCH", or "DELETE"
    * request is the path of the particular resource such as "/v2/assets"
    * json or postdata is assumed to be a dictionary that can be serialized to JSON
    Return response of REST request or raise an Exception if the request returned an error status code
    """
    # * gather url, authentication from cpd_conn or environment variables
    # * extend the request by query parameters that are specific to CP4D
    #   such as ?project_id=...&version=...
    #   (if the parameters are not already included in the request)
    # * return exception if response.status_code not in 20x range
    import logging
    import requests,os
    from urllib.parse import urljoin

    logging.debug(f"cpd_util:rest_request(...,{method},{request},{postdata},{json})")
    # hide connection info with token

    # 1. get the complete connection
    if isinstance(cpd_access_info, dict) and cpd_access_info.get("is_complete"):
        cpd_conn = cpd_access_info
    else:
        cpd_conn = _cpd_conn_complete(cpd_access_info)

    # 2. compose the full http URL incl query parameters
    # url = cpd_conn["url"].rstrip('/')
    # if url.endswith("/zen") : url = url[:-4] # e.g. when url was copied from browser
    # url_request = url+'/'+request.lstrip('/')
    url_request = urljoin(cpd_conn["url"], request)
    params = {"version": cpd_conn.get("version", "2021-06-01")}
    # caller can eliminate version param by passing cpd_access_info={'version':None}

    from urllib.parse import urlparse, parse_qs
    # add location as query argument if it is not already included in the request
    parsed = urlparse(request)
    pq = parse_qs(parsed.query)
    if not pq or not (
        pq.get("project_id") or pq.get("space_id") or pq.get("catalog_id")
    ):
        # add project_id or space_id to query, if available in cpd_conn
        params["project_id"] = cpd_conn.get("project_id")
        params["space_id"] = cpd_conn.get("space_id")
        params["catalog_id"] = cpd_conn.get("catalog_id")
        
    if cpd_conn.get("userfs") and not "userfs" in pq :
        params["userfs"] = "true"
        pass

    # 3. submit the request to CP4D system and check response
    assert cpd_conn.get("token")
    headers = {
        "Authorization": f'Bearer {cpd_conn["token"]}',
        #'Content-Type': 'application/json'   # not valid with 'files' data
    }
    if postdata is not None or json is not None:
        headers["Content-Type"] = "application/json"
    logging.debug(
        f"cpd_util:rest_request({method},{url_request},params={params},postdata={postdata},json={json})"
    )
    logging.debug(f"cpd_util:rest_request headers {headers}")
    response = requests.request(
        method,
        url_request,
        params=params,
        json=(json if json else postdata),
        headers=headers,
        files=files,
        verify=False,
        timeout=100,
    )
    if os.getenv("CPD_REQUEST_SHOW_CURL"):  # print corresponding curl command
        # e.g. when os.environ["CPD_REQUEST_SHOW_CURL"] = "1"
        import json as jsonpkg  # naming conflict wiith parameter "json"

        print("curl -k -X", method, '-H "Authorization: Bearer $USER_ACCESS_TOKEN" \\')
        for k in headers:
            if k != "Authorization":
                print(f"    -H '{k}: {headers[k]}' \\")
        if postdata or json:
            print(f"    -d '{jsonpkg.dumps(json if json else postdata)}' \\")
        if files:
            print("    -F file=@path/to/your/file \\")
        print(f"    '{response.url}'")
    logging.debug(f"cpd_util:rest_request returned status {response.status_code}")
    logging.debug(f"cpd_util:rest_request response.text : {response.text[:50]}...")
    if response.status_code not in [200, 201, 202, 204]:
        print("Request failed :", response.status_code)
        print(response.url)
        raise Exception(f'REST returned code {response.status_code} "{response.text}"')
    return response


cpd_rest_request35 = cpd_rest_request40


# DELETE method might return status 204
# HTTP Status 204 (No Content) indicates that the server has successfully fulfilled the request
# and that there is no content to send in the response payload body.
#

# troubleshoot:
#
# If URL does not start with http: or https:
# request raises exception
# requests.exceptions.MissingSchema: Invalid URL 'bla/v2/jobs': No schema supplied. Perhaps you meant http://bla/v2/jobs?
#
# Exception: REST returned code 504 "<html>
# <head><title>504 Gateway Time-out</title></head>
# Cause: token is invalid
# Both in CP4D v3.0 and v3.5
#
#     raise Exception(f'REST returned code {response.status_code} "{response.text}"')
# Exception: REST returned code 400 "{"code":400,"error":"Bad Request","reason":"Invalid resource guid format.","message":"The server cannot or will not process the request due to an apparent client error (e.g. malformed request syntax)."}"
# Cause: could be invalud project id parameter in URL
#
# Exception: REST returned code 400 "{"code":400,"error":"Bad Request","reason":"Missing or Invalid Data","message":"invalid signature"}"
# bad token
#
# HTTPIO_ERROR_SEND_STATE sap




def cpd_rest_request_postfile(cpd_conn, request, fname, verbose=False):
    # using curl instead of PUT request
    import requests, os
    import subprocess

    logging.debug(f"cpd_rest_request_postfile( ,{request},{fname})")

    assert cpd_conn

    url = cpd_conn.get(
        "url", os.getenv("RUNTIME_ENV_APSX_URL", "https://internal-nginx-svc:12443")
    )
    token = cpd_conn.get("token", os.getenv("USER_ACCESS_TOKEN"))
    full_url = url + request + "?project_id=" + os.environ["PROJECT_ID"]
    # todo: use cpd_conn

    # check if we can open the file, may trigger an exception
    with open(fname, "rb") as f:
        # for debugging: print(f.read()[:30])
        pass

    # _request('PUT', '/v2/asset_files/script/{}?project_id={}'.format(script_name, project.guid), headers={}, files={'file': open(fname, 'rb')})

    curl_cmd = ["curl", "-k", "-X", "PUT", full_url]
    curl_cmd.extend(["-F", "file=@" + fname])
    curl_cmd.extend(["-H", "Accept: */*"])
    logging.debug(f"cpd_util:cpd_rest_request_postfile {curl_cmd}")
    curl_cmd.extend(["-H", "Authorization: Bearer " + token])
    run_curl = subprocess.run(
        curl_cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    #  # check=True would immediately raise exception if returncode!=0
    if verbose:
        print("type", type(run_curl.returncode))
        print("run_curl.returncode", repr(run_curl.returncode))  # may be empty
    if run_curl.returncode and str(run_curl.returncode) != "0":
        logging.debug(f"run_curl: rc={run_curl.returncode}, stdout={run_curl.stdout}")

    return run_curl.returncode


# --data-binary
# https://github.com/IBM/watson-machine-learning-samples/blob/master/cloud/notebooks/rest_api/curl/deployments/scikit/Use%20scikit-learn%20to%20predict%20diabetes%20progression.ipynb
# https://stackoverflow.com/questions/14365027/python-post-binary-data


#


##########  Assets and asset types


def cpd_get_asset_types(cpd_access_info):
    res = cpd_rest_request35(cpd_access_info, "GET", "/v2/asset_types")
    l = res.json()["resources"]
    return [(t["name"], t.get("description")) for t in l]


# How to get all asset types:
# cpd_access_info = {"project_id":os.getenv("PROJECT_ID")} # connect to current project
# tl = wml_util.cpd_rest_request_json(cpd_access_info,"GET","/v2/asset_types")
# [ t.get("name")  for t in tl.get("resources")]

# Get assets of any type: POST /v2/asset_types/Asset/search
# cpd.cpd_rest_request35(cpd_conn,"POST","/v2/asset_types/Asset/search",postdata={'query':'*:*'})



# Generic asset search function using CP4D Data REST API
# "/v2/asset_types/"+asset_type+"/search"
# usage e.g.:
#    cpd_search_assets(cpd_access_info,"notebook",name="HelloWorld",sortby="created_at")
#
def cpd_search_assets(
    cpd_access_info, asset_type, name=None, query=None, sortby=None, verbose=False
):
    """Search assets based on name or query pattern.
    Provide either name or query as argument.
    * cpd_access_info: see cpd_rest_request(cpd_access_info,...)
    * asset_type can be, e.g., "data_asset", "script", "wml_model", ...
    * query can be "*:*" to match any asset
      or complex such as "job_run.job_ref:<job_id> OR job_run.job_ref:<job_id> OR ..."
    * sortby can be "last_updated_at" or "created_at"
    """
    # Lucene syntax https://lucene.apache.org/core/2_9_4/queryparsersyntax.html#Wildcard%20Searches
    import logging
    
    #
    # Check parameters
    logging.debug(f"search_assets({asset_type},{name},{query})")
    assert asset_type

    if name:
        pattern = name.replace(" ", "\\ ").replace("/", "\\/").replace(":", "\\:")
        # '/' is a special character in CAMS search function, needs to be escaped
        postquery = {"query": "asset.name:" + pattern}
    else:
        postquery = {"query": (query if query else "*:*")}

    response = cpd_rest_request35(
        cpd_access_info,
        "POST",
        f"/v2/asset_types/{asset_type}/search",
        postdata=postquery,
    )
    # empty search result would have .status_code 200 and .text {"total_rows":0,"results":[]}

    l = response.json()["results"]
    if not l or not sortby:
        return l
    elif sortby == "last_updated_at" or sortby == "modified_at":
        if l[0]["metadata"].get("usage"):  # as in cpd 3.5:
            return sorted(l, key=lambda d: d["metadata"]["usage"]["last_updated_at"])
        else:  # cpd 3.0
            return sorted(l, key=lambda d: d["metadata"]["modified_at"])
        # in cpd 3.5: d["metadata"] 'usage': {'last_updated_at': ...
    elif sortby == "created_at":
        return sorted(l, key=lambda d: d["metadata"]["created_at"])
    # else
    raise exception("sortby '{}' not supported".format(sortby))


#

# Notice the results of an Asset Type Search, as shown above, only contain the "metadata" section
# of a primary metadata document. In particular, the "entity" section that contains the attributes
# is not returned. That is done to reduce the size of the response because, in general,
# the "entity" section of a primary metadata document can be much larger than the "metadata" section.
# Use the value of the "metadata.asset_id" in one of the items in "results" to retrieve more details.
# https://cloud.ibm.com/apidocs/watson-data-api-cpd#search-asset-type-attribute-boo


def cpd_lookup_asset(
    cpd_access_info, asset_type, name=None, id=None, href=None, version=None
):
    """Lookup a asset by name.
    * cpd_access_info: see cpd_rest_request(cpd_access_info,...)
    Returns metadata for asset or None if not found.
    Can raise an Exception when lookup by name finds duplicates.
    """

    if href:
        return cpd_rest_request35(cpd_access_info, "GET", href).json()

    if id:
        assert isinstance(id, str)
        return cpd_rest_request35(cpd_access_info, "GET", "/v2/assets/" + id).json()
        # similar to client.data_assets.get_details(id)

    # else lookup by name
    sortby = "last_updated_at" if version == "latest" else None
    l = cpd_search_assets(cpd_access_info, asset_type, name=name, sortby=sortby)
    if not l:
        return None
    meta = None
    if len(l) == 1:
        meta = l[0]
    else:
        assert len(l) >= 2
        if version == "latest":
            meta = l[-1]  # last / most recent item
        else:
            raise Exception("Asset name not unique : " + name)
    assert meta is not None
    return cpd_rest_request35(cpd_access_info, "GET", meta["href"]).json()


#######   download
# Get asset content (download)

# Data API https://cloud.ibm.com/apidocs/watson-data-api-cpd#introduction

# "Get a data asset" https://cloud.ibm.com/apidocs/watson-data-api-cpd#getdataassetv2

# sample curl commands https://github.ibm.com/PrivateCloud-analytics/Zen/issues/22000
# incl downloading files

def cpd_download_asset_to_file(cpd_access_info, asset=None, id=None, href=None, to_path=None) :
    """Download asset content into a local file
    * asset, id, or href must be defined
    """
    from pathlib import Path
 
    if not asset:
        if not href:
            assert id
            href = "/v2/assets/" + id
        asset = cpd_rest_request35(cpd_access_info, "GET", href).json()
    assert isinstance(asset,dict)  # metadata dictionary
    
    fpath = Path(to_path if to_path else meta["metadata"]["name"])
    fpath.parent.mkdir(parents=True, exist_ok=True)

    res = cpd_get_asset_content(cpd_access_info,asset=asset)
    with open(str(fpath),"wb") as f:
         f.write(res.content)



def cpd_get_asset_content(cpd_access_info, asset=None, id=None, href=None):
    """Get the content of an asset such as a notebook or data asset.
    * asset, id, or href must be defined
    Returns response object
    Caller can access data using r.content or r.text,r.encoding
    Restriction: only first attachment
    """
    if not asset:
        if not href:
            assert id
            href = "/v2/assets/" + id
        asset = cpd_rest_request35(cpd_access_info, "GET", href).json()
    # Get attachment
    asset_id = asset["metadata"]["asset_id"]
    attachment_id = asset["attachments"][0]["id"]
    attachment_details = cpd_rest_request35(
        cpd_access_info, "GET", f"/v2/assets/{asset_id}/attachments/{attachment_id}"
    )
    return cpd_rest_request35(cpd_access_info, "GET", attachment_details.json()["url"])


# Sample usage:
# cpd_access_info = {"project_id":os.getenv("PROJECT_ID")}
# assets = cpd_rest_search_assets(cpd_access_info,"notebook",name="HelloWorld",sortby="created_at")
# response = cpd_get_asset_content(cpd_access_info,href=assets[-1]["href"])
# with open("tmpfile","wb") as f:
#     f.write(response.content)


def cpd_get_attachment_content(cpd_access_info, asset, attachment):
    attachment_id = attachments["id"]
    attachment_details = cpd_rest_request35(
        cpd_access_info, "GET", f"/v2/assets/{asset_id}/attachments/{attachment_id}"
    )
    return cpd_rest_request35(cpd_access_info, "GET", attachment_details.json()["url"])


# Sample usage:
#     asset = cpd_lookup_asset(cpd_access_info,name="...")
#     for att in asset.get('attachments',[]) :
#         response = cpd_get_attachment_content(cpd_access_info,asset,attachment)
#         with open("tmpfile"+str(n),"wb") as f:
#             f.write(response.content)


##################
#
# Delete asset


def cpd_delete_asset(cpd_access_info, asset_type, id, force_read_only=False):
    """Delete a 'regular' asset such as notebook, script.
    Uses "DELETE /v2/assets/{id}?purge_on_delete=true"
    Use other specific Delete requests for objects such as Connections.
    """
    #
    logging.info(f"Deleting asset {asset_type} {id}")
    res = cpd_rest_request35(cpd_access_info, "GET", f"/v2/assets/{id}")
    asset = res.json()
    if not asset:
        return None

    if asset_type == "connection":
        print("cpd_delete_asset connection")
        cpd_rest_request35(cpd_access_info, "DELETE", f"/v2/connections/{id}")
        return None
    # Regular "DELETE",f"/v2/assets/{id}?purge_on_delete=true"
    # on connection with personal credentials returns:
    # Exception: REST returned code 400 "{"trace":"el7urqcytkidt4aczfwb30jdv","errors":
    # [{"code":"ReservedValue","message":"Background delete processing has not finished yet
    # for 40a0b326-feb2-43ff-8585-4cca5f0045e4 / c41c137c-cd56-4685-9cb4-5f3afeb527f0"}]}"

    res = cpd_rest_request35(
        cpd_access_info, "DELETE", f"/v2/assets/{id}?purge_on_delete=true"
    )  # ,verbose=True)
    # A regular DELETE will just move the metadata to the trash bin (and could be restored)
    # With purge_on_delete the metadata entry is gone.
    # The option purge_on_delete will also delete the attached files
    # unless the attachment has a flag object_key_is_read_only == True.
    # Assets are usually created with object_key_is_read_only == False.

    if not force_read_only:
        return
    # Proceed if you want to delete "read_only" attachments.
    # Note:
    # In the POST input the attribute is called "object_key_is_read_only"
    # In the resulting entity from GET it is called "is_object_key_read_only"
    for att in asset.get("attachments", []):
        if not att.get("is_object_key_read_only"):
            continue  # already purged
        print(
            "Deleting attachment",
            att["is_user_provided_path_key"],
            att.get("object_key"),
        )
        for k in [
            "is_remote",
            "is_managed",
            "is_referenced",
            "is_object_key_read_only",
        ]:
            print(k, "=", att.get(k), end=" ")
        print("")  # att.get()'object_key')
        if att["is_user_provided_path_key"] and att.get("object_key"):
            # DELETE /v2/asset_files/{path}
            att_path = att["object_key"].lstrip("/")
            try:
                cpd_rest_request35(
                    cpd_access_info, "DELETE", f"/v2/asset_files/{att_path}"
                )  # ,verbose=True)
                print("    ... success")
            except Exception as ex:
                print("    ... gone")


def cpd_delete_assets(cpd_access_info, asset_type, name):
    assets = cpd_search_assets(cpd_access_info, asset_type, name=name)
    for asset in assets:
        cpd_delete_asset(cpd_access_info, asset_type, id=asset["metadata"]["asset_id"])

        
        

#########################
#
# upload script file to project

        
# from cpd_upload.py

def cpd_upload_file_create_script(cpd_conn, path):
    import os
    if os.path.splitext(path)[1] in [".R",".r"]:
        return cpd_upload_file_create_r_script(cpd_conn, path)
    else:
        return cpd_upload_file_create_py_script(cpd_conn, path)

        
def cpd_upload_file_create_py_script(cpd_conn, path):
    # create Python script asset
    filepath = str(path)
    
    # Software specification id
    # default_py3.7_opence           c2057dd4-f42c-5f77-a02f-72bdbd3282c9
    # runtime-22.1-py3.9             12b83a17-24d8-5082-900f-0ab31fbfd3cb
    sw_base_id = "12b83a17-24d8-5082-900f-0ab31fbfd3cb"

    newmeta = {
        "metadata": {
            "name": filepath,
            "asset_type": "script",
            "origin_country": "us",
        },
        "entity": {
            "script": {
                "language": {"name": "python3"},
                "software_spec": {"base_id": sw_base_id}, # dict can be empty
            }
        },
    }
    # from JupyterLab: 'entity': {'script': {'language': {'name': 'python3'}, 'software_spec': {}}},

    meta2 = cpd_rest_request35(
        cpd_conn, "POST", "/v2/assets", newmeta
    ).json()
    asset_id = meta2["metadata"]["asset_id"]
    print("new script asset_id", asset_id)
    #
    # upload attachment file as 'script/'+filepath
    # CP4D git pull saves a script from JupyterLab into '/jupyterlab/'+filepath
    # e.g. 'object_key': '/jupyterlab/wml_score.py'
    # WML Py client uploads files as e.g. 'script/1114fddb-847e-4579-b2ab-0e849a642ea6'
    mime = "text/plain"
    asset_upload_attach_file(
        cpd_conn, asset_id, "script", filepath, mime=mime
    )
    return asset_id
        
        
def cpd_upload_file_create_r_script(cpd_conn, path):
    # create R script asset
    filepath = str(path)
    newmeta = {
        "metadata": {
            "name": filepath,
            "asset_type": "script",
            "origin_country": "us",
        },
        "entity": {
            "script": {"language": {"name": "R"}, "software_spec": {"name": "R 3.6"}},
        },
    }

    # POST /v2/assets
    meta2 = cpd_rest_request35(
        cpd_conn, "POST", "/v2/assets", newmeta
    ).json()
    assert meta2
    asset_id = meta2["metadata"]["asset_id"]
    print("new script asset_id", asset_id)
    #
    # upload script file to asset_files as 'script/'+filepath
    # CP4D git pull saves an RStudio script into 'rstudio/'+filepath
    mime = "text/plain"
    asset_upload_attach_file(
        cpd_conn, asset_id, "script", filepath, mime=mime
    )
    return asset_id


def asset_upload_attach_file(
    cpd_conn, asset_id, asset_type, filepath, mime="", local_file=None
):
    """Given an existing asset, upload a local file and attach it to the asset."""
    # upload attachment file        # https://restfulapi.net/rest-put-vs-post/
    res = cpd_rest_request35(
        cpd_conn, "PUT",f"/v2/asset_files/{asset_type}/{filepath}",files={'file': open(local_file if local_file else filepath, 'rb')})

    # link asset to attachment
    assetfile_meta = {
        "asset_type": asset_type,
        "mime": mime,
        "object_key": f"{asset_type}/{filepath}",
    }
    res = cpd_rest_request35(
        cpd_conn,
        "POST",
        f"/v2/assets/{asset_id}/attachments",
        assetfile_meta,
    ).json()
    return asset_id