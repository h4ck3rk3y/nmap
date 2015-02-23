local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates the installed Drupal modules/themes by using a list of known modules and themes.

The script works by iterating over module/theme names and requesting
MODULES_PATH/MODULE_NAME/LICENSE.txt same for theme except logo.png is searched for.  MODULES_PATH is either provided by the
user, grepped for in the html body or defaulting to sites/all/modules/. If the
response status code is 200, it means that the module/theme is installed.  By
default, the script checks for the top 100 modules (by downloads), given the
huge number of existing modules (~10k).
]]

---
-- @args http-drupal-enum.root The base path. Defaults to <code>/</code>.
-- @args http-drupal-enum.search-limit Number of modules to check.
-- Use this option with a number or "all" as an argument to test for all modules.
-- Defaults to <code>100</code>.
-- @args http-drupal-enum.direct_path_modules Direct Path for Modules
-- @args http-drupal-enum.direct_path_themes Direct Path for Themes
-- @args http-drupal-enum.type default all.choose between "themes" and "modules"
-- @usage
-- nmap -p 80 --script http-drupal-enum --script-args direct_path_modules="sites/all/modules/",direct_path_themes="themes/",search-limit=10 <target>
--
--
--@output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-drupal-enum:
-- | Search limited to top 10 themes/modules
-- |   modules
-- |     ckeditor
-- |     views
-- |     token
-- |     pathauto
-- |     cck
-- |     admin_menu
-- |   themes
-- |_    theme470
-- Final times for host: srtt: 329644 rttvar: 185712  to: 1072492
-- TODO version checking
-- TODO xml-output
-- TODO better paths as some use /contrib and /customs. need to search deeper.


author = {
  "Hani Benhabiles",
  "Gyanendra Mishra",
}

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {
  "discovery",
  "intrusive",
}

local DEFAULT_SEARCH_LIMIT = 100
local DEFAULT_MODULES_PATH = 'sites/all/modules/'
local DEFAULT_THEMES_PATH = 'sites/all/themes/'
local IDENTIFICATION_STRING = "GNU GENERAL PUBLIC LICENSE"

portrule = shortport.http

--Reads database
local function read_data_file (file)
  return coroutine.wrap(function ()
      for line in file:lines() do
        if not line:match "^%s*#" and not line:match "^%s*$" then
          coroutine.yield(line)
        end
      end
    end)
end

--Checks if the module/theme file exists
local function existence_check_assign (act_file)
  if not act_file then
    return false
  end
  local temp_file = io.open(act_file, "r")
  if not temp_file then
    return false
  end
  return temp_file
end

--- Attempts to find modules path
local get_path = function (host, port, root, type_of)
  local default_path
  if type_of == "themes" then
    default_path = DEFAULT_THEMES_PATH
  else
    default_path = DEFAULT_MODULES_PATH
  end
  local body = http.get(host, port, root).body
  local pattern = "sites/[%w.-/]*/" .. type_of .. "/"
  local found_path = body:match(pattern)
  return found_path or default_path
end


function action (host, port)
  local result = {}
  local file = {}
  local all = {}
  local requests = {}
  local drupal_autoroot
  local method = "HEAD"

  --Read script arguments
  local operation_type_arg = stdnse.get_script_args(SCRIPT_NAME .. ".type") or "all"
  local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or "/"
  local resource_search_arg = stdnse.get_script_args(SCRIPT_NAME .. ".search-limit") or DEFAULT_SEARCH_LIMIT
  local direct_path_themes = stdnse.get_script_args(SCRIPT_NAME .. ".direct_path_themes")
  local direct_path_modules = stdnse.get_script_args(SCRIPT_NAME .. ".direct_path_modules")

  local drupal_themes_file = nmap.fetchfile "nselib/data/drupal-themes.lst"
  local drupal_modules_file = nmap.fetchfile "nselib/data/drupal-modules.lst"

  if operation_type_arg == "themes" or operation_type_arg == "all" then
    local theme_db = existence_check_assign(drupal_themes_file)
    if not theme_db then
      return false, "Couldn't find drupal-themes.lst in /nselib/data/"
    else
      file['themes'] = theme_db
    end
  end
  if operation_type_arg == "modules" or operation_type_arg == "all" then
    local modules_db = existence_check_assign(drupal_modules_file)
    if not modules_db then
      return false, "Couldn't find drupal-modules.lst in /nselib/data/"
    else
      file['modules'] = modules_db
    end
  end

  local resource_search
  if resource_search_arg == "all" then
    resource_search = nil
  else
    resource_search = tonumber(resource_search_arg)
  end

  -- search the website root for evidences of a Drupal path
  local theme_path = direct_path_themes
  local module_path = direct_path_modules

  if not direct_path_themes then
    theme_path = get_path(host, port, root, "themes")
  end
  if not direct_path_modules then
    module_path = get_path(host, port, root, "modules")
  end

  -- We default to HEAD requests unless the server returns
  -- non 404 (200 or other) status code

  local response = http.head(host, port, root .. module_path .. "randomaBcD/LICENSE.txt")
  if response.status ~= 404 then
    method = "GET"
  end

  for key, value in pairs(file) do
    local temp_table = {}
    temp_table['name'] = key
    local count = 0
    for obj_name in read_data_file(value) do
      count = count + 1
      if resource_search and count > resource_search then
        break
      end
      -- add request to pipeline
      if key == "modules" then
        all = http.pipeline_add(root .. module_path .. obj_name .. "/LICENSE.txt", nil, all, method)
      else
        all = http.pipeline_add(root .. theme_path .. obj_name .. "/logo.png", nil, all, method)
      end
      -- add to requests buffer
      table.insert(requests, obj_name)
    end

    -- send requests
    local pipeline_responses = http.pipeline_go(host, port, all)
    if not pipeline_responses then
      stdnse.print_debug(1, "No answers from pipelined requests")
      return nil
    end

    for i, response in pairs(pipeline_responses) do
      -- Module exists if 200 on HEAD
      -- or contains identification string for GET or key is themes and is image
      if method == "HEAD" and response.status == 200 or method == "GET" and response.status == 200 and (string.match(response.body, IDENTIFICATION_STRING) or key == "themes") then
        table.insert(temp_table, requests[i])
      end
    end
    table.insert(result, temp_table)
    requests = {}
    all = {}
  end
  local len = 0
  for i, v in ipairs(result) do
    len = len >= #v and len or #v
  end
  if len > 0 then
    result.name = string.format("Search limited to top %s themes/modules", resource_search)
    return stdnse.format_output(true, result)
  else
    if nmap.verbosity() > 1 then
      return string.format("Nothing found amongst the top %s resources," .. "use --script-args search-limit=<number|all> for deeper analysis)", resource_search)
    else
      return nil
    end
  end
end