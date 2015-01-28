local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[This is a combination of http-wordpress-plugins.nse and http-wordpress-themes.nse
        All scripting credits go to their authors Ange Gutek and Peter Hill.
        Feel free to criticize as this is my first patch. 
        ]]
-- @args http-wordpress-combo.root If set, points to the blog root directory on the website. If not, the script will try to find a WP directory installation or fall back to root.
-- @args http-wordpress-combo.search As the plugins list contains tens of thousand of plugins, this script will only search the 100 most popular ones by default.
-- Use this option with a number or "all" as an argument for a more comprehensive brute force.
-- @args http-wordpress-combo.type to tell what needs to be searched 0 for themes 1.Defaults to both.
--
-- @usage 
--nmap --script=http-wordpress-combo --script-args http-wordpress-combo.root="/blog/",http-wordpress-combo.search=50,http-wordpress-combo.type=2 <target>
-- --@output
-- Not shown: 977 closed ports
-- PORT      STATE    SERVICE
-- 6/tcp     filtered unknown
-- 22/tcp    open     ssh
-- 80/tcp    open     http
-- | http-wordpress-combo: 
-- | search amongst the 10 plugins or keys resulted : 
-- |   themes
-- |     getnoticed
-- |   plugins
-- |_    akismet

author = "Gyanendra Mishra <anomaly.the@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}

local DEFAULT_SEARCH_LIMIT = 100
portrule = shortport.service("http")

--combo the two as the default is the same 

local function read_data_file(file)
  return coroutine.wrap(function()
    for line in file:lines() do
      if not line:match("^%s*#") and not line:match("^%s*$") then
        coroutine.yield(line)
      end
    end
  end)
end
local function existence_check_assign(act_file)
  if not act_file then
    return false
  end
  local temp_file = io.open(act_file,"r")
  if not temp_file then
    return false
  end  
  return temp_file   
 end 



action = function(host, port)

  local result = {}
  local all = {}
  local bfqueries = {}

  --Check if the wp plugins/themes list exists
local operation_type_arg = tonumber(stdnse.get_script_args("http-wordpress-combo.type"))
local wp_themes_file = nmap.fetchfile("nselib/data/wp-themes.lst")
local wp_plugins_file = nmap.fetchfile("nselib/data/wp-plugins.lst")
local file = {}
if operation_type_arg == 0 then 
  if not  existence_check_assign(wp_themes_file) then
    return false, "Couldn't find wp-themes.lst (should be in nselib/data)"
  else
    file['themes'] = existence_check_assign(wp_themes_file)
  end    
elseif operation_type_arg==1 then
  if not  existence_check_assign(wp_plugins_file) then
    return  false, "Couldn't find wp-plugins.lst (should be in nselib/data)"
  else
    file['plugins'] = existence_check_assign(wp_plugins_file)
  end  
else
  if not  existence_check_assign(wp_themes_file) then
    return  false, "Couldn't find wp-themes.lst (should be in nselib/data)"
  else
    file['themes'] = existence_check_assign(wp_themes_file)
  end
  if not  existence_check_assign(wp_plugins_file) then
    return  false, "Couldn't find wp-plugins.lst (should be in nselib/data)"
  else
    file['plugins'] = existence_check_assign(wp_plugins_file)
  end  
end         
  local wp_autoroot
  local wp_root = stdnse.get_script_args("http-wordpress-combo.root")
  local combo_search = DEFAULT_SEARCH_LIMIT
  local combo_search_arg = stdnse.get_script_args("http-wordpress-combo.search")

  if combo_search_arg == "all" then
    combo_search = nil
  elseif combo_search_arg then
    combo_search = tonumber(combo_search_arg)
  end

  stdnse.print_debug(1,"combo search range: %s", combo_search or "unlimited")


  -- search the website root for evidences of a Wordpress path
  if not wp_root then
    local target_index = http.get(host,port, "/")

    if target_index.status and target_index.body then
      wp_autoroot = string.match(target_index.body, "http://[%w%-%.]-/([%w%-%./]-)wp%-content")
      if wp_autoroot then
        wp_autoroot = "/" .. wp_autoroot
        stdnse.print_debug(1,"WP root directory: %s", wp_autoroot)
      else
        stdnse.print_debug(1,"WP root directory: wp_autoroot was unable to find a WP content dir (root page returns %d).", target_index.status)
      end
    end
  end


  --identify the 404
  local status_404, result_404, body_404 = http.identify_404(host, port)
    if not status_404 then
    return stdnse.format_output(false, SCRIPT_NAME .. " unable to handle 404 pages (" .. result_404 .. ")")
  end


  --build a table of both directories to brute force and the corresponding WP plugins' or themes' name
  local combo_count=0
  for key,value in pairs(file) do
  local l_file = value
  combo_count = 0
  for line in read_data_file(l_file) do
    if combo_search and combo_count >= combo_search then
      break
    end

    local target
    if wp_root then
      -- Give user-supplied argument the priority
      target = wp_root .. string.gsub("/wp-content/plugins/","plugins",key) .. line .. "/"
    elseif wp_autoroot then
      -- Maybe the script has discovered another Wordpress content directory
      target = wp_autoroot .. string.gsub("/wp-content/plugins/","plugins",key) .. line .. "/"
    else
      -- Default WP directory is root
      target = string.gsub("/wp-content/plugins/","plugins",key) .. line .. "/"
    end


    target = string.gsub(target, "//", "/")
    table.insert(bfqueries, {target, line})
    all = http.pipeline_add(target, nil, all, "GET")
    combo_count = combo_count + 1

  end
  -- release hell...
  local pipeline_returns = http.pipeline_go(host, port, all)
  if not pipeline_returns then
    stdnse.print_debug(1,"got no answers from pipelined queries")
  end
  local response = {}
  response['name'] = key
  for i, data in pairs(pipeline_returns) do
    -- if it's not a four-'o-four, it probably means that the plugin is present
    if http.page_exists(data, result_404, body_404, bfqueries[i][1], true) then
      stdnse.print_debug(1,string.gsub("Found a plugin: %s","plugin",key), bfqueries[i][2])
      table.insert(response, bfqueries[i][2])
    end
  end
  table.insert(result,response)
  bfqueries={}
  all = {}

end
  if #result > 0 then
    result.name = "search amongst the " .. combo_count .. " plugins or keys resulted : "
    return stdnse.format_output(true, result)
  else
    return "nothing found amongst the " .. combo_count .. (" most popular plugins or keys , use --script-args http-wordpress-combo.search=<number|all> for deeper analysis)\n")
  end
    
end
