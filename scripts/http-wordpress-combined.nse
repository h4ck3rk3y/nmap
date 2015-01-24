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

-- usage nmap --script=http-wordpress-combined --script-args http-wordpress-combined.root="/blog/",http-wordpress-combined.search=500,http-wordpress-combined.type=0 <target> -d

author = "Gyanendra Mishra <anomaly.the@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}

local DEFAULT_SEARCH_LIMIT = 100
portrule = shortport.service("http")

--combined the two as the default is the same 

local function read_data_file(file)
  return coroutine.wrap(function()
    for line in file:lines() do
      if not line:match("^%s*#") and not line:match("^%s*$") then
        coroutine.yield(line)
      end
    end
  end)
end

action = function(host, port)

  local result = {}
  local all = {}
  local bfqueries = {}

  --Check if the wp plugins list exists
local operation_type_arg = tonumber(stdnse.get_script_args("http-wordpress-combined.type"))
local wp_themes_file = nmap.fetchfile("nselib/data/wp-themes.lst")
local wp_plugins_file = nmap.fetchfile("nselib/data/wp-plugins.lst")
local wp_both = {}
local types = {}
local file = {}
if operation_type_arg == 0 then
  wp_both["wp-themes.lst"] = wp_themes_file 
  types = {'themes'}
elseif operation_type_arg==1 then
  wp_both["wp-plugins.lst"] = wp_plugins_file
  types = {'plugins'}
else
  wp_both["wp-plugins.lst"] = wp_plugins_file
  wp_both["wp-themes.lst"] = wp_themes_file
  types = {'themes' , 'plugins'}
end       
  for key,value in pairs(wp_both) do    
    if not value then
      return false, string.gsub("Couldn't find file (should be in nselib/data)","file",key)
    end

    file[key] = io.open(value, "r")
    if not value then
      return false,  string.gsub("Couldn't find file (should be in nselib/data)","file",key)
    end
  end   

  local wp_autoroot
  local wp_root = stdnse.get_script_args("http-wordpress-combined.root")
  local combo_search = DEFAULT_SEARCH_LIMIT
  local combo_search_arg = stdnse.get_script_args("http-wordpress-combined.search")

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


  --build a table of both directories to brute force and the corresponding WP plugins' name
  for key in types do
  local l_file  
  if key == 'plugins' then
      l_file=file['wp-plugins.lst']
  elseif key=='themes' then
      l_file=file['wp-themes.lst']
  end            
  local combo_count=0
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

  for i, data in pairs(pipeline_returns) do
    -- if it's not a four-'o-four, it probably means that the plugin is present
    if http.page_exists(data, result_404, body_404, bfqueries[i][1], true) then
      stdnse.print_debug(1,string.gsub("Found a plugin: %s","plugin",key), bfqueries[i][2])
      table.insert(result, bfqueries[i][2])
    end
  end


  if #result > 0 then
    result.name = "search amongst the " .. combo_count .. string.gsub(" most popular plugins","plugins",key)
    return stdnse.format_output(true, result)
  else
    return "nothing found amongst the " .. combo_count .. string.gsub(" most popular plugins, use --script-args http-wordpress-combo.search=<number|all> for deeper analysis)\n","plugins",key)
  end
  result = {}
  bfqueries={}
  all = {}

end
end