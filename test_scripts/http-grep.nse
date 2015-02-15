local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Spiders a website and attempts to match all pages and urls against a given
string. Matches are counted and grouped per url under which they were
discovered.
]]

---
-- @usage
-- nmap -p 80 www.example.com --script http-grep --script-args='http-grep.match="[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?",http-grep.breakonmatch'
-- nmap --script http-grep --script-args='http-grep.builtins="email,phone"' <target>
-- @output needs to be updated
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-grep:
-- |   (4) http://example.com/name/
-- |     + name@example.com
-- |     + name@example.com
-- |     + name@example.com
-- |     + name@example.com
-- |   (4) http://example.com/sales.html
-- |     + sales@example.com
-- |     + sales@example.com
-- |     + sales@example.com
-- |__   + sales@example.com
--
-- @args http-grep.match the string to match in urls and page contents or list of patterns separated by delimiter
-- @args http-grep.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-grep.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-grep.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-grep.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-grep.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)
-- @args http-grep.builtins supply a single or a list of built in types
-- @args http-grep.delimiter supply a delimiter or use ',' by default appliest to both type and patterns
-- @args http-grep.unique to show a particular match just once. default false.
author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http

-- Shortens a matching string if it exceeds 60 characters
-- All characters after 60 will be replaced with ...
local function shortenMatch(match)
  if ( #match > 60 ) then
    return match:sub(1, 60) .. " ..."
  else
    return match
  end
end

local function already_present(shortenMatch,mini_match,results)
  shortenMatch = "+ " .. shortenMatch 
  -- maybe it's in the current mini_match table??
  for _,match in pairs(mini_match) do
    if match == shortenMatch then
      return true
    end
  end
  -- maybe it's in the bigger results table??
  for _,matches in pairs(results) do
   for _,mini_match in pairs(matches) do
    if type(mini_match)== "table" then 
      for _,match in pairs(mini_match) do
        if match == shortenMatch then
          return true
        end
      end
    end  
  end
  end 
  return false
end        
action = function(host, port)
  -- a set of famous/most searched patterns
  local BUILT_IN_PATTERNS = {
  ['email'] = {'[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?',},
  ['phone'] = {'>?%d%d%d%-%d%d%d%d<?','%(%d%d%d%)%s%d%d%d%-%d%d%d','%+%-%d%d%d%-%d%d%d%-%d%d%d%d','%d%d%d%-%d%d%d%-%d%d%d%d'},
  ['mastercard']= {'5%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d',},
  ['visa'] = {'4%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d',},
  ['discover']={'6011%s?%-?%d%d%d%d%s?%-?%d%d%d%d%s?%-?%d%d%d%d',},
  ['amex'] ={'3%d%d%d%s?%-?%d%d%d%d%d%d%s?%-?%d%d%d%d%d',},
  ['ssn'] = {'%d%d%d%-%d%d%d%-%d%d%d'},
  ['ip']={'%d%d?%d?%.%d%d?%d?%.%d%d?%d%.%d%d?%d?',},
  }

  -- read script specific arguments
  local match = stdnse.get_script_args("http-grep.match")
  local break_on_match = stdnse.get_script_args("http-grep.breakonmatch")
  local delimiter = stdnse.get_script_args("http-grep.delimiter") or ','
  local builtins = stdnse.get_script_args("http-grep.builtins")
  local unique = stdnse.get_script_args("http-grep.unique") or "false"
  local to_be_searched = {}
  if ( not(match) ) and (not(builtins)) then
    return stdnse.format_output(true, "ERROR: Argument http-grep.match was not set nor was builtin")
  end

  local crawler = httpspider.Crawler:new(host, port, nil, { scriptname = SCRIPT_NAME } )
  local results = {}

  local delimiter_pattern = '([^' .. delimiter .. ']+)'

  if builtins then
    for builtin in  string.gmatch(builtins,delimiter_pattern) do
        for name,v in pairs(BUILT_IN_PATTERNS) do
            if name == builtin then
            for _,pattern in pairs(v) do
              table.insert(to_be_searched,pattern)
            end
           end  
        end          
    end
  end
  if match then    
    for pattern in string.gmatch(match,delimiter_pattern) do
      table.insert(to_be_searched,pattern)
    end
  end    
  if #to_be_searched == 0 then 
    return stdnse.format_output(true,"ERROR: No pattern was entered and the builtin type specified was invalid")
  end      
  -- set timeout to 10 seconds
  crawler:set_timeout(10000)

  while(true) do
    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(true, "ERROR: %s", r.reason)
      else
        break
      end
    end
    local mini_match = {}
    local count = 0
    local matches = {}
    -- search for multiple patterns on a particular page and store the results in the mini_match table
    for _,pattern in pairs(to_be_searched) do
      mini_match = {}
      mini_match.name = "Results for Patttern " .. pattern .. " are: " 
      local body = r.response.body
      -- try to match the url and body
      if body and ( body:match( pattern ) or tostring(r.url):match(pattern) ) then
        count = count + select(2, body:gsub(pattern,""))
        
        for match in body:gmatch(pattern) do
          if unique == "true" then
            if not(already_present(shortenMatch(match),mini_match,results)) then
            table.insert(mini_match,"+ " .. shortenMatch(match))
            else
            count = count - 1  
            end
          else
            table.insert(mini_match,"+ " .. shortenMatch(match))          
          end  
        end
        
        -- should we continue to search for matches?
        if ( break_on_match ) then
          crawler:stop()
          break
        end
      end
    -- all the pattern match results for a particular table are stored in the matches table  
    table.insert(matches,mini_match)
    end
    --the matches table is given the name of the present url and is pushed into the results table
    matches.name = ("(%d) %s"):format(count,tostring(r.url))
    table.insert(results, matches)
  end
  table.sort(results, function(a,b) return a.name>b.name end)
  return stdnse.format_output(true, results)
end