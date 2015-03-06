local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json  = require "json"


description = [[
Finds out whether a website/blog is a tumblr blog or not by querying the API. 
If It is then it returns some stats about the same.
]]

--@args api-key insert an api key or use the default api key present here api.tumblr.com
--@usage nmap -p 80 --script <target>
--@output
-- | http-tumblr-stats: 
-- |   is_nsfw :
-- |     false
-- |   description :
-- |     page description
-- |   name :
-- |     nmap
-- |   updated :
-- |     2015-02-27T18:36:49
-- |   share_likes :
-- |     false
-- |   ask_anon :
-- |     false
-- |   posts :
-- |     4607
-- |   url :
-- |     http://www.example.com/
-- |   title :
-- |     Some Title
-- |   ask :
-- |     true
-- |   ask_page_title :
-- |_    Ask me anything



author = {
  "Gyanendra Mishra"
}

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {
  "discovery",
  "safe",
}

local API_KEY = "fuiKNFp9vQFvjLNvx4sUwti4Yb5yGutBN4Xh10LXZhhRKjWlV4"

portrule = shortport.http

local function shortenOutput(words)
  if words:len() >= 75 then
    return words:sub(1,75) .. ' ...'
  else
    return words
  end  
end

function action (host, port)
  
  --Read script arguments
  local api_key = stdnse.get_script_args(SCRIPT_NAME .. ".api-key") or API_KEY
  local target_name = host.targetname

  -- check if target name has been specified properly
  if not(target_name) then
    return stdnse.format_output(false,"Please enter name of the website instead of the ip address.")
  end
       
  
  local build_url =  '/v2/blog/' ..  target_name .. '/info?api_key=' .. api_key
  
  local response = http.get('api.tumblr.com', port,build_url)

  if response.status == 401 then
    return stdnse.format_output(false,"Invalid API KEY. If using the default API KEY please report bug to dev()nmap.org")
  elseif response.status == 404 then
    return stdnse.format_output(false,"Given Page is not a tumblr blog")
  elseif response.status ~=200 then
    return stdnse.format_output(false,"Got some unhandeled response.")
  end  

  local status, parsed = json.parse(response.body)
  if ( not(status) ) then
    return fail("Failed to parse response")
  end

  if ( parsed.errorMessage ) then
    return fail(parsed.errorMessage)
  end

  local output = {}
  
  local mini_table  = {}
  for entry_name, entry in pairs(parsed.response.blog or {}) do
    mini_table['name'] = tostring(entry_name) .. ' :'
    if entry_name == 'updated' then
      entry = stdnse.format_timestamp(entry)
    end  
    table.insert(mini_table,shortenOutput(tostring(entry)))
    table.insert(output,mini_table)
    mini_table = {}
  end
  return stdnse.format_output(true, output)

end